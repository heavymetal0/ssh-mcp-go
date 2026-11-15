// Package config 负责加载与热重载 ssh-mcp 的 TOML 配置。
// 重写版完全拥有配置文件格式，但保持与原版兼容的字段语义。
package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/pelletier/go-toml/v2"
)

// 审批模式：被策略拦截时工具的行为。
const (
	ApprovalAsk  = "ask"  // 默认：以对话式交互询问是否放宽（追加命令名/根目录）
	ApprovalDeny = "deny" // 直接返回 PermissionDenied，不询问（提高与不支持审批流客户端的兼容性）
)

// Defaults 对应 TOML 的 [defaults] 段。
type Defaults struct {
	CommandTimeout    string `toml:"command_timeout"`
	ConnectionTimeout string `toml:"connection_timeout"`
	SftpTimeout       string `toml:"sftp_timeout"`
	KeepaliveInterval string `toml:"keepalive_interval"`
	KeepaliveCountMax int    `toml:"keepalive_count_max"`
	MaxOutputBytes    int    `toml:"max_output_bytes"`
	Transport         string `toml:"transport"`
	ApprovalMode      string `toml:"approval_mode"` // "ask"(默认) | "deny"

	// 主机密钥校验策略：
	//   insecure    —— 不校验（与原版一致，默认，保证开箱可用）
	//   known_hosts —— 用 known_hosts 文件严格校验，文件不存在或密钥不匹配则拒绝连接
	HostKeyPolicy  string `toml:"host_key_policy"`
	KnownHostsFile string `toml:"known_hosts_file"`
}

// Server 对应 TOML 的 [[server]] 段。
//
// 设计原则：配置只声明"意图"，复杂的策略判定（命令分类、路径门禁、
// 穿越拦截、系统目录封锁）全部由 Go 程序实现，不写进配置文件。
type Server struct {
	Name          string   `toml:"name"`
	Host          string   `toml:"host"`
	Port          int      `toml:"port"`
	Username      string   `toml:"username"`
	Password      string   `toml:"password"`
	PrivateKey    string   `toml:"private_key"`
	AllowCommands []string `toml:"allow_commands"`
	Roots         []string `toml:"roots"`
	DirPolicy     string   `toml:"dir_policy"` // "off" | "strict" | "read_beyond"
	ReadOnly      bool     `toml:"read_only"`
	ApprovalMode  string   `toml:"approval_mode"` // 覆盖 defaults，空则继承
}

// Config 是线程安全的配置容器，支持热重载。
type Config struct {
	Path       string   `toml:"-"`
	Defaults   Defaults `toml:"defaults"`
	Servers    []Server `toml:"server"`
	NeedsSetup bool     `toml:"-"` // 无配置文件或其中无任何服务器时为 true

	mu      sync.RWMutex // 保护 Defaults / Servers / NeedsSetup
	writeMu sync.Mutex   // 串行化对配置文件的"读-改-写"
	watchMu sync.Mutex   // 保护 stopFn / 监听生命周期
	stopFn  func()
}

// Load 读取并解析配置文件。若文件不存在或其中没有任何服务器，
// 不报错，而是返回一个 NeedsSetup=true 的空配置，交由配置向导生成。
func Load(path string) (*Config, error) {
	if _, err := os.Stat(path); err != nil {
		return &Config{Path: path, NeedsSetup: true}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{Path: path}
	if err := toml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}
	if len(c.Servers) == 0 {
		c.NeedsSetup = true
	}
	c.normalize()
	return c, nil
}

// normalize 补齐"配置里省略即用内置默认"的字段。
// 手写 TOML 若省略 allow_commands，不能让白名单为空导致所有命令被拦；
// 这里填充一份独立副本，避免多台服务器共享同一底层 slice。
func (c *Config) normalize() {
	for i := range c.Servers {
		if len(c.Servers[i].AllowCommands) == 0 {
			c.Servers[i].AllowCommands = append([]string(nil), DefaultAllowCommands...)
		}
	}
}

// DefaultAllowCommands 是内置的开箱即用命令白名单（首词，纯命令名，无正则）。
// 命令里的路径参数由 roots + dir_policy 自动门禁；写/改类命令另由
// policy.writeCommands / writeSubcommands 识别，受 read_only 与 roots 约束。
var DefaultAllowCommands = []string{
	// ── 系统信息 / 监控（只读，路径无关）──
	"uname", "hostname", "uptime", "date", "id", "who", "last", "which", "env",
	"ps", "top", "htop", "free", "df", "du", "lscpu", "vmstat", "iostat",
	"dmesg", "lsmod", "lsblk", "mount", "netstat", "ss", "ip", "ifconfig", "getent",

	// ── 网络诊断 / 连通性（只读低危）──
	"ping", "traceroute", "traceroute6", "mtr", "nslookup", "dig", "host",
	"curl", "wget", "openssl", "echo", "sleep",

	// ── 文件与文本查看（只读）──
	"ls", "cat", "head", "tail", "grep", "egrep", "wc", "stat", "find", "file",
	"less", "more", "tree", "strings", "nl", "diff",
	"awk", "cut", "sort", "uniq", "tr", "jq", "column", "paste",

	// ── 服务 / 套件状态查询（只读）──
	"systemctl", "synoservice", "synoservicecfg", "synopkg",

	// ── 容器（docker 子命令由程序放行，如 ps / compose up）──
	"docker",

	// ── 写 / 改类（受 read_only 与 roots 双重约束）──
	"kill", "pkill", "mkdir", "cp", "mv", "rm", "rmdir", "tar", "touch", "ln",
	"chmod", "chown", "chgrp", "rsync", "rclone", "dd", "truncate", "install",
	"patch", "tee", "sed", "vi", "vim", "nano",
	"bash", "sh", "nohup", "setsid", "python3", "pip3", "pip", "ssh",
	// 注：sudo / env / nohup 等前缀由策略层自动剥离，其后真实命令仍须在本列表内。
}

// DefaultDefaults 返回一组合理的默认超时/连接参数。
func DefaultDefaults() Defaults {
	return Defaults{
		CommandTimeout:    "120m",
		ConnectionTimeout: "30s",
		SftpTimeout:       "5m",
		KeepaliveInterval: "15s",
		KeepaliveCountMax: 3,
		MaxOutputBytes:    20971520,
		Transport:         "exec",
		HostKeyPolicy:     "insecure",
	}
}

// —— 配置读取辅助（全部加锁，避免与热重载 Reload 产生 data race）——

func (c *Config) defaultsSnapshot() Defaults {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Defaults
}

// DefaultsSnapshot 返回 defaults 的线程安全快照，供其他包读取。
func (c *Config) DefaultsSnapshot() Defaults { return c.defaultsSnapshot() }

// NeedSetup 返回当前是否缺少可用服务器配置（线程安全）。
func (c *Config) NeedSetup() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.NeedsSetup
}

func (c *Config) HostKeyPolicy() string {
	p := strings.TrimSpace(c.defaultsSnapshot().HostKeyPolicy)
	if p == "" {
		return "insecure"
	}
	return p
}

func (c *Config) KnownHostsFile() string {
	f := strings.TrimSpace(c.defaultsSnapshot().KnownHostsFile)
	if f == "" {
		return "~/.ssh/known_hosts"
	}
	return f
}

// ParseDuration 把 TOML 里的时长字符串解析为 time.Duration。
// 空值、负数或格式非法时返回 fallback。
func ParseDuration(s string, fallback time.Duration) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

func (c *Config) ConnectionTimeout() time.Duration {
	return ParseDuration(c.defaultsSnapshot().ConnectionTimeout, 30*time.Second)
}
func (c *Config) CommandTimeout() time.Duration {
	return ParseDuration(c.defaultsSnapshot().CommandTimeout, 120*time.Minute)
}
func (c *Config) SftpTimeout() time.Duration {
	return ParseDuration(c.defaultsSnapshot().SftpTimeout, 5*time.Minute)
}
func (c *Config) KeepaliveInterval() time.Duration {
	return ParseDuration(c.defaultsSnapshot().KeepaliveInterval, 15*time.Second)
}
func (c *Config) KeepaliveCountMax() int {
	if n := c.defaultsSnapshot().KeepaliveCountMax; n > 0 {
		return n
	}
	return 3
}
func (c *Config) MaxOutputBytes() int {
	if n := c.defaultsSnapshot().MaxOutputBytes; n > 0 {
		return n
	}
	return DefaultDefaults().MaxOutputBytes
}

// WriteConfig 将完整配置写出为 TOML 文件（chmod 600），用于向导首次生成。
func WriteConfig(path string, c *Config) error {
	var sb strings.Builder
	sb.WriteString("# 由 setup-wizard 自动生成\n")
	sb.WriteString("# 运行：ssh-mcp-go --config " + path + "\n\n")
	data, err := toml.Marshal(c)
	if err != nil {
		return err
	}
	sb.Write(data)
	return writeAtomic(path, []byte(sb.String()))
}

// Reload 从磁盘重新解析配置并替换内存状态。解析失败时保留旧配置。
func (c *Config) Reload() error {
	data, err := os.ReadFile(c.Path)
	if err != nil {
		return err
	}
	tmp := &Config{Path: c.Path}
	if err := toml.Unmarshal(data, tmp); err != nil {
		return err
	}
	tmp.normalize()
	c.mu.Lock()
	c.Defaults = tmp.Defaults
	c.Servers = tmp.Servers
	c.NeedsSetup = len(tmp.Servers) == 0 // 向导生成/手动清空后同步更新
	c.mu.Unlock()
	return nil
}

// Watch 监听配置文件所在目录并自动热重载。监听目录而非文件，
// 是为了兼容编辑器的"写临时文件 + rename 覆盖"保存方式（原实现监听文件，
// rename 后 inode 变化会永久丢失监听，热重载悄悄失效）。
func (c *Config) Watch() (func(), error) {
	c.watchMu.Lock()
	defer c.watchMu.Unlock()
	return c.watchLocked()
}

// watchLocked 在持有 watchMu 的前提下启动监听，避免 EnsureWatch 的 TOCTOU 竞态。
func (c *Config) watchLocked() (func(), error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(c.Path)
	if dir == "" {
		dir = "."
	}
	if err := w.Add(dir); err != nil {
		w.Close()
		return nil, err
	}
	target := filepath.Base(c.Path)
	var once sync.Once
	stop := func() {
		once.Do(func() { _ = w.Close() })
	}
	go func() {
		var timer *time.Timer
		var timerC <-chan time.Time
		for {
			select {
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if filepath.Base(ev.Name) != target {
					continue
				}
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
					continue
				}
				// 去抖：一次保存常触发多个事件，合并为一次 Reload
				if timer == nil {
					timer = time.NewTimer(80 * time.Millisecond)
				} else if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
					timer.Reset(80 * time.Millisecond)
				}
				timerC = timer.C
			case <-timerC:
				timerC, timer = nil, nil
				if err := c.Reload(); err != nil {
					log.Printf("配置热重载失败（保留旧配置）: %v", err)
				}
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				log.Printf("配置监听错误: %v", err)
			}
		}
	}()
	c.stopFn = stop
	return stop, nil
}

// EnsureWatch 在尚未监听时启动热重载监听（用于向导首次生成配置文件后）。
func (c *Config) EnsureWatch() error {
	c.watchMu.Lock()
	defer c.watchMu.Unlock()
	if c.stopFn != nil {
		return nil
	}
	_, err := c.watchLocked()
	return err
}

// StopWatch 停止热重载监听（进程退出时清理 goroutine）。
func (c *Config) StopWatch() {
	c.watchMu.Lock()
	defer c.watchMu.Unlock()
	if c.stopFn != nil {
		c.stopFn()
		c.stopFn = nil
	}
}

// GetServers 返回当前服务器列表（加读锁）。
func (c *Config) GetServers() []Server {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Server, len(c.Servers))
	copy(out, c.Servers)
	return out
}

// ServerByName 按名称查找服务器。
// name 为空时返回默认（第一个）服务器；显式指定名称找不到时返回 false，
// 绝不再静默回退到别的服务器——否则命令可能打到完全无关的主机上。
func (c *Config) ServerByName(name string) (Server, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.Servers) == 0 {
		return Server{}, false
	}
	if name == "" {
		return c.Servers[0], true
	}
	for _, s := range c.Servers {
		if s.Name == name {
			return s, true
		}
	}
	return Server{}, false
}

// ApprovalModeOf 返回服务器实际生效的审批模式（加锁读 defaults，避免与 Reload 竞态）。
func (c *Config) ApprovalModeOf(srv Server) string {
	m := srv.ApprovalMode
	if m == "" {
		m = c.defaultsSnapshot().ApprovalMode
	}
	m = strings.ToLower(strings.TrimSpace(m))
	if m == ApprovalDeny {
		return ApprovalDeny
	}
	return ApprovalAsk
}

// AppendAllowCommand 向指定服务器的 allow_commands 追加一个命令名。
// 先写文件、成功后 Reload 更新内存：写失败不污染内存，保证两者一致。
func (c *Config) AppendAllowCommand(serverName, cmd string) error {
	c.writeMu.Lock()
	err := insertIntoArray(c.Path, serverName, "allow_commands", cmd)
	if errors.Is(err, errArrayNotFound) {
		// 手写 TOML 省略了 allow_commands 行：以内存中的默认白名单为基础，
		// 在目标 [[server]] 段内补写完整数组行，保证审批放行能真正落盘。
		err = insertMissingArray(c.Path, serverName, "allow_commands", c.currentAllowCommands(serverName), cmd)
	}
	c.writeMu.Unlock()
	if err != nil {
		return err
	}
	return c.Reload()
}

// AppendRoot 向指定服务器的 roots 追加一个受保护根目录。
func (c *Config) AppendRoot(serverName, root string) error {
	c.writeMu.Lock()
	err := insertIntoArray(c.Path, serverName, "roots", root)
	c.writeMu.Unlock()
	if err != nil {
		return err
	}
	return c.Reload()
}

// errArrayNotFound 表示目标 [[server]] 段里压根没有这个数组行（可自动补写）。
var errArrayNotFound = errors.New("配置段中不存在该数组行")

// insertIntoArray 在 TOML 文件中目标服务器的指定数组里插入一个带引号的元素，
// 其余内容与注释保持不变。同时兼容"单行内联数组"与"多行数组"两种写法。
func insertIntoArray(path, serverName, key, value string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	quoted := `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	inServer := false
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[[server]]") {
			inServer = false
			continue
		}
		if strings.HasPrefix(trim, "name") && strings.Contains(trim, `"`+serverName+`"`) {
			inServer = true
			continue
		}
		if !inServer || !strings.HasPrefix(trim, key) {
			continue
		}
		rest := strings.TrimSpace(trim[len(key):])
		if !strings.HasPrefix(rest, "=") {
			continue
		}
		// 单行内联数组：key = [ a, b ]
		if strings.Contains(rest, "]") {
			open := strings.Index(rest, "[")
			close := strings.LastIndex(rest, "]")
			if open < 0 || close < open {
				return fmt.Errorf("数组 %s 格式异常", key)
			}
			inner := strings.TrimSpace(rest[open+1 : close])
			newInner := quoted
			if inner != "" {
				newInner = inner + ", " + quoted
			}
			lines[i] = indentOf(line) + key + " = [ " + newInner + " ]"
			return writeAtomicLines(path, lines)
		}
		// 多行数组：在闭合的 ] 行之前插入。
		// 关键修复：给"最后一个真实元素行"补逗号，而不是 ] 的上一行——
		// 示例配置中 ] 前是一行注释，给注释补逗号会写出非法 TOML。
		for j := i + 1; j < len(lines); j++ {
			if !strings.HasPrefix(strings.TrimSpace(lines[j]), "]") {
				continue
			}
			last := -1
			for k := j - 1; k > i; k-- {
				tk := strings.TrimSpace(lines[k])
				if tk == "" || strings.HasPrefix(tk, "#") {
					continue
				}
				last = k
				break
			}
			if last >= 0 {
				lines[last] = ensureTrailingComma(lines[last])
			}
			// 新元素带尾逗号，TOML 允许数组尾随逗号
			lines[j] = "  " + quoted + ",\n" + lines[j]
			return writeAtomicLines(path, lines)
		}
		return fmt.Errorf("未找到数组 %s 的结束符", key)
	}
	return fmt.Errorf("服务器 %s: %w: %s", serverName, errArrayNotFound, key)
}

// ensureTrailingComma 给数组元素行补逗号，且只在引号外的代码部分补，
// 避免把逗号加到行尾注释里（如 "ssh"  # 说明）。
func ensureTrailingComma(line string) string {
	inQuote := false
	cut := -1
	for idx, r := range line {
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if r == '#' && !inQuote {
			cut = idx
			break
		}
	}
	code, comment := line, ""
	if cut >= 0 {
		code, comment = line[:cut], line[cut:]
	}
	code = strings.TrimRight(code, " \t")
	if strings.HasSuffix(code, ",") {
		return line
	}
	if comment != "" {
		return code + ",  " + comment
	}
	return code + ","
}

func indentOf(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

// writeAtomicLines / writeAtomic 用"同目录临时文件 + rename"原子替换，
// 避免热重载监听到写了一半的文件，也让目录监听能收到完整的 Rename 事件。
func writeAtomicLines(path string, lines []string) error {
	return writeAtomic(path, []byte(strings.Join(lines, "\n")))
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ssh-mcp-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// currentAllowCommands 返回指定服务器当前生效的白名单副本。
func (c *Config) currentAllowCommands(serverName string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, s := range c.Servers {
		if s.Name == serverName {
			return append([]string(nil), s.AllowCommands...)
		}
	}
	return append([]string(nil), DefaultAllowCommands...)
}

// insertMissingArray 处理"配置文件里压根没有 allow_commands 这一行"的情况：
// 在目标 [[server]] 段内、下一段开始之前，插入一份完整的多行数组。
func insertMissingArray(path, serverName, key string, existing []string, value string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	nameLine := -1
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "name") && strings.Contains(trim, `"`+serverName+`"`) {
			nameLine = i
			break
		}
	}
	if nameLine < 0 {
		return fmt.Errorf("未在配置中找到服务器 %s", serverName)
	}
	insertAt := len(lines)
	for j := nameLine + 1; j < len(lines); j++ {
		if strings.HasPrefix(strings.TrimSpace(lines[j]), "[") {
			insertAt = j
			break
		}
	}
	quote := func(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }
	block := []string{"  " + key + " = ["}
	for _, e := range existing {
		block = append(block, "    "+quote(e)+",")
	}
	block = append(block, "    "+quote(value)+",", "  ]")
	out := make([]string, 0, len(lines)+len(block))
	out = append(out, lines[:insertAt]...)
	out = append(out, block...)
	out = append(out, lines[insertAt:]...)
	return writeAtomicLines(path, out)
}
