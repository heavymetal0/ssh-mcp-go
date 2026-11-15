// Package config 负责加载与热重载 ssh-mcp 的 TOML 配置。
// 重写版完全拥有配置文件格式，但保持与原版兼容的字段语义。
package config

import (
	"fmt"
	"os"
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
//   - allow_commands：允许执行的命令名列表（写命令名即可，无需正则）
//   - roots：受保护的根目录列表，命令中的路径参数与所有 SFTP 操作都必须
//     落在这些目录内；越权/穿越由程序自动拦截
//   - read_only：true 时禁止一切写命令（即便列在 allow_commands）
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

	mu     sync.RWMutex
	stopFn func()
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
	return c, nil
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

// HostKeyPolicy 返回生效的主机密钥校验策略（缺省 insecure）。
func (c *Config) HostKeyPolicy() string {
	p := strings.TrimSpace(c.defaultsSnapshot().HostKeyPolicy)
	if p == "" {
		return "insecure"
	}
	return p
}

// KnownHostsFile 返回 known_hosts 文件路径（缺省 ~/.ssh/known_hosts）。
func (c *Config) KnownHostsFile() string {
	f := strings.TrimSpace(c.defaultsSnapshot().KnownHostsFile)
	if f == "" {
		return "~/.ssh/known_hosts"
	}
	return f
}

// —— 时长 / 上限解析辅助 ——
// 这些值集中在此解析，确保"配置文件里写了就生效、没写就用兜底值"，
// 避免各调用点各写一套默认值导致不一致。

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

// defaultsSnapshot 读取 defaults 的快照（加读锁），供下面各 getter 使用。
func (c *Config) defaultsSnapshot() Defaults {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Defaults
}

// ConnectionTimeout 返回生效的 SSH 建连超时（缺省 30s）。
func (c *Config) ConnectionTimeout() time.Duration {
	return ParseDuration(c.defaultsSnapshot().ConnectionTimeout, 30*time.Second)
}

// CommandTimeout 返回生效的命令执行默认超时（缺省 120m）。
func (c *Config) CommandTimeout() time.Duration {
	return ParseDuration(c.defaultsSnapshot().CommandTimeout, 120*time.Minute)
}

// KeepaliveInterval 返回心跳间隔（缺省 15s）。
func (c *Config) KeepaliveInterval() time.Duration {
	return ParseDuration(c.defaultsSnapshot().KeepaliveInterval, 15*time.Second)
}

// KeepaliveCountMax 返回连续心跳失败多少次后判定连接失效（缺省 3）。
func (c *Config) KeepaliveCountMax() int {
	if n := c.defaultsSnapshot().KeepaliveCountMax; n > 0 {
		return n
	}
	return 3
}

// MaxOutputBytes 返回命令输出上限字节数（缺省 20MB，对应 DefaultDefaults）。
func (c *Config) MaxOutputBytes() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.Defaults.MaxOutputBytes > 0 {
		return c.Defaults.MaxOutputBytes
	}
	return DefaultDefaults().MaxOutputBytes
}

// WriteConfig 将完整配置写出为 TOML 文件（chmod 600），用于向导首次生成。
// 文件顶部的注释说明由向导生成，正文由 go-toml 序列化（保留字段顺序）。
func WriteConfig(path string, c *Config) error {
	var sb strings.Builder
	sb.WriteString("# 由 setup-wizard 自动生成\n")
	sb.WriteString("# 运行：ssh-mcp-go --config " + path + "\n\n")
	data, err := toml.Marshal(c)
	if err != nil {
		return err
	}
	sb.Write(data)
	return os.WriteFile(path, []byte(sb.String()), 0o600)
}

// Reload 从磁盘重新解析配置并替换内存状态。
func (c *Config) Reload() error {
	data, err := os.ReadFile(c.Path)
	if err != nil {
		return err
	}
	tmp := &Config{Path: c.Path}
	if err := toml.Unmarshal(data, tmp); err != nil {
		return err
	}
	c.mu.Lock()
	c.Defaults = tmp.Defaults
	c.Servers = tmp.Servers
	c.mu.Unlock()
	return nil
}

// Watch 监听配置文件变化并自动重载（热重载）。
// 返回停止函数。
func (c *Config) Watch() (func(), error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := w.Add(c.Path); err != nil {
		w.Close()
		return nil, err
	}
	go func() {
		for ev := range w.Events {
			if ev.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				_ = c.Reload()
			}
		}
	}()
	stop := func() { w.Close() }
	c.stopFn = stop
	return stop, nil
}

// EnsureWatch 在尚未监听时启动热重载监听（用于向导首次生成配置文件后，
// 让新文件也能被后续热重载生效）。
func (c *Config) EnsureWatch() error {
	c.mu.Lock()
	if c.stopFn != nil {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()
	_, err := c.Watch()
	return err
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
func (c *Config) ServerByName(name string) (Server, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, s := range c.Servers {
		if s.Name == name {
			return s, true
		}
	}
	if len(c.Servers) > 0 {
		return c.Servers[0], true // 无匹配时默认第一个
	}
	return Server{}, false
}

// ApprovalModeOf 返回服务器实际生效的审批模式。
// server 级 approval_mode 优先；为空则取 defaults；再为空则默认 ask（交互）。
func (c *Config) ApprovalModeOf(srv Server) string {
	m := srv.ApprovalMode
	if m == "" {
		m = c.Defaults.ApprovalMode
	}
	if m == ApprovalDeny {
		return ApprovalDeny
	}
	return ApprovalAsk
}

// AppendAllowCommand 向指定服务器的 allow_commands 追加一个命令名：
// 1) 更新内存状态；2) 以"定点行插入"方式写回文件以保留注释。
func (c *Config) AppendAllowCommand(serverName, cmd string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.Servers {
		if c.Servers[i].Name == serverName {
			c.Servers[i].AllowCommands = append(c.Servers[i].AllowCommands, cmd)
		}
	}
	return insertIntoArray(c.Path, serverName, "allow_commands", cmd)
}

// AppendRoot 向指定服务器的 roots 追加一个受保护根目录。
func (c *Config) AppendRoot(serverName, root string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.Servers {
		if c.Servers[i].Name == serverName {
			c.Servers[i].Roots = append(c.Servers[i].Roots, root)
		}
	}
	return insertIntoArray(c.Path, serverName, "roots", root)
}

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
		if !inServer {
			continue
		}
		if !strings.HasPrefix(trim, key+" = [") {
			continue
		}
		// 单行内联数组：whitelist = [ a, b ]
		if strings.Contains(trim, "]") {
			open := strings.Index(trim, "[")
			close := strings.LastIndex(trim, "]")
			inner := strings.TrimSpace(trim[open+1 : close])
			if inner == "" {
				lines[i] = indentOf(line) + key + " = [ " + quoted + " ]"
			} else {
				lines[i] = indentOf(line) + key + " = [ " + inner + ", " + quoted + " ]"
			}
			return writeLines(path, lines)
		}
		// 多行数组：在闭合的 ] 行之前插入
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "]" {
				prev := lines[j-1]
				if strings.TrimSpace(prev) == key+" = [" {
					// 空数组：直接放入首个元素
					lines[j] = "  " + quoted + "\n" + lines[j]
				} else {
					// 给原"最后一个元素"补逗号（它不再是末尾了）
					if !strings.HasSuffix(strings.TrimRight(prev, " \t"), ",") {
						lines[j-1] = prev + ","
					}
					lines[j] = "  " + quoted + "\n" + lines[j]
				}
				return writeLines(path, lines)
			}
		}
		return fmt.Errorf("未找到数组 %s 的结束符", key)
	}
	return fmt.Errorf("未在服务器 %s 找到数组 %s", serverName, key)
}

// indentOf 返回一行的缩进（前导空白）。
func indentOf(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

// writeLines 将行数组写回文件并保留 0600 权限。
func writeLines(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600)
}
