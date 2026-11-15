// Package ssh 提供 SSH 连接池、命令执行与 SFTP 文件操作。
// 使用 golang.org/x/crypto/ssh 与 github.com/pkg/sftp。
package ssh

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssh-mcp-go/internal/config"
)

// Client 是 crypto/ssh.Client 的别名，便于上层直接引用。
type Client = ssh.Client

type cachedConn struct {
	client *ssh.Client
	fp     string // 连接参数指纹：配置变更时强制重连
}

// Pool 是带缓存的 SSH 连接池（按服务器名索引）。
type Pool struct {
	mu      sync.Mutex
	clients map[string]*cachedConn
	cfg     *config.Config
}

// NewPool 创建连接池。cfg 提供 connection_timeout / keepalive 等参数；
// 传 nil 时使用内置默认值。
func NewPool(cfg *config.Config) *Pool {
	if cfg == nil {
		cfg = &config.Config{Defaults: config.DefaultDefaults()}
	}
	return &Pool{clients: make(map[string]*cachedConn), cfg: cfg}
}

// Get 返回（必要时建立）到指定服务器的连接。
// 相比旧实现，这里会：
//   - 比对配置指纹，热重载改了 host/port/凭据后自动重连；
//   - 探活缓存连接，远端/心跳关闭后不再返回死连接。
func (p *Pool) Get(s config.Server) (*ssh.Client, error) {
	fp := fingerprint(s, p.cfg.HostKeyPolicy(), p.cfg.KnownHostsFile())
	p.mu.Lock()
	defer p.mu.Unlock()
	if cc, ok := p.clients[s.Name]; ok && cc != nil && cc.client != nil {
		if cc.fp == fp && connAlive(cc.client) {
			return cc.client, nil
		}
		_ = cc.client.Close()
		delete(p.clients, s.Name)
	}
	hkcb, err := p.hostKeyCallback()
	if err != nil {
		return nil, err
	}
	client, err := dial(s, p.cfg.ConnectionTimeout(), p.cfg.KeepaliveInterval(), p.cfg.KeepaliveCountMax(), hkcb)
	if err != nil {
		return nil, err
	}
	p.clients[s.Name] = &cachedConn{client: client, fp: fp}
	return client, nil
}

// Close 关闭池内全部连接（进程退出时清理）。
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, cc := range p.clients {
		if cc != nil && cc.client != nil {
			_ = cc.client.Close()
		}
		delete(p.clients, name)
	}
}

// fingerprint 汇总所有"影响连接目标/身份"的配置项。
// 任一变化都必须重连，否则热重载看似生效、实际仍连着旧主机。
//
// 私钥与 known_hosts 属于"配置字符串不变、但文件内容变了"的典型：用文件的
// size+mtime 作为轻量签名并入指纹，使热重载替换密钥/信任库后一定重新握手。
func fingerprint(s config.Server, hostKeyPolicy, knownHostsFile string) string {
	extra := ""
	if s.PrivateKey != "" {
		extra += fileStamp(expand(s.PrivateKey))
	}
	if isStrictHostKeyPolicy(hostKeyPolicy) && knownHostsFile != "" {
		extra += fileStamp(expand(knownHostsFile))
	}
	return fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s",
		s.Host, s.Port, s.Username, s.Password, s.PrivateKey, hostKeyPolicy, extra)
}

func isStrictHostKeyPolicy(p string) bool {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "known_hosts", "known-hosts", "strict":
		return true
	}
	return false
}

// fileStamp 用轻量 stat 生成文件签名，不读取内容（避免每次 Get 都做文件 IO 哈希）。
func fileStamp(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return "missing(" + path + ")|"
	}
	return fmt.Sprintf("%s:%d:%d|", path, st.Size(), st.ModTime().UnixNano())
}

// connAlive 用一次轻量 no-reply 请求探测连接是否仍可写。
// 只有底层连接断开时 SendRequest 才返回错误，开销极小。
func connAlive(c *ssh.Client) bool {
	_, _, err := c.SendRequest("keepalive@openssh.com", false, nil)
	return err == nil
}

// hostKeyCallback 依据配置构造主机密钥校验回调。
// 未知策略值一律 fail-closed（拒绝连接），避免把拼错的 known_hosts
// 静默降级成"不校验"造成安全回退。
func (p *Pool) hostKeyCallback() (ssh.HostKeyCallback, error) {
	policy := strings.ToLower(strings.TrimSpace(p.cfg.HostKeyPolicy()))
	switch policy {
	case "", "insecure", "none":
		return ssh.InsecureIgnoreHostKey(), nil
	case "known_hosts", "known-hosts", "strict":
		path := expand(p.cfg.KnownHostsFile())
		cb, err := knownhosts.New(path)
		if err != nil {
			return nil, fmt.Errorf("加载 known_hosts(%s) 失败: %w（可先用 ssh-keyscan 写入主机公钥）", path, err)
		}
		return cb, nil
	default:
		return nil, fmt.Errorf("未知的 host_key_policy %q，拒绝连接（可用 insecure / known_hosts）", policy)
	}
}

func dial(s config.Server, timeout, keepalive time.Duration, keepaliveMax int, hkcb ssh.HostKeyCallback) (*ssh.Client, error) {
	var auths []ssh.AuthMethod
	if s.PrivateKey != "" {
		key, err := os.ReadFile(expand(s.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("读取私钥失败: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("解析私钥失败: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if s.Password != "" {
		auths = append(auths, ssh.Password(s.Password))
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("服务器 %s 未配置任何认证方式", s.Name)
	}
	port := s.Port
	if port <= 0 {
		port = 22 // 手写配置漏填 port 时给出合理默认
	}
	cfg := &ssh.ClientConfig{
		User:            s.Username,
		Auth:            auths,
		HostKeyCallback: hkcb,
		Timeout:         timeout,
	}
	addr := fmt.Sprintf("%s:%d", s.Host, port)
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	startKeepalive(client, keepalive, keepaliveMax)
	return client, nil
}

// startKeepalive 周期性发送 SSH 心跳，连续 N 次"底层错误"后关闭连接。
//
// 关键修复：服务器对 keepalive@openssh.com 正常回复"不支持"(ok=false, err=nil)
// 说明连接仍然存活，必须重置计数；旧实现把 ok=false 当失败，会在约 45 秒后
// 主动杀掉一条完全健康的连接。只有 err!=nil（连接真断了）才计入失败。
func startKeepalive(client *ssh.Client, interval time.Duration, maxMiss int) {
	if interval <= 0 {
		return
	}
	if maxMiss <= 0 {
		maxMiss = 3
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		miss := 0
		for range ticker.C {
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				miss++
				if miss >= maxMiss {
					_ = client.Close()
					return
				}
				continue
			}
			miss = 0 // 收到任何回复都代表链路存活
		}
	}()
}

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// limitedBuffer 在累计写入超过 limit 字节后丢弃后续数据。
//
// stdio 场景下 session.Stdout 与 session.Stderr 指向同一个 buffer，
// x/crypto/ssh 会用两个 goroutine 并发写入；bytes.Buffer 非线程安全，
// 因此这里必须用互斥锁保护（旧实现存在 data race，可能输出错乱甚至 panic）。
type limitedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.limit <= 0 {
		return w.buf.Write(p)
	}
	remain := w.limit - w.buf.Len()
	if remain <= 0 {
		w.truncated = true
		return len(p), nil // 假装已写入，避免 io.Copy 报 ErrShortWrite
	}
	if len(p) > remain {
		_, _ = w.buf.Write(p[:remain])
		w.truncated = true
		return len(p), nil
	}
	return w.buf.Write(p)
}

func (w *limitedBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func (w *limitedBuffer) wasTruncated() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.truncated
}

// RunCommand 在远程执行命令，带超时与输出上限。返回合并的标准输出/错误。
// 超时后关闭会话使底层 Run 返回，并等待 goroutine 退出（带兜底，避免
// 极端情况下 Run 不返回导致整个 MCP 请求永久挂起）。
func RunCommand(client *ssh.Client, cmd string, timeout time.Duration, maxBytes int) (string, error) {
	if timeout <= 0 {
		timeout = 120 * time.Minute
	}
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	w := &limitedBuffer{limit: maxBytes}
	session.Stdout = w
	session.Stderr = w

	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()
	var runErr error
	select {
	case runErr = <-done:
		session.Close()
	case <-time.After(timeout):
		session.Close()
		select {
		case <-done: // 正常收敛，避免 goroutine 泄漏
		case <-time.After(2 * time.Second): // 兜底：不再无限等待
		}
		runErr = fmt.Errorf("命令超时(%s): %s", timeout, cmd)
	}
	out := w.String()
	if w.wasTruncated() {
		out += fmt.Sprintf("\n…[输出已截断：超过 %d 字节上限]", maxBytes)
	}
	return out, runErr
}

// sftpCall 在超时保护下执行一次 SFTP 操作。超时会关闭该次操作的 sftp 客户端，
// 使底层 IO 尽快失败返回，避免大文件传输把 MCP 请求永久挂起。
// onTimeout 必须与调用方的 defer 共用同一把 sync.Once，保证 Close 幂等。
func sftpCall[T any](timeout time.Duration, fn func() (T, error), onTimeout func()) (T, error) {
	var zero T
	if timeout <= 0 {
		return fn()
	}
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := fn()
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-time.After(timeout):
		onTimeout()
		return zero, fmt.Errorf("SFTP 操作超时(%s)", timeout)
	}
}

func ListRemote(client *ssh.Client, path string, timeout time.Duration) (string, error) {
	c, err := sftp.NewClient(client)
	if err != nil {
		return "", err
	}
	var once sync.Once
	closeC := func() { once.Do(func() { _ = c.Close() }) }
	defer closeC()
	return sftpCall(timeout, func() (string, error) {
		entries, err := c.ReadDir(path)
		if err != nil {
			return "", err
		}
		var sb strings.Builder
		for _, e := range entries {
			typ := "f"
			if e.Mode().IsDir() {
				typ = "d"
			}
			fmt.Fprintf(&sb, "%s %8d  %s\n", typ, e.Size(), e.Name())
		}
		return sb.String(), nil
	}, closeC)
}

func Upload(client *ssh.Client, local, remote string, timeout time.Duration) error {
	c, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	var once sync.Once
	closeC := func() { once.Do(func() { _ = c.Close() }) }
	defer closeC()
	_, err = sftpCall(timeout, func() (struct{}, error) {
		src, err := os.Open(local)
		if err != nil {
			return struct{}{}, err
		}
		defer src.Close()
		dst, err := c.Create(remote)
		if err != nil {
			return struct{}{}, err
		}
		_, cpErr := io.Copy(dst, src)
		closeErr := dst.Close()
		if cpErr != nil {
			return struct{}{}, cpErr
		}
		return struct{}{}, closeErr
	}, closeC)
	return err
}

func Download(client *ssh.Client, remote, local string, timeout time.Duration) error {
	c, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	var once sync.Once
	closeC := func() { once.Do(func() { _ = c.Close() }) }
	defer closeC()
	_, err = sftpCall(timeout, func() (struct{}, error) {
		src, err := c.Open(remote)
		if err != nil {
			return struct{}{}, err
		}
		defer src.Close()
		dst, err := os.Create(local)
		if err != nil {
			return struct{}{}, err
		}
		_, cpErr := io.Copy(dst, src)
		closeErr := dst.Close()
		if cpErr != nil {
			return struct{}{}, cpErr
		}
		return struct{}{}, closeErr
	}, closeC)
	return err
}

func joinRemote(base, name string) string {
	if strings.HasSuffix(base, "/") {
		return base + name
	}
	return base + "/" + name
}

// SyncUploadDir 递归上传本地目录到远程目录，返回上传的文件数。
// 目标远程路径由调用方保证已通过策略校验；这里按相对路径拼接，防止逃逸。
func SyncUploadDir(client *ssh.Client, localRoot, remoteRoot string, timeout time.Duration) (int, error) {
	c, err := sftp.NewClient(client)
	if err != nil {
		return 0, err
	}
	var once sync.Once
	closeC := func() { once.Do(func() { _ = c.Close() }) }
	defer closeC()
	return sftpCall(timeout, func() (int, error) {
		localRoot = filepath.Clean(localRoot)
		count := 0
		err := filepath.Walk(localRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(localRoot, path)
			if err != nil {
				return err
			}
			if rel == "." {
				return nil
			}
			rel = filepath.ToSlash(rel)
			target := joinRemote(remoteRoot, rel)
			if info.IsDir() {
				return c.MkdirAll(target)
			}
			if !info.Mode().IsRegular() {
				return nil // 跳过符号链接、设备等特殊文件
			}
			// 关键修复：不能再在 Walk 回调里 defer src.Close()——
			// defer 要到整个函数返回才执行，成千上万个文件会耗尽 fd。
			src, err := os.Open(path)
			if err != nil {
				return err
			}
			dst, err := c.Create(target)
			if err != nil {
				src.Close()
				return err
			}
			_, cpErr := io.Copy(dst, src)
			dstErr := dst.Close()
			srcErr := src.Close()
			if cpErr != nil {
				return cpErr
			}
			if dstErr != nil {
				return dstErr
			}
			if srcErr != nil {
				return srcErr
			}
			count++
			return nil
		})
		return count, err
	}, closeC)
}

// SyncDownloadDir 递归下载远程目录到本地目录，返回下载的文件数。
func SyncDownloadDir(client *ssh.Client, remoteRoot, localRoot string, timeout time.Duration) (int, error) {
	c, err := sftp.NewClient(client)
	if err != nil {
		return 0, err
	}
	var once sync.Once
	closeC := func() { once.Do(func() { _ = c.Close() }) }
	defer closeC()
	return sftpCall(timeout, func() (int, error) {
		count := 0
		walker := c.Walk(remoteRoot)
		for walker.Step() {
			if err := walker.Err(); err != nil {
				return count, err
			}
			path := walker.Path()
			rel, err := filepath.Rel(filepath.Clean(remoteRoot), path)
			if err != nil {
				return count, err
			}
			if rel == "." {
				continue
			}
			// 防御：远程文件名异常时 rel 可能含 ".."，避免写到 localRoot 之外
			if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return count, fmt.Errorf("拒绝不安全的远程相对路径 %q", rel)
			}
			target := filepath.Join(localRoot, rel)
			info := walker.Stat()
			if info == nil {
				continue
			}
			if info.IsDir() {
				if err := os.MkdirAll(target, 0o755); err != nil {
					return count, err
				}
				continue
			}
			if !info.Mode().IsRegular() {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return count, err
			}
			src, err := c.Open(path)
			if err != nil {
				return count, err
			}
			dst, err := os.Create(target)
			if err != nil {
				src.Close()
				return count, err
			}
			_, cpErr := io.Copy(dst, src)
			dstErr := dst.Close()
			srcErr := src.Close()
			if cpErr != nil {
				return count, cpErr
			}
			if dstErr != nil {
				return count, dstErr
			}
			if srcErr != nil {
				return count, srcErr
			}
			count++
		}
		return count, nil
	}, closeC)
}
