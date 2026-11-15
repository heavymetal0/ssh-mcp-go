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

// Pool 是带简单缓存的 SSH 连接池（按服务器名索引）。
type Pool struct {
	mu      sync.Mutex
	clients map[string]*ssh.Client
	cfg     *config.Config
}

// NewPool 创建一个新的连接池。cfg 提供 connection_timeout / keepalive 等参数；
// 传 nil 时使用一组内置默认值（便于测试与独立调用）。
func NewPool(cfg *config.Config) *Pool {
	if cfg == nil {
		cfg = &config.Config{Defaults: config.DefaultDefaults()}
	}
	return &Pool{clients: make(map[string]*ssh.Client), cfg: cfg}
}

// Get 返回（必要时建立）到指定服务器的连接。
func (p *Pool) Get(s config.Server) (*ssh.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[s.Name]; ok && c != nil {
		return c, nil
	}
	hkcb, err := p.hostKeyCallback()
	if err != nil {
		return nil, err
	}
	client, err := dial(s, p.cfg.ConnectionTimeout(), p.cfg.KeepaliveInterval(), p.cfg.KeepaliveCountMax(), hkcb)
	if err != nil {
		return nil, err
	}
	p.clients[s.Name] = client
	return client, nil
}

// hostKeyCallback 依据配置构造主机密钥校验回调。
// 默认 insecure（保持兼容）；known_hosts 时用已知主机文件严格校验。
func (p *Pool) hostKeyCallback() (ssh.HostKeyCallback, error) {
	policy := strings.ToLower(strings.TrimSpace(p.cfg.HostKeyPolicy()))
	switch policy {
	case "known_hosts", "known-hosts", "strict":
		path := expand(p.cfg.KnownHostsFile())
		cb, err := knownhosts.New(path)
		if err != nil {
			return nil, fmt.Errorf("加载 known_hosts(%s) 失败: %w（可先用 ssh-keyscan 写入主机公钥）", path, err)
		}
		return cb, nil
	default: // insecure 或未知值：保持原版行为
		return ssh.InsecureIgnoreHostKey(), nil
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
	cfg := &ssh.ClientConfig{
		User:            s.Username,
		Auth:            auths,
		HostKeyCallback: hkcb,    // 由 defaults.host_key_policy 决定
		Timeout:         timeout, // 来自 defaults.connection_timeout
	}
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	startKeepalive(client, keepalive, keepaliveMax)
	return client, nil
}

// startKeepalive 周期性发送 SSH 心跳，连续失败达到上限后主动关闭连接。
// 连接被关闭后 SendRequest 会持续报错，计数达到上限即退出 goroutine，不会泄漏。
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
			ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err == nil && ok {
				miss = 0
				continue
			}
			miss++
			if miss >= maxMiss {
				_ = client.Close()
				return
			}
		}
	}()
}

// expand 展开路径中的 ~ 为家目录。
func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}

// limitedBuffer 在累计写入超过 limit 字节后丢弃后续数据：既限制内存占用，
// 又标记输出是否被截断。limit<=0 表示不限制。
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	if w.limit <= 0 {
		return w.buf.Write(p)
	}
	remain := w.limit - w.buf.Len()
	if remain <= 0 {
		w.truncated = true
		return len(p), nil // 假装已写入，避免 io.Copy 报 ErrShortWrite
	}
	if len(p) > remain {
		w.buf.Write(p[:remain])
		w.truncated = true
		return len(p), nil
	}
	return w.buf.Write(p)
}

func (w *limitedBuffer) String() string { return w.buf.String() }

// RunCommand 在远程执行命令，带超时与输出上限。返回合并的标准输出/错误。
// 超时后关闭会话使底层阻塞的 Run 返回，并等待 goroutine 退出，避免泄漏。
// maxBytes 来自 defaults.max_output_bytes，<=0 表示不截断。
func RunCommand(client *ssh.Client, cmd string, timeout time.Duration, maxBytes int) (string, error) {
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
		session.Close() // 关闭底层 channel，使 Run 立即返回
		<-done          // 等待 goroutine 退出，防止泄漏
		runErr = fmt.Errorf("命令超时(%s): %s", timeout, cmd)
	}
	out := w.String()
	if w.truncated {
		out += fmt.Sprintf("\n…[输出已截断：超过 %d 字节上限]", maxBytes)
	}
	return out, runErr
}

// ListRemote 列出远程目录内容。
func ListRemote(client *ssh.Client, path string) (string, error) {
	c, err := sftp.NewClient(client)
	if err != nil {
		return "", err
	}
	defer c.Close()
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
}

// Upload 通过 SFTP 上传本地文件到远程。
func Upload(client *ssh.Client, local, remote string) error {
	c, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer c.Close()
	src, err := os.Open(local)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := c.Create(remote)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

// Download 通过 SFTP 下载远程文件到本地。
func Download(client *ssh.Client, remote, local string) error {
	c, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer c.Close()
	src, err := c.Open(remote)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(local)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

// joinRemote 用正斜杠拼接远程路径（远程多为 Unix 系统，不依赖 filepath.Separator）。
func joinRemote(base, name string) string {
	if strings.HasSuffix(base, "/") {
		return base + name
	}
	return base + "/" + name
}

// SyncUploadDir 递归上传本地目录到远程目录，返回上传的文件数。
// 目标远程路径由调用方保证已通过策略校验；这里按相对路径拼接，防止逃逸。
func SyncUploadDir(client *ssh.Client, localRoot, remoteRoot string) (int, error) {
	c, err := sftp.NewClient(client)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	localRoot = filepath.Clean(localRoot)
	count := 0
	err = filepath.Walk(localRoot, func(path string, info os.FileInfo, err error) error {
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
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		dst, err := c.Create(target)
		if err != nil {
			return err
		}
		if _, err := io.Copy(dst, src); err != nil {
			dst.Close()
			return err
		}
		if err := dst.Close(); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, err
}

// SyncDownloadDir 递归下载远程目录到本地目录，返回下载的文件数。
func SyncDownloadDir(client *ssh.Client, remoteRoot, localRoot string) (int, error) {
	c, err := sftp.NewClient(client)
	if err != nil {
		return 0, err
	}
	defer c.Close()
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
		target := filepath.Join(localRoot, rel)
		info := walker.Stat()
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
		_, copyErr := io.Copy(dst, src)
		dst.Close()
		src.Close()
		if copyErr != nil {
			return count, copyErr
		}
		count++
	}
	return count, nil
}
