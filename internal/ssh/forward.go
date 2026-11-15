// 本文件实现本地端口转发（local forward）：在本机监听一个端口，
// 把每个 TCP 连接通过已建立的 SSH 连接转发到"从 SSH 服务器视角可达"的目标地址。
//
// 生命周期由 ForwardManager 管理，转发在后台 goroutine 中运行，
// 因此 MCP 的 tools/call 可以同步返回，不阻塞 stdio 消息循环。
package ssh

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"

	cryptossh "golang.org/x/crypto/ssh"

	"ssh-mcp-go/internal/config"
)

// Forward 描述一条正在运行的本地转发。
type Forward struct {
	ID         string `json:"id"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	Server     string `json:"server"`
}

type forwardEntry struct {
	Forward
	listener net.Listener
	done     chan struct{}
	once     sync.Once
}

// ForwardManager 管理全部本地转发，按本地监听地址索引。
type ForwardManager struct {
	mu    sync.Mutex
	items map[string]*forwardEntry
	pool  *Pool
}

// NewForwardManager 创建转发管理器。
func NewForwardManager(pool *Pool) *ForwardManager {
	return &ForwardManager{items: map[string]*forwardEntry{}, pool: pool}
}

// Start 启动一条本地转发。srv 是已解析好的目标服务器；local/remote 分别是
// 本机监听地址与远程目标地址（均支持省略 IP 的写法，见 normalizeListenAddr）。
func (m *ForwardManager) Start(srv config.Server, local, remote string) (Forward, error) {
	local = normalizeListenAddr(local)
	remote = normalizeListenAddr(remote)
	if local == "" || remote == "" {
		return Forward{}, fmt.Errorf("local 与 remote 均不能为空")
	}
	// 先确保 SSH 连接可用；转发依赖该连接长期存活。
	client, err := m.pool.Get(srv)
	if err != nil {
		return Forward{}, fmt.Errorf("连接服务器失败: %w", err)
	}

	m.mu.Lock()
	if _, exists := m.items[local]; exists {
		m.mu.Unlock()
		return Forward{}, fmt.Errorf("本地地址 %s 已有转发，请先 stop", local)
	}
	ln, err := net.Listen("tcp", local)
	if err != nil {
		m.mu.Unlock()
		return Forward{}, fmt.Errorf("监听 %s 失败: %w", local, err)
	}
	entry := &forwardEntry{
		Forward:  Forward{ID: local, LocalAddr: local, RemoteAddr: remote, Server: srv.Name},
		listener: ln,
		done:     make(chan struct{}),
	}
	m.items[local] = entry
	m.mu.Unlock()

	go m.serve(entry, client)
	return entry.Forward, nil
}

func (m *ForwardManager) serve(entry *forwardEntry, client *cryptossh.Client) {
	for {
		conn, err := entry.listener.Accept()
		if err != nil {
			return // 监听器关闭（主动 stop 或异常）时退出
		}
		go pipe(conn, client, entry.RemoteAddr)
	}
}

// pipe 把单个本地连接转发到远程目标，双向拷贝，任一端结束即关闭两端。
func pipe(local net.Conn, client *cryptossh.Client, remote string) {
	rc, err := client.Dial("tcp", remote)
	if err != nil {
		local.Close()
		return
	}
	go func() {
		_, _ = io.Copy(rc, local)
		rc.Close()
	}()
	go func() {
		_, _ = io.Copy(local, rc)
		local.Close()
	}()
}

// Stop 停止指定本地地址的转发（幂等）。
func (m *ForwardManager) Stop(id string) bool {
	id = normalizeListenAddr(id)
	m.mu.Lock()
	entry, ok := m.items[id]
	if ok {
		delete(m.items, id)
	}
	m.mu.Unlock()
	if !ok {
		return false
	}
	entry.once.Do(func() {
		close(entry.done)
		entry.listener.Close()
	})
	return true
}

// List 返回当前全部转发，按本地地址排序。
func (m *ForwardManager) List() []Forward {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Forward, 0, len(m.items))
	for _, e := range m.items {
		out = append(out, e.Forward)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LocalAddr < out[j].LocalAddr })
	return out
}

// StopAll 停止全部转发（进程退出时的清理钩子）。
func (m *ForwardManager) StopAll() {
	for _, f := range m.List() {
		m.Stop(f.ID)
	}
}

// normalizeListenAddr 为纯端口或 :端口 补足默认监听 IP（仅本机可达）。
func normalizeListenAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if !strings.Contains(addr, ":") {
		return "127.0.0.1:" + addr
	}
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
}
