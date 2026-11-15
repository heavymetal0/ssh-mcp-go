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

	mu    sync.Mutex
	conns map[net.Conn]struct{} // 活动连接，Stop 时一并关闭
}

// ForwardManager 管理全部本地转发，按本地监听地址索引。
type ForwardManager struct {
	mu    sync.Mutex
	items map[string]*forwardEntry
	pool  *Pool
}

func NewForwardManager(pool *Pool) *ForwardManager {
	return &ForwardManager{items: map[string]*forwardEntry{}, pool: pool}
}

// Start 启动一条本地转发。srv 是已解析好的目标服务器。
// 出于安全，本地监听地址强制绑定到 127.0.0.1（不暴露到局域网/公网）。
func (m *ForwardManager) Start(srv config.Server, local, remote string) (Forward, error) {
	local = loopbackAddr(local)
	remote = normalizeRemoteAddr(remote)
	if local == "" || remote == "" {
		return Forward{}, fmt.Errorf("local 与 remote 均不能为空")
	}
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
		conns:    map[net.Conn]struct{}{},
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
			// 监听器被关闭（主动 stop）或异常退出：清理条目，避免
			// List 仍显示一条已死的转发、且 Start 因"已存在"无法重建。
			select {
			case <-entry.done:
			default:
				m.remove(entry.LocalAddr)
			}
			return
		}
		entry.mu.Lock()
		entry.conns[conn] = struct{}{}
		entry.mu.Unlock()
		go func(c net.Conn) {
			defer func() {
				entry.mu.Lock()
				delete(entry.conns, c)
				entry.mu.Unlock()
			}()
			pipe(c, client, entry.RemoteAddr, entry.done)
		}(conn)
	}
}

// pipe 把单个本地连接转发到远程目标，双向拷贝，任一端结束即关闭两端。
func pipe(local net.Conn, client *cryptossh.Client, remote string, done <-chan struct{}) {
	rc, err := client.Dial("tcp", remote)
	if err != nil {
		local.Close()
		return
	}
	var once sync.Once
	closed := make(chan struct{})
	closeBoth := func() {
		once.Do(func() {
			rc.Close()
			local.Close()
			close(closed) // 唤醒下面的监听 goroutine，避免泄漏
		})
	}
	// 转发被 stop 时主动断开活动连接；正常结束时由 closed 唤醒退出。
	go func() {
		select {
		case <-done:
			closeBoth()
		case <-closed:
		}
	}()
	go func() {
		_, _ = io.Copy(rc, local)
		closeBoth()
	}()
	_, _ = io.Copy(local, rc)
	closeBoth()
}

// Stop 停止指定本地地址的转发（幂等），并关闭该转发的所有活动连接。
func (m *ForwardManager) Stop(id string) bool {
	id = loopbackAddr(id)
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
		entry.mu.Lock()
		for c := range entry.conns {
			_ = c.Close()
		}
		entry.conns = map[net.Conn]struct{}{}
		entry.mu.Unlock()
	})
	return true
}

func (m *ForwardManager) remove(id string) {
	m.mu.Lock()
	entry, ok := m.items[id]
	if ok {
		delete(m.items, id)
	}
	m.mu.Unlock()
	if ok {
		entry.once.Do(func() {
			close(entry.done)
			entry.listener.Close()
		})
	}
}

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

// loopbackAddr 把本地监听地址规范化为"仅回环"。
// 无论用户传 8080 / :8080 / 0.0.0.0:8080，都只监听 127.0.0.1，
// 防止误把 SSH 转发暴露到局域网或公网。
func loopbackAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	port := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		port = addr[i+1:]
	}
	if port == "" {
		return ""
	}
	return "127.0.0.1:" + port
}

// normalizeRemoteAddr 为纯端口或 :端口 补足本机地址（从 SSH 服务器视角）。
func normalizeRemoteAddr(addr string) string {
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
