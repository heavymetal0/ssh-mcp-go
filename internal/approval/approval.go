// Package approval 实现"对话式审批"的状态机：
// 当命令/路径被策略拦截时，记录一条待审批请求；
// 用户通过 approve_last / deny_last 工具完成放行或拒绝。
// pending 仅保留最近一条（MVP），带过期时间，被拒绝过的规则进入拒绝集防骚扰。
package approval

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Kind 表示待审批的类型。
type Kind string

const (
	KindCommand    Kind = "command"
	KindRemotePath Kind = "remote_path"
	KindLocalPath  Kind = "local_path"
)

// PendingTTL 是待审批请求的有效期。超过后自动失效，避免用户几天后
// 误用 approve_last 批准一条早已脱离上下文的旧请求。
const PendingTTL = 10 * time.Minute

// Request 是一条待审批请求。
type Request struct {
	ID           string         `json:"id"`
	Kind         Kind           `json:"kind"`
	Server       string         `json:"server"`
	Tool         string         `json:"tool"`          // 触发审批的原始工具名
	Detail       string         `json:"detail"`        // 被拦的命令或路径
	AddCommand   string         `json:"add_command"`   // 建议追加到 allow_commands 的命令名
	AddRoot      string         `json:"add_root"`      // 建议追加到 roots 的目录
	OriginalArgs map[string]any `json:"original_args"` // 用于批准后重试
	CreatedAt    time.Time      `json:"created_at"`
}

// Manager 管理待审批请求与拒绝集。
type Manager struct {
	mu      sync.Mutex
	pending *Request
	denied  map[string]bool
}

func NewManager() *Manager { return &Manager{denied: make(map[string]bool)} }

func genID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
	}
	return hex.EncodeToString(b)
}

// expired 判断 pending 是否已过期，过期则清空。调用方须持有 m.mu。
func (m *Manager) expiredLocked() bool {
	if m.pending == nil {
		return true
	}
	if time.Since(m.pending.CreatedAt) > PendingTTL {
		m.pending = nil
		return true
	}
	return false
}

// Request 记录一条新的待审批请求，返回其 ID。
func (m *Manager) Request(r Request) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.ID = genID()
	r.CreatedAt = time.Now()
	m.pending = &r
	return r.ID
}

// Get 返回当前待审批请求的副本（不暴露内部指针，避免锁外读写竞态）。
func (m *Manager) Get() *Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.expiredLocked() {
		return nil
	}
	cp := *m.pending
	return &cp
}

// Approve 取出并清空当前 pending，返回被批准请求。过期返回 nil。
func (m *Manager) Approve() *Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.expiredLocked() {
		return nil
	}
	r := m.pending
	m.pending = nil
	return r
}

// Deny 拒绝并清空当前 pending，同时将指纹记入拒绝集。过期返回 nil。
func (m *Manager) Deny() *Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.expiredLocked() {
		return nil
	}
	r := m.pending
	m.denied[fingerprint(r)] = true
	m.pending = nil
	return r
}

// IsDenied 判断某（服务器+工具+类型+详情+建议）是否曾被拒绝。
// 指纹必须包含 server 与 tool：否则在 A 服务器/工具上拒绝过的规则，会
// 静默压制 B 服务器/工具上的同类请求，造成"怎么也批不了"的假象。
func (m *Manager) IsDenied(server, tool string, kind Kind, detail, addCmd, addRoot string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.denied[fingerprintRaw(server, tool, kind, detail, addCmd, addRoot)]
}

func fingerprint(r *Request) string {
	return fingerprintRaw(r.Server, r.Tool, r.Kind, r.Detail, r.AddCommand, r.AddRoot)
}
func fingerprintRaw(server, tool string, kind Kind, detail, addCmd, addRoot string) string {
	return server + "|" + tool + "|" + string(kind) + "|" + detail + "|" + addCmd + "|" + addRoot
}
