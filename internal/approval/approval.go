// Package approval 实现"对话式审批"的状态机：
// 当命令/路径被策略拦截时，记录一条待审批请求；
// 用户通过 approve_last / deny_last 工具完成放行或拒绝。
// pending 仅保留最近一条（MVP），并被拒绝过的规则进入拒绝集防骚扰。
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

// Request 是一条待审批请求。
// 与旧版"追加正则规则"不同，新版只携带结构化的最小放宽建议：
// 要么追加一个命令名（AddCommand），要么追加一个根目录（AddRoot）。
type Request struct {
	ID           string         `json:"id"`
	Kind         Kind           `json:"kind"`
	Server       string         `json:"server"`
	Tool         string         `json:"tool"`          // 触发审批的原始工具名（execute-command/list-remote/upload/download）
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

// NewManager 创建审批管理器。
func NewManager() *Manager { return &Manager{denied: make(map[string]bool)} }

func genID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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

// Get 返回当前待审批请求（可能为 nil）。
func (m *Manager) Get() *Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pending
}

// Approve 取出并清空当前 pending，返回被批准请求。
func (m *Manager) Approve() *Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return nil
	}
	r := m.pending
	m.pending = nil
	return r
}

// Deny 拒绝并清空当前 pending，同时将指纹记入拒绝集。
func (m *Manager) Deny() *Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return nil
	}
	r := m.pending
	m.denied[fingerprint(r)] = true
	m.pending = nil
	return r
}

// IsDenied 判断某（类型+详情+建议）是否曾被拒绝。
func (m *Manager) IsDenied(kind Kind, detail, addCmd, addRoot string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.denied[fingerprintRaw(kind, detail, addCmd, addRoot)]
}

func fingerprint(r *Request) string {
	return fingerprintRaw(r.Kind, r.Detail, r.AddCommand, r.AddRoot)
}
func fingerprintRaw(kind Kind, detail, addCmd, addRoot string) string {
	return string(kind) + "|" + detail + "|" + addCmd + "|" + addRoot
}
