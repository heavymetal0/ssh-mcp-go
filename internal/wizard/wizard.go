// Package wizard 实现"配置向导"状态机。
//
// 设计：对话式、逐步收集。Agent 每次调用 setup-wizard 工具时把上一步的答案
// 通过 answer 参数传回，向导校验后推进到下一步并给出下一个问题；最后一步完成后
// 由上层（tools.go）把收集结果写成 TOML 配置文件。整个流程无需任何额外 UI，
// 完全在 WorkBuddy 对话里闭环，与既有的"对话式审批"风格一致。
package wizard

import (
	"strconv"
	"strings"
	"sync"

	"ssh-mcp-go/internal/config"
)

// recommendedCommands 是向导默认提供的"推荐允许命令"列表。
var recommendedCommands = []string{
	"uname", "hostname", "uptime", "date",
	"df", "free", "ps", "top",
	"ls", "cat", "head", "tail", "grep",
	"systemctl", "docker",
	"cp", "mv", "rm", "mkdir", "rsync", "tar",
}

// stepDef 描述向导的某一步：收集哪个字段、如何提问、如何校验。
type stepDef struct {
	key      string
	prompt   func(w *Wizard) string
	validate func(w *Wizard, a string) error
}

// steps 是向导的全部步骤，按序推进。
var steps = []stepDef{
	{key: "name", prompt: constPrompt("请输入服务器名称（例如 synology-nas）："), validate: nonEmpty},
	{key: "host", prompt: constPrompt("请输入主机地址（IP 或域名）："), validate: nonEmpty},
	{key: "port", prompt: constPrompt("请输入 SSH 端口（直接回车使用默认 22）："), validate: portOrEmpty},
	{key: "username", prompt: constPrompt("请输入登录用户名："), validate: nonEmpty},
	{key: "auth", prompt: constPrompt("认证方式：输入 password（密码）或 private_key（私钥）："), validate: oneOf("password", "private_key")},
	{key: "cred", prompt: func(w *Wizard) string {
		if w.ans["auth"] == "private_key" {
			return "请输入私钥路径（例如 ~/.ssh/id_ed25519）："
		}
		return "请输入登录密码："
	}, validate: nonEmpty},
	{key: "roots", prompt: constPrompt("请输入受保护根目录（命令与 SFTP 仅能访问其内，例如 /volume/docker/）："), validate: absPath},
	{key: "dir_policy", prompt: constPrompt("目录权限模式：off(不限制) / strict(读写都受限) / read_beyond(读可越界、写不可越界，推荐)。直接回车用 read_beyond："), validate: inSetOrEmpty("off", "strict", "read_beyond")},
	{key: "read_only", prompt: constPrompt("是否只读（禁止一切写命令）？yes/no（直接回车=no）："), validate: yesNoEmpty},
	{key: "allow_commands", prompt: constPrompt("允许执行的命令（直接回车用推荐列表，或输入逗号分隔的自定义列表）："), validate: anyOK},
}

// Wizard 是向导的状态机实例。
type Wizard struct {
	mu     sync.Mutex
	active bool
	step   int
	ans    map[string]string
}

// New 创建新的向导实例。
func New() *Wizard { return &Wizard{ans: map[string]string{}} }

// Step 推进向导：answer 是上一步的答案（首次调用可传空）。
// 返回 (下一个问题, 是否已完成, 错误)。校验失败时返回原问题并要求重答。
func (w *Wizard) Step(answer string) (string, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.active {
		w.active = true
		w.step = 0
		w.ans = map[string]string{}
		return steps[0].prompt(w), false, nil
	}
	if w.step < len(steps) {
		a := strings.TrimSpace(answer)
		if err := steps[w.step].validate(w, a); err != nil {
			return "❌ " + err.Error() + "\n" + steps[w.step].prompt(w), false, nil
		}
		w.ans[steps[w.step].key] = a
		w.step++
	}
	if w.step >= len(steps) {
		return "", true, nil
	}
	return steps[w.step].prompt(w), false, nil
}

// Draft 把已收集的答案组装成一个 config.Server（带默认值填充）。
func (w *Wizard) Draft() config.Server {
	port := 22
	if p, err := strconv.Atoi(orDefault(w.ans["port"], "22")); err == nil && p > 0 {
		port = p
	}
	allow := recommendedCommands
	if c := strings.TrimSpace(w.ans["allow_commands"]); c != "" {
		allow = splitComma(c)
	}
	roots := splitComma(w.ans["roots"])
	dp := orDefault(w.ans["dir_policy"], "read_beyond")
	ro := strings.EqualFold(w.ans["read_only"], "yes")
	s := config.Server{
		Name:          w.ans["name"],
		Host:          w.ans["host"],
		Port:          port,
		Username:      w.ans["username"],
		AllowCommands: allow,
		Roots:         roots,
		DirPolicy:     dp,
		ReadOnly:      ro,
	}
	if w.ans["auth"] == "private_key" {
		s.PrivateKey = w.ans["cred"]
	} else {
		s.Password = w.ans["cred"]
	}
	return s
}

// —— 辅助函数 ——

func constPrompt(s string) func(*Wizard) string { return func(*Wizard) string { return s } }

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return strings.TrimSpace(s)
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func nonEmpty(w *Wizard, a string) error {
	if a == "" {
		return errString("不能为空")
	}
	return nil
}

func portOrEmpty(w *Wizard, a string) error {
	if a == "" {
		return nil
	}
	n, err := strconv.Atoi(a)
	if err != nil || n <= 0 {
		return errString("端口必须是正整数")
	}
	return nil
}

func oneOf(allowed ...string) func(*Wizard, string) error {
	return func(w *Wizard, a string) error {
		for _, ok := range allowed {
			if a == ok {
				return nil
			}
		}
		return errString("请输入 " + strings.Join(allowed, " 或 "))
	}
}

func absPath(w *Wizard, a string) error {
	if a == "" {
		return errString("不能为空")
	}
	if !strings.HasPrefix(a, "/") {
		return errString("必须是绝对路径（以 / 开头）")
	}
	return nil
}

func inSetOrEmpty(allowed ...string) func(*Wizard, string) error {
	return func(w *Wizard, a string) error {
		if a == "" {
			return nil
		}
		for _, ok := range allowed {
			if a == ok {
				return nil
			}
		}
		return errString("请输入 " + strings.Join(allowed, " / "))
	}
}

func yesNoEmpty(w *Wizard, a string) error {
	if a == "" {
		return nil
	}
	if strings.EqualFold(a, "yes") || strings.EqualFold(a, "no") {
		return nil
	}
	return errString("请输入 yes 或 no")
}

func anyOK(w *Wizard, a string) error { return nil }

// errString 是轻量错误类型，仅承载校验消息。
type errString string

func (e errString) Error() string { return string(e) }
