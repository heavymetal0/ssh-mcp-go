package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"ssh-mcp-go/internal/approval"
	"ssh-mcp-go/internal/config"
	"ssh-mcp-go/internal/policy"
	"ssh-mcp-go/internal/ssh"
	"ssh-mcp-go/internal/wizard"
)

// Tool 描述一个 MCP 工具（用于 tools/list）。
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// Content 是工具结果中的一段文本。
type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// CallResult 是 tools/call 的返回体。
type CallResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

func textResult(t string) CallResult {
	return CallResult{Content: []Content{{Type: "text", Text: t}}}
}
func errResult(t string) CallResult {
	return CallResult{Content: []Content{{Type: "text", Text: t}}, IsError: true}
}

// Handler 聚合服务所需的依赖。
type Handler struct {
	cfg      *config.Config
	pool     *ssh.Pool
	approval *approval.Manager
	wizard   *wizard.Wizard
	forwards *ssh.ForwardManager
}

// NewHandler 创建处理器。
func NewHandler(cfg *config.Config, pool *ssh.Pool, mgr *approval.Manager) *Handler {
	return &Handler{cfg: cfg, pool: pool, approval: mgr, wizard: wizard.New(), forwards: ssh.NewForwardManager(pool)}
}

// allTools 返回全部工具定义（含原工具 + 审批工具）。
func allTools() []Tool {
	str := func(props string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"type":"object","properties":%s}`, props))
	}
	return []Tool{
		{"execute-command", "在远程服务器执行命令（首词须在 allow_commands 内，路径参数须落在 roots 内，程序自动防穿越）",
			str(`{"command":{"type":"string"},"server":{"type":"string"},"timeout":{"type":"string"}}`)},
		{"list-servers", "列出已配置的服务器及其状态", str(`{}`)},
		{"server-status", "采集系统状态（CPU/内存/磁盘等）", str(`{"server":{"type":"string"}}`)},
		{"list-remote", "通过 SFTP 列出远程目录（须落在 roots 内）",
			str(`{"path":{"type":"string"},"server":{"type":"string"}}`)},
		{"upload", "通过 SFTP 上传本地文件到远程（远程路径须落在 roots 内）",
			str(`{"local":{"type":"string"},"remote":{"type":"string"},"server":{"type":"string"}}`)},
		{"download", "通过 SFTP 下载远程文件到本地（远程路径须落在 roots 内）",
			str(`{"remote":{"type":"string"},"local":{"type":"string"},"server":{"type":"string"}}`)},
		{"dir-sync", "递归同步目录：direction=upload(本地src→远程dst) 或 download(远程src→本地dst)，远程路径受 roots 约束",
			str(`{"src":{"type":"string"},"dst":{"type":"string"},"direction":{"type":"string"},"server":{"type":"string"}}`)},
		{"port-forward", "本地端口转发：mode=start(local/remote) 启动、stop(local) 停止、list 列出。remote 为从 SSH 服务器视角可达的地址",
			str(`{"mode":{"type":"string"},"local":{"type":"string"},"remote":{"type":"string"},"server":{"type":"string"}}`)},
		// —— 配置向导 ——
		{"setup-wizard", "配置向导：没有配置文件时逐步生成配置。首次调用开始，之后每次把上一步的答案通过 answer 传入；传 reset=true 可重新开始",
			str(`{"answer":{"type":"string"},"reset":{"type":"boolean"}}`)},
		// —— 审批闭环工具 ——
		{"approve_last", "批准最近一次被策略拦截的请求：自动追加命令名或根目录并重试",
			str(`{"reason":{"type":"string"}}`)},
		{"deny_last", "拒绝最近一次被策略拦截的请求", str(`{"reason":{"type":"string"}}`)},
		{"pending_approval", "查询当前是否有待审批的请求", str(`{}`)},
	}
}

// Dispatch 是 MCP 请求分发入口。
func (h *Handler) Dispatch(req Request) (any, *RPCError) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": true}},
			"serverInfo":      map[string]any{"name": "ssh-mcp-go", "version": "0.1.0"},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": allTools()}, nil
	case "tools/call":
		return h.handleToolCall(req)
	default:
		return nil, &RPCError{Code: -32601, Message: "method not found: " + req.Method}
	}
}

type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

func (h *Handler) handleToolCall(req Request) (any, *RPCError) {
	var p callParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResult("参数解析失败: " + err.Error()), nil
	}
	var res CallResult
	switch p.Name {
	case "execute-command":
		res = h.executeCommand(p.Arguments)
	case "list-servers":
		res = h.listServers()
	case "server-status":
		res = h.serverStatus(p.Arguments)
	case "list-remote":
		res = h.listRemote(p.Arguments)
	case "upload":
		res = h.upload(p.Arguments)
	case "download":
		res = h.download(p.Arguments)
	case "dir-sync":
		res = h.dirSync(p.Arguments)
	case "port-forward":
		res = h.portForward(p.Arguments)
	case "approve_last":
		res = h.approveLast()
	case "deny_last":
		res = h.denyLast()
	case "pending_approval":
		res = h.pendingApproval()
	case "setup-wizard":
		res = h.setupWizard(p.Arguments)
	default:
		res = errResult("未知工具: " + p.Name)
	}
	return res, nil
}

// resolveServer 按名称或默认取服务器。
func (h *Handler) resolveServer(args map[string]any) (config.Server, bool) {
	if name, ok := args["server"].(string); ok && name != "" {
		return h.cfg.ServerByName(name)
	}
	return h.cfg.ServerByName("")
}

// noServerHint 在没有可用服务器时给出配置引导提示。
func (h *Handler) noServerHint() string {
	if h.cfg.NeedsSetup {
		return "（当前没有服务器配置，请先调用 setup-wizard 工具完成配置）"
	}
	return ""
}

// commandTimeout 决定单条命令的执行超时，优先级从高到低：
//  1. 工具调用参数 timeout（如 "30s"、"2m"，仅本次生效）；
//  2. 配置 defaults.command_timeout（全局默认，热重载后对新调用生效）；
//  3. 代码兜底 120m。
func (h *Handler) commandTimeout(args map[string]any) time.Duration {
	if t, ok := args["timeout"].(string); ok {
		if d, err := time.ParseDuration(t); err == nil && d > 0 {
			return d
		}
	}
	return h.cfg.CommandTimeout()
}

// connect 取得（或建立）到服务器的连接，错误以 errResult 形式返回。
func (h *Handler) connect(srv config.Server) (*ssh.Client, CallResult) {
	c, err := h.pool.Get(srv)
	if err != nil {
		return nil, errResult("连接服务器失败: " + err.Error())
	}
	return c, CallResult{}
}

// executeCommand 执行命令；被策略拦截时返回"对话式审批"提示而非报错。
func (h *Handler) executeCommand(args map[string]any) CallResult {
	cmd, _ := args["command"].(string)
	if cmd == "" {
		return errResult("缺少参数 command")
	}
	srv, ok := h.resolveServer(args)
	if !ok {
		return errResult("未找到可用服务器" + h.noServerHint())
	}
	res := policy.ValidateCommand(srv.AllowCommands, srv.Roots, srv.ReadOnly, srv.DirPolicy, cmd)
	if res.Allowed {
		client, ce := h.connect(srv)
		if ce.IsError {
			return ce
		}
		out, err := ssh.RunCommand(client, cmd, h.commandTimeout(args), h.cfg.MaxOutputBytes())
		if err != nil {
			return errResult(out + "\n[执行错误] " + err.Error())
		}
		return textResult(out)
	}
	// 审批模式为 deny：直接返回 PermissionDenied，不询问（兼容无审批流的客户端）
	if h.cfg.ApprovalModeOf(srv) == config.ApprovalDeny {
		return errResult("PermissionDenied: " + res.Reason + "\n命令: " + cmd)
	}
	// 被拦截：先查拒绝集，避免反复弹窗
	if h.approval.IsDenied(approval.KindCommand, cmd, res.AddCommand, res.AddRoot) {
		return textResult("⚠️ 该请求此前已被你拒绝放宽，如需放开请手动编辑配置文件。\n命令: " + cmd)
	}
	suggestion := ""
	switch {
	case res.AddCommand != "":
		suggestion = "建议把命令 " + res.AddCommand + " 加入 allow_commands"
	case res.AddRoot != "":
		suggestion = "建议把目录 " + res.AddRoot + " 加入 roots"
	}
	h.approval.Request(approval.Request{
		Kind:         approval.KindCommand,
		Server:       srv.Name,
		Detail:       cmd,
		AddCommand:   res.AddCommand,
		AddRoot:      res.AddRoot,
		OriginalArgs: args,
	})
	prompt := fmt.Sprintf(
		"⚠️ 命令被策略拦截（%s）。\n原命令: %s", res.Reason, cmd)
	if suggestion != "" {
		prompt += "\n" + suggestion
	}
	prompt += "\n是否允许？请回复 APPROVE（或调用 approve_last）放行并重试，或 DENY（deny_last）拒绝。"
	return textResult(prompt)
}

// approveLast 批准最近一次待审批请求并自动重试。
func (h *Handler) approveLast() CallResult {
	r := h.approval.Approve()
	if r == nil {
		return textResult("当前没有待审批的请求。")
	}
	switch r.Kind {
	case approval.KindCommand:
		// 依次应用结构化的最小放宽（追加命令名 / 追加根目录）
		if r.AddCommand != "" {
			if err := h.cfg.AppendAllowCommand(r.Server, r.AddCommand); err != nil {
				return errResult("写入 allow_commands 失败: " + err.Error())
			}
		}
		if r.AddRoot != "" {
			if err := h.cfg.AppendRoot(r.Server, r.AddRoot); err != nil {
				return errResult("写入 roots 失败: " + err.Error())
			}
		}
		_ = h.cfg.Reload()
		srv, _ := h.cfg.ServerByName(r.Server)
		// 兜底校验：即便已放宽，系统目录封锁等规则仍不可被批准绕过
		if res := policy.ValidateCommand(srv.AllowCommands, srv.Roots, srv.ReadOnly, srv.DirPolicy, r.Detail); res.Blocked {
			return errResult("即使已放宽策略，该命令仍被拦截: " + res.Reason + "\n命令: " + r.Detail)
		}
		client, ce := h.connect(srv)
		if ce.IsError {
			return ce
		}
		out, err := ssh.RunCommand(client, r.Detail, h.cfg.CommandTimeout(), h.cfg.MaxOutputBytes())
		if err != nil {
			return errResult(out + "\n[重试执行错误] " + err.Error())
		}
		return textResult("✅ 已放宽策略并重试成功：\n" + out)
	case approval.KindRemotePath:
		if r.AddRoot != "" {
			if err := h.cfg.AppendRoot(r.Server, r.AddRoot); err != nil {
				return errResult("写入 roots 失败: " + err.Error())
			}
		}
		_ = h.cfg.Reload()
		srv, _ := h.cfg.ServerByName(r.Server)
		op := "read"
		if r.Tool == "upload" {
			op = "write"
		}
		// 兜底校验：系统目录封锁等规则仍不可被批准绕过
		if pr := policy.ValidateSftpPath(srv.Roots, srv.DirPolicy, op, r.Detail); !pr.Allowed {
			return errResult("即使已放宽策略，该路径仍被拦截: " + pr.Reason + ": " + r.Detail)
		}
		client, ce := h.connect(srv)
		if ce.IsError {
			return ce
		}
		switch r.Tool {
		case "upload":
			local, _ := r.OriginalArgs["local"].(string)
			if err := ssh.Upload(client, local, r.Detail); err != nil {
				return errResult("[重试上传失败] " + err.Error())
			}
			return textResult("✅ 已放行路径并重试成功：已上传 " + local + " -> " + r.Detail)
		case "download":
			local, _ := r.OriginalArgs["local"].(string)
			if err := ssh.Download(client, r.Detail, local); err != nil {
				return errResult("[重试下载失败] " + err.Error())
			}
			return textResult("✅ 已放行路径并重试成功：已下载 " + r.Detail + " -> " + local)
		case "dir-sync":
			return h.dirSync(r.OriginalArgs)
		default: // list-remote
			out, err := ssh.ListRemote(client, r.Detail)
			if err != nil {
				return errResult("[重试列目录错误] " + err.Error())
			}
			return textResult("✅ 已放行路径并重试成功：\n" + out)
		}
	default:
		return errResult("不支持的审批类型: " + string(r.Kind))
	}
}

func (h *Handler) denyLast() CallResult {
	r := h.approval.Deny()
	if r == nil {
		return textResult("当前没有待审批的请求。")
	}
	return textResult("🚫 已拒绝请求（" + string(r.Kind) + "）：" + r.Detail + "\n未做任何配置改动。")
}

func (h *Handler) pendingApproval() CallResult {
	r := h.approval.Get()
	if r == nil {
		return textResult("无待审批请求。")
	}
	suggestion := ""
	switch {
	case r.AddCommand != "":
		suggestion = "建议追加命令: " + r.AddCommand
	case r.AddRoot != "":
		suggestion = "建议追加根目录: " + r.AddRoot
	}
	return textResult(fmt.Sprintf("待审批 #%s\n类型: %s\n服务器: %s\n详情: %s\n%s",
		r.ID, r.Kind, r.Server, r.Detail, suggestion))
}

// setupWizard 驱动配置向导：逐步收集答案，完成后写出配置文件并热重载。
func (h *Handler) setupWizard(args map[string]any) CallResult {
	answer, _ := args["answer"].(string)
	if reset, _ := args["reset"].(bool); reset {
		h.wizard = wizard.New()
	}
	prompt, done, err := h.wizard.Step(answer)
	if err != nil {
		return errResult("向导内部错误: " + err.Error())
	}
	if !done {
		return textResult(prompt)
	}
	// 收集完成：组装配置并写出
	s := h.wizard.Draft()
	d := h.cfg.Defaults
	if d.CommandTimeout == "" {
		d = config.DefaultDefaults()
	}
	servers := h.cfg.GetServers()
	servers = append(servers, s)
	if err := config.WriteConfig(h.cfg.Path, &config.Config{
		Path:     h.cfg.Path,
		Defaults: d,
		Servers:  servers,
	}); err != nil {
		return errResult("写入配置文件失败: " + err.Error())
	}
	if err := h.cfg.Reload(); err != nil {
		return errResult("重载配置失败: " + err.Error())
	}
	_ = h.cfg.EnsureWatch() // 首次生成文件后启用热重载监听
	h.wizard = wizard.New() // 重置向导，避免后续空闲调用重复写入
	return textResult(fmt.Sprintf(
		"✅ 已生成配置文件：%s\n服务器 %q 已就绪，现在可以直接调用 execute-command / list-remote 等工具了。",
		h.cfg.Path, s.Name))
}

func (h *Handler) listServers() CallResult {
	var sb strings.Builder
	for _, s := range h.cfg.GetServers() {
		fmt.Fprintf(&sb, "- %s  %s:%d  user=%s\n", s.Name, s.Host, s.Port, s.Username)
	}
	return textResult(sb.String())
}

func (h *Handler) serverStatus(args map[string]any) CallResult {
	srv, ok := h.resolveServer(args)
	if !ok {
		return errResult("未找到可用服务器" + h.noServerHint())
	}
	client, ce := h.connect(srv)
	if ce.IsError {
		return ce
	}
	var sb strings.Builder
	for _, c := range []string{"uptime", "df -h", "free -m"} {
		out, err := ssh.RunCommand(client, c, h.cfg.CommandTimeout(), h.cfg.MaxOutputBytes())
		fmt.Fprintf(&sb, "$ %s\n%s\n", c, out)
		if err != nil {
			fmt.Fprintf(&sb, "[错误] %v\n", err)
		}
	}
	return textResult(sb.String())
}

func (h *Handler) listRemote(args map[string]any) CallResult {
	path, _ := args["path"].(string)
	srv, ok := h.resolveServer(args)
	if !ok {
		return errResult("未找到可用服务器" + h.noServerHint())
	}
	if path == "" {
		if len(srv.Roots) > 0 {
			path = srv.Roots[0]
		} else {
			path = "/"
		}
	}
	pr := policy.ValidateSftpPath(srv.Roots, srv.DirPolicy, "read", path)
	if !pr.Allowed {
		if h.cfg.ApprovalModeOf(srv) == config.ApprovalDeny {
			return errResult("PermissionDenied: " + pr.Reason + ": " + path)
		}
		if h.approval.IsDenied(approval.KindRemotePath, path, "", pr.AddRoot) {
			return textResult("⚠️ 该路径此前已拒绝放行，请手动编辑 roots。")
		}
		h.approval.Request(approval.Request{
			Kind: approval.KindRemotePath, Server: srv.Name, Tool: "list-remote",
			Detail: path, AddRoot: pr.AddRoot, OriginalArgs: args,
		})
		suggestion := ""
		if pr.AddRoot != "" {
			suggestion = "\n建议把目录 " + pr.AddRoot + " 加入 roots"
		}
		return textResult(fmt.Sprintf(
			"⚠️ 远程路径 %s 不在 roots 内（%s）。%s\n是否允许？APPROVE / DENY。", path, pr.Reason, suggestion))
	}
	client, ce := h.connect(srv)
	if ce.IsError {
		return ce
	}
	out, err := ssh.ListRemote(client, path)
	if err != nil {
		return errResult("[列目录错误] " + err.Error())
	}
	return textResult(out)
}

func (h *Handler) upload(args map[string]any) CallResult {
	local, _ := args["local"].(string)
	remote, _ := args["remote"].(string)
	srv, ok := h.resolveServer(args)
	if !ok {
		return errResult("未找到可用服务器" + h.noServerHint())
	}
	pr := policy.ValidateSftpPath(srv.Roots, srv.DirPolicy, "write", remote)
	if !pr.Allowed {
		if h.cfg.ApprovalModeOf(srv) == config.ApprovalDeny {
			return errResult("PermissionDenied: " + pr.Reason + ": " + remote)
		}
		if h.approval.IsDenied(approval.KindRemotePath, remote, "", pr.AddRoot) {
			return textResult("⚠️ 该路径此前已拒绝放行，请手动编辑 roots。")
		}
		h.approval.Request(approval.Request{Kind: approval.KindRemotePath, Server: srv.Name, Tool: "upload", Detail: remote, AddRoot: pr.AddRoot, OriginalArgs: args})
		suggestion := ""
		if pr.AddRoot != "" {
			suggestion = "\n建议把目录 " + pr.AddRoot + " 加入 roots"
		}
		return textResult(fmt.Sprintf("⚠️ 远程路径 %s 不在 roots 内（%s）。%s\n是否允许？APPROVE / DENY。", remote, pr.Reason, suggestion))
	}
	client, ce := h.connect(srv)
	if ce.IsError {
		return ce
	}
	if err := ssh.Upload(client, local, remote); err != nil {
		return errResult("[上传失败] " + err.Error())
	}
	return textResult("✅ 已上传 " + local + " -> " + remote)
}

func (h *Handler) download(args map[string]any) CallResult {
	remote, _ := args["remote"].(string)
	local, _ := args["local"].(string)
	srv, ok := h.resolveServer(args)
	if !ok {
		return errResult("未找到可用服务器" + h.noServerHint())
	}
	pr := policy.ValidateSftpPath(srv.Roots, srv.DirPolicy, "read", remote)
	if !pr.Allowed {
		if h.cfg.ApprovalModeOf(srv) == config.ApprovalDeny {
			return errResult("PermissionDenied: " + pr.Reason + ": " + remote)
		}
		if h.approval.IsDenied(approval.KindRemotePath, remote, "", pr.AddRoot) {
			return textResult("⚠️ 该路径此前已拒绝放行，请手动编辑 roots。")
		}
		h.approval.Request(approval.Request{Kind: approval.KindRemotePath, Server: srv.Name, Tool: "download", Detail: remote, AddRoot: pr.AddRoot, OriginalArgs: args})
		suggestion := ""
		if pr.AddRoot != "" {
			suggestion = "\n建议把目录 " + pr.AddRoot + " 加入 roots"
		}
		return textResult(fmt.Sprintf("⚠️ 远程路径 %s 不在 roots 内（%s）。%s\n是否允许？APPROVE / DENY。", remote, pr.Reason, suggestion))
	}
	client, ce := h.connect(srv)
	if ce.IsError {
		return ce
	}
	if err := ssh.Download(client, remote, local); err != nil {
		return errResult("[下载失败] " + err.Error())
	}
	return textResult("✅ 已下载 " + remote + " -> " + local)
}

// dirSync 递归同步目录。direction=upload 时 src 为本地目录、dst 为远程目录（受 write 策略约束）；
// direction=download 时 src 为远程目录（受 read 策略约束）、dst 为本地目录。
func (h *Handler) dirSync(args map[string]any) CallResult {
	src, _ := args["src"].(string)
	dst, _ := args["dst"].(string)
	direction := strings.ToLower(strings.TrimSpace(asString(args["direction"])))
	if direction == "" {
		direction = "upload"
	}
	if src == "" || dst == "" {
		return errResult("缺少参数 src 或 dst")
	}
	if direction != "upload" && direction != "download" {
		return errResult("direction 只能是 upload 或 download")
	}
	srv, ok := h.resolveServer(args)
	if !ok {
		return errResult("未找到可用服务器" + h.noServerHint())
	}

	remotePath, op := dst, "write"
	if direction == "download" {
		remotePath, op = src, "read"
	}
	pr := policy.ValidateSftpPath(srv.Roots, srv.DirPolicy, op, remotePath)
	if !pr.Allowed {
		if h.cfg.ApprovalModeOf(srv) == config.ApprovalDeny {
			return errResult("PermissionDenied: " + pr.Reason + ": " + remotePath)
		}
		if h.approval.IsDenied(approval.KindRemotePath, remotePath, "", pr.AddRoot) {
			return textResult("⚠️ 该路径此前已拒绝放行，请手动编辑 roots。")
		}
		h.approval.Request(approval.Request{Kind: approval.KindRemotePath, Server: srv.Name, Tool: "dir-sync", Detail: remotePath, AddRoot: pr.AddRoot, OriginalArgs: args})
		suggestion := ""
		if pr.AddRoot != "" {
			suggestion = "\n建议把目录 " + pr.AddRoot + " 加入 roots"
		}
		return textResult(fmt.Sprintf("⚠️ 远程路径 %s 不在 roots 内（%s）。%s\n是否允许？APPROVE / DENY。", remotePath, pr.Reason, suggestion))
	}

	client, ce := h.connect(srv)
	if ce.IsError {
		return ce
	}
	var n int
	var err error
	if direction == "upload" {
		n, err = ssh.SyncUploadDir(client, src, dst)
	} else {
		n, err = ssh.SyncDownloadDir(client, src, dst)
	}
	if err != nil {
		return errResult("[" + direction + " 同步失败] " + err.Error())
	}
	return textResult(fmt.Sprintf("✅ 目录同步完成（%s）：%s -> %s，共 %d 个文件", direction, src, dst, n))
}

// portForward 管理本地端口转发：start / stop / list。
func (h *Handler) portForward(args map[string]any) CallResult {
	mode := strings.ToLower(strings.TrimSpace(asString(args["mode"])))
	if mode == "" {
		mode = "list"
	}
	switch mode {
	case "list":
		fw := h.forwards.List()
		if len(fw) == 0 {
			return textResult("当前没有活动的本地转发。")
		}
		var sb strings.Builder
		sb.WriteString("活动的本地转发：\n")
		for _, f := range fw {
			fmt.Fprintf(&sb, "- %s -> %s (经服务器 %s)\n", f.LocalAddr, f.RemoteAddr, f.Server)
		}
		return textResult(sb.String())
	case "stop":
		local := asString(args["local"])
		if local == "" {
			return errResult("stop 需要 local 参数")
		}
		if h.forwards.Stop(local) {
			return textResult("✅ 已停止转发 " + local)
		}
		return textResult("未找到转发 " + local)
	case "start":
		local := asString(args["local"])
		remote := asString(args["remote"])
		if local == "" || remote == "" {
			return errResult("start 需要 local 与 remote 参数")
		}
		srv, ok := h.resolveServer(args)
		if !ok {
			return errResult("未找到可用服务器" + h.noServerHint())
		}
		f, err := h.forwards.Start(srv, local, remote)
		if err != nil {
			return errResult("[启动转发失败] " + err.Error())
		}
		return textResult(fmt.Sprintf("✅ 已启动本地转发：%s -> %s（经服务器 %s）。\n使用完毕请用 port-forward mode=stop local=%s 关闭。", f.LocalAddr, f.RemoteAddr, f.Server, f.LocalAddr))
	default:
		return errResult("mode 只能是 start / stop / list")
	}
}

// asString 从 map 值安全地取字符串（兼容 JSON 解码后的 string）。
func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
