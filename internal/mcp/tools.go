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

type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

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

func NewHandler(cfg *config.Config, pool *ssh.Pool, mgr *approval.Manager) *Handler {
	return &Handler{cfg: cfg, pool: pool, approval: mgr, wizard: wizard.New(), forwards: ssh.NewForwardManager(pool)}
}

// Shutdown 清理后台资源（转发、连接池、配置监听）。
func (h *Handler) Shutdown() {
	h.forwards.StopAll()
	h.pool.Close()
	h.cfg.StopWatch()
}

func allTools() []Tool {
	str := func(props string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"type":"object","properties":%s}`, props))
	}
	return []Tool{
		{"execute-command", "在远程服务器执行命令。复合命令（; | && 等）会逐段校验白名单与路径；命令替换 $()/反引号被拒绝。路径参数须落在 roots 内",
			str(`{"command":{"type":"string"},"server":{"type":"string"},"timeout":{"type":"string"}}`)},
		{"list-servers", "列出已配置的服务器及其状态", str(`{}`)},
		{"server-status", "采集系统状态（uptime/df/free，均需通过命令白名单）", str(`{"server":{"type":"string"}}`)},
		{"list-remote", "通过 SFTP 列出远程目录（须落在 roots 内）",
			str(`{"path":{"type":"string"},"server":{"type":"string"}}`)},
		{"upload", "通过 SFTP 上传本地文件到远程（远程路径须落在 roots 内）",
			str(`{"local":{"type":"string"},"remote":{"type":"string"},"server":{"type":"string"}}`)},
		{"download", "通过 SFTP 下载远程文件到本地（远程路径须落在 roots 内）",
			str(`{"remote":{"type":"string"},"local":{"type":"string"},"server":{"type":"string"}}`)},
		{"dir-sync", "递归同步目录：direction=upload(本地src→远程dst) 或 download(远程src→本地dst)，远程路径受 roots 约束",
			str(`{"src":{"type":"string"},"dst":{"type":"string"},"direction":{"type":"string"},"server":{"type":"string"}}`)},
		{"port-forward", "本地端口转发（仅监听 127.0.0.1）：mode=start(local/remote) 启动、stop(local) 停止、list 列出",
			str(`{"mode":{"type":"string"},"local":{"type":"string"},"remote":{"type":"string"},"server":{"type":"string"}}`)},
		{"setup-wizard", "配置向导：没有配置文件时逐步生成配置。首次调用开始，之后每次把上一步的答案通过 answer 传入；传 reset=true 可重新开始",
			str(`{"answer":{"type":"string"},"reset":{"type":"boolean"}}`)},
		{"approve_last", "批准最近一次被策略拦截的请求：自动追加命令名或根目录并重试（请求 10 分钟内有效）",
			str(`{"reason":{"type":"string"}}`)},
		{"deny_last", "拒绝最近一次被策略拦截的请求", str(`{"reason":{"type":"string"}}`)},
		{"pending_approval", "查询当前是否有待审批的请求", str(`{}`)},
	}
}

func (h *Handler) Dispatch(req Request) (any, *RPCError) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "ssh-mcp-go", "version": "0.2.0"},
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
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
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

func (h *Handler) noServerHint() string {
	if h.cfg.NeedSetup() {
		return "（当前没有服务器配置，请先调用 setup-wizard 工具完成配置）"
	}
	return "（请检查 server 参数是否与 list-servers 列出的名称一致）"
}

// commandTimeout 决定单条命令的执行超时，优先级：调用参数 > 配置 > 120m。
func (h *Handler) commandTimeout(args map[string]any) time.Duration {
	if t, ok := args["timeout"].(string); ok {
		if d, err := time.ParseDuration(t); err == nil && d > 0 {
			return d
		}
	}
	return h.cfg.CommandTimeout()
}

func (h *Handler) connect(srv config.Server) (*ssh.Client, CallResult) {
	c, err := h.pool.Get(srv)
	if err != nil {
		return nil, errResult("连接服务器失败: " + err.Error())
	}
	return c, CallResult{}
}

// blockedResult 统一处理"被策略拦截"的响应：
//   - deny 模式：直接 PermissionDenied；
//   - 无任何放宽建议（系统目录硬封锁、只读、命令替换等）：直接拒绝，
//     不进入审批流（旧实现会弹出一个批准后什么都不会发生的无效请求）；
//   - 否则记录审批请求并返回交互式提示。
func (h *Handler) blockedResult(srv config.Server, kind approval.Kind, tool, detail, addCommand, addRoot, reason string, args map[string]any) CallResult {
	if h.cfg.ApprovalModeOf(srv) == config.ApprovalDeny {
		return errResult("PermissionDenied: " + reason + "\n" + detail)
	}
	if addCommand == "" && addRoot == "" {
		return errResult("策略硬拦截（不可通过审批放宽）: " + reason + "\n" + detail)
	}
	if h.approval.IsDenied(srv.Name, tool, kind, detail, addCommand, addRoot) {
		return textResult("⚠️ 该请求此前已被你拒绝放宽，如需放开请手动编辑配置文件。\n" + detail)
	}
	h.approval.Request(approval.Request{
		Kind:         kind,
		Server:       srv.Name,
		Tool:         tool,
		Detail:       detail,
		AddCommand:   addCommand,
		AddRoot:      addRoot,
		OriginalArgs: args,
	})
	suggestion := ""
	switch {
	case addCommand != "":
		suggestion = "\n建议把命令 " + addCommand + " 加入 allow_commands"
	case addRoot != "":
		suggestion = "\n建议把目录 " + addRoot + " 加入 roots"
	}
	return textResult(fmt.Sprintf(
		"⚠️ 被策略拦截（%s）。\n详情: %s%s\n是否允许？请回复 APPROVE（或调用 approve_last）放行并重试，或 DENY 拒绝。",
		reason, detail, suggestion))
}

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
	if !res.Allowed {
		return h.blockedResult(srv, approval.KindCommand, "execute-command", cmd,
			res.AddCommand, res.AddRoot, res.Reason, args)
	}
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

// approveLast 批准最近一次待审批请求，追加规则并真重试原操作。
func (h *Handler) approveLast() CallResult {
	r := h.approval.Approve()
	if r == nil {
		return textResult("当前没有待审批的请求（或请求已超过 10 分钟有效期，请重新触发一次操作）。")
	}
	srv, ok := h.cfg.ServerByName(r.Server)
	if !ok {
		return errResult("审批对应的服务器 " + r.Server + " 已不存在，无法重试")
	}

	switch r.Kind {
	case approval.KindCommand:
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
		// Append* 内部已 Reload，重新取最新策略做兜底校验
		srv, _ = h.cfg.ServerByName(r.Server)
		if res := policy.ValidateCommand(srv.AllowCommands, srv.Roots, srv.ReadOnly, srv.DirPolicy, r.Detail); res.Blocked {
			return errResult("即使已放宽策略，该命令仍被拦截: " + res.Reason + "\n命令: " + r.Detail)
		}
		client, ce := h.connect(srv)
		if ce.IsError {
			return ce
		}
		// 保留原始调用里的 timeout，不再一律退回全局默认
		out, err := ssh.RunCommand(client, r.Detail, h.commandTimeout(r.OriginalArgs), h.cfg.MaxOutputBytes())
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
		// dir-sync 的 upload 方向是写操作，旧实现一律按 read 兜底，
		// 在 read_beyond 下会错误放行越界的写路径。
		op := h.approvalOp(r)
		srv, _ = h.cfg.ServerByName(r.Server)
		if pr := policy.ValidateSftpPath(srv.Roots, srv.DirPolicy, op, r.Detail); !pr.Allowed {
			return errResult("即使已放宽策略，该路径仍被拦截: " + pr.Reason + ": " + r.Detail)
		}
		// dir-sync 自带连接与完整校验，直接重放原始参数
		if r.Tool == "dir-sync" {
			return h.dirSync(r.OriginalArgs)
		}
		client, ce := h.connect(srv)
		if ce.IsError {
			return ce
		}
		switch r.Tool {
		case "upload":
			local, _ := r.OriginalArgs["local"].(string)
			if err := ssh.Upload(client, local, r.Detail, h.cfg.SftpTimeout()); err != nil {
				return errResult("[重试上传失败] " + err.Error())
			}
			return textResult("✅ 已放行路径并重试成功：已上传 " + local + " -> " + r.Detail)
		case "download":
			local, _ := r.OriginalArgs["local"].(string)
			if err := ssh.Download(client, r.Detail, local, h.cfg.SftpTimeout()); err != nil {
				return errResult("[重试下载失败] " + err.Error())
			}
			return textResult("✅ 已放行路径并重试成功：已下载 " + r.Detail + " -> " + local)
		default: // list-remote
			out, err := ssh.ListRemote(client, r.Detail, h.cfg.SftpTimeout())
			if err != nil {
				return errResult("[重试列目录错误] " + err.Error())
			}
			return textResult("✅ 已放行路径并重试成功：\n" + out)
		}
	default:
		return errResult("不支持的审批类型: " + string(r.Kind))
	}
}

// approvalOp 推断审批请求对应的读写属性。
func (h *Handler) approvalOp(r *approval.Request) string {
	if r.Tool == "upload" {
		return "write"
	}
	if r.Tool == "dir-sync" {
		dir := strings.ToLower(strings.TrimSpace(asString(r.OriginalArgs["direction"])))
		if dir == "" || dir == "upload" {
			return "write"
		}
	}
	return "read"
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
		return textResult("无待审批请求（请求有效期 10 分钟）。")
	}
	suggestion := ""
	switch {
	case r.AddCommand != "":
		suggestion = "建议追加命令: " + r.AddCommand
	case r.AddRoot != "":
		suggestion = "建议追加根目录: " + r.AddRoot
	}
	left := approval.PendingTTL - time.Since(r.CreatedAt)
	if left < 0 {
		left = 0
	}
	return textResult(fmt.Sprintf("待审批 #%s\n类型: %s\n工具: %s\n服务器: %s\n详情: %s\n%s\n剩余有效期: %s",
		r.ID, r.Kind, r.Tool, r.Server, r.Detail, suggestion, left.Round(time.Second)))
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
	s := h.wizard.Draft()
	d := h.cfg.DefaultsSnapshot() // 加锁读取，避免与热重载 Reload 竞态
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
	_ = h.cfg.EnsureWatch()
	h.wizard = wizard.New() // 重置，避免后续空闲调用重复写入
	return textResult(fmt.Sprintf(
		"✅ 已生成配置文件：%s\n服务器 %q 已就绪，现在可以直接调用 execute-command / list-remote 等工具了。",
		h.cfg.Path, s.Name))
}

func (h *Handler) listServers() CallResult {
	var sb strings.Builder
	for _, s := range h.cfg.GetServers() {
		fmt.Fprintf(&sb, "- %s  %s:%d  user=%s\n", s.Name, s.Host, s.Port, s.Username)
	}
	if sb.Len() == 0 {
		return textResult("尚无服务器配置。" + h.noServerHint())
	}
	return textResult(sb.String())
}

// serverStatus 采集系统状态。旧实现直接执行硬编码命令，绕过了白名单；
// 现在逐条走策略校验，未授权的命令跳过并说明。
func (h *Handler) serverStatus(args map[string]any) CallResult {
	srv, ok := h.resolveServer(args)
	if !ok {
		return errResult("未找到可用服务器" + h.noServerHint())
	}
	client, ce := h.connect(srv)
	if ce.IsError {
		return ce
	}
	statusTimeout := 30 * time.Second
	if t := h.cfg.CommandTimeout(); t < statusTimeout {
		statusTimeout = t
	}
	var sb strings.Builder
	for _, c := range []string{"uptime", "df -h", "free -m"} {
		if res := policy.ValidateCommand(srv.AllowCommands, srv.Roots, srv.ReadOnly, srv.DirPolicy, c); res.Blocked {
			fmt.Fprintf(&sb, "$ %s\n[跳过：未通过命令策略] %s\n", c, res.Reason)
			continue
		}
		out, err := ssh.RunCommand(client, c, statusTimeout, h.cfg.MaxOutputBytes())
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
		return h.blockedResult(srv, approval.KindRemotePath, "list-remote", path, "", pr.AddRoot, pr.Reason, args)
	}
	client, ce := h.connect(srv)
	if ce.IsError {
		return ce
	}
	out, err := ssh.ListRemote(client, path, h.cfg.SftpTimeout())
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
	if local == "" || remote == "" {
		return errResult("缺少参数 local 或 remote")
	}
	pr := policy.ValidateSftpPath(srv.Roots, srv.DirPolicy, "write", remote)
	if !pr.Allowed {
		return h.blockedResult(srv, approval.KindRemotePath, "upload", remote, "", pr.AddRoot, pr.Reason, args)
	}
	client, ce := h.connect(srv)
	if ce.IsError {
		return ce
	}
	if err := ssh.Upload(client, local, remote, h.cfg.SftpTimeout()); err != nil {
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
	if local == "" || remote == "" {
		return errResult("缺少参数 remote 或 local")
	}
	pr := policy.ValidateSftpPath(srv.Roots, srv.DirPolicy, "read", remote)
	if !pr.Allowed {
		return h.blockedResult(srv, approval.KindRemotePath, "download", remote, "", pr.AddRoot, pr.Reason, args)
	}
	client, ce := h.connect(srv)
	if ce.IsError {
		return ce
	}
	if err := ssh.Download(client, remote, local, h.cfg.SftpTimeout()); err != nil {
		return errResult("[下载失败] " + err.Error())
	}
	return textResult("✅ 已下载 " + remote + " -> " + local)
}

// dirSync 递归同步目录。direction=upload 时 src 为本地目录、dst 为远程目录（write 策略）；
// direction=download 时 src 为远程目录（read 策略）、dst 为本地目录。
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
		return h.blockedResult(srv, approval.KindRemotePath, "dir-sync", remotePath, "", pr.AddRoot, pr.Reason, args)
	}
	client, ce := h.connect(srv)
	if ce.IsError {
		return ce
	}
	var n int
	var err error
	if direction == "upload" {
		n, err = ssh.SyncUploadDir(client, src, dst, h.cfg.SftpTimeout())
	} else {
		n, err = ssh.SyncDownloadDir(client, src, dst, h.cfg.SftpTimeout())
	}
	if err != nil {
		return errResult("[" + direction + " 同步失败] " + err.Error())
	}
	return textResult(fmt.Sprintf("✅ 目录同步完成（%s）：%s -> %s，共 %d 个文件", direction, src, dst, n))
}

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

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
