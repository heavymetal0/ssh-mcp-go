// Package policy 实现 ssh-mcp 的全部安全策略判定。
//
// 设计原则：策略"语义"写在程序里，配置只声明意图（允许哪些命令、受保护根目录、
// 以及目录权限模式）。本包同时承担两件职责：
//  1. 真实放行判定（命令名是否在 allow_commands、路径是否落在 roots 内、
//     目录权限模式如何区分读/写越界）；
//  2. 被拦截时推断"最小且安全"的放宽建议（追加命令名 / 追加根目录）。
//
// 防穿越、写命令识别、系统目录封锁、读/写越界策略等复杂逻辑全部在此硬编码，
// 不依赖配置文件里的正则黑名单。
//
// 已知边界（见 README）：白名单放行的是"命令名"，不隔离命令内部行为。一旦
// allow_commands 里包含 bash/sh/python3/ssh 等解释器或远程执行器，它们照样能
// 运行任意子程序；命令替换 $()/反引号/进程替换被硬拒绝，其余属于意图级门禁。
package policy

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// writeCommands 是内建的"写/改"命令集合。read_only=true 时一律禁止，
// 目录权限为 strict/read_beyond 时其路径参数必须落在 roots 内。
var writeCommands = map[string]bool{
	"cp": true, "mv": true, "rm": true, "rmdir": true, "mkdir": true,
	"touch": true, "ln": true, "chmod": true, "chown": true, "chgrp": true,
	"rsync": true, "rclone": true, "tar": true, "dd": true, "tee": true,
	"install": true, "truncate": true, "shred": true, "patch": true,
	"vi": true, "vim": true, "nano": true, "sed": true,
	"kill": true, "pkill": true,
	"bash": true, "sh": true, "python3": true, "python": true,
	"pip3": true, "pip": true, "ssh": true,
	"nohup": true, "setsid": true,
}

// writeSubcommands 列出"首词本身不是写命令、但特定子命令/选项会产生写副作用"的情况。
// 典型如 docker rm、systemctl restart、curl -o、find -delete。若不识别，
// read_only 与"写路径必须落在 roots 内"会被这些命令悄悄绕过。
var writeSubcommands = map[string]map[string]bool{
	"docker": {
		"run": true, "rm": true, "rmi": true, "start": true, "stop": true,
		"restart": true, "kill": true, "pull": true, "push": true,
		"build": true, "create": true, "cp": true, "exec": true,
		"pause": true, "unpause": true, "update": true, "rename": true,
		"commit": true, "import": true, "load": true, "save": true,
		"up": true, "down": true,
	},
	"docker-compose": {
		"up": true, "down": true, "start": true, "stop": true, "restart": true,
		"pull": true, "push": true, "build": true, "create": true, "rm": true,
		"run": true, "exec": true, "kill": true,
	},
	"systemctl": {
		"start": true, "stop": true, "restart": true, "reload": true,
		"enable": true, "disable": true, "mask": true, "unmask": true,
		"isolate": true, "daemon-reload": true, "set-default": true,
	},
	"synopkg": {
		"start": true, "stop": true, "restart": true, "update": true,
		"upgrade": true, "install": true, "uninstall": true,
	},
	"synoservice": {
		"--start": true, "--stop": true, "--restart": true,
		"--enable": true, "--disable": true,
	},
	"synoservicecfg": {
		"--start": true, "--stop": true, "--restart": true,
		"--enable": true, "--disable": true,
	},
	"curl": {"-o": true, "-O": true, "--output": true, "-T": true, "--upload-file": true},
	"wget": {"-O": true, "--output-document": true},
	"find": {"-delete": true, "-exec": true, "-execdir": true, "-ok": true, "-fprint": true},
}

// prefixCommands 是"前缀包装命令"：它们后面跟的才是真正要执行的命令。
// 校验时必须剥离，否则 "env FOO=1 <任意命令>" 会借 env 首词绕过白名单。
var prefixCommands = map[string]bool{
	"sudo": true, "env": true, "nohup": true, "setsid": true,
	"nice": true, "ionice": true, "command": true,
}

// protectedDirs 是程序硬封锁的系统目录（只要启用了目录权限就始终生效，
// 无论 roots 如何配置、也不可通过审批放宽）。
var protectedDirs = []string{
	"/etc", "/root", "/usr", "/bin", "/sbin", "/boot", "/sys", "/lib",
	"/lib64", "/proc", "/dev", "/var", "/volume1",
}

const (
	DirOff        = "off"
	DirStrict     = "strict"
	DirReadBeyond = "read_beyond"
)

func normalizeDirPolicy(s string) string {
	switch s {
	case DirOff, DirStrict, DirReadBeyond:
		return s
	default:
		return DirStrict
	}
}

type CommandResult struct {
	Allowed    bool
	Blocked    bool
	Reason     string
	AddCommand string
	AddRoot    string
}

type shellSegment struct {
	text     string
	redirect bool // 含输出重定向（> / >>），视作写操作
}

// ValidateCommand 校验一条待执行命令。
//
// 关键点：命令最终是整条交给远端 shell 执行的，因此不能只校验"第一个词"。
// 本函数先按 ; && || | 换行 把复合命令拆成多个子命令，逐个子命令校验
// 首词白名单 / 写命令 / 路径门禁；任何一段不合法即整条拒绝。这样既保留
// "ps aux | grep"、"cmd1 && cmd2" 等正常运维写法，又堵住 "ls ; rm -rf /"
// 借首词白名单夹带未授权命令的漏洞。命令替换 $() / 反引号 / 进程替换 <(、
// 未闭合引号一律拒绝（无法静态判定其内容）。
func ValidateCommand(allowCommands, roots []string, readOnly bool, dirPolicy string, cmd string) CommandResult {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return CommandResult{Blocked: true, Reason: "空命令"}
	}
	segments, ok := splitShellSegments(cmd)
	if !ok {
		return CommandResult{Blocked: true, Reason: "命令含命令替换 $()/反引号/进程替换或未闭合引号，无法安全校验，已拒绝"}
	}
	if len(segments) == 0 {
		return CommandResult{Blocked: true, Reason: "空命令"}
	}
	for _, seg := range segments {
		if r := validateSegment(allowCommands, roots, readOnly, dirPolicy, seg); r.Blocked {
			return r
		}
	}
	return CommandResult{Allowed: true}
}

func validateSegment(allowCommands, roots []string, readOnly bool, dirPolicy string, seg shellSegment) CommandResult {
	fields := strings.Fields(seg.text)
	if len(fields) == 0 {
		return CommandResult{Allowed: true}
	}
	cmdFields := stripPrefixes(fields)
	first := cmdFields[0]
	if !slices.Contains(allowCommands, first) {
		return CommandResult{
			Blocked:    true,
			Reason:     fmt.Sprintf("命令 %q 不在 allow_commands 允许列表", first),
			AddCommand: first,
		}
	}
	// 写子命令与路径门禁都必须基于"剥离前缀后的真实命令参数" cmdFields[1:]，
	// 不能用含 sudo/env 前缀的原始 fields[1:]：否则 "sudo /var/packages/.../docker"
	// 会把命令本体路径当成参数去检查，误命中 /var 系统目录（命令本体路径只应受
	// 白名单约束，first 已校验过）。被剥离的前缀 token（sudo/-S/变量赋值）不是
	// 传给真实命令的文件参数，跳过其路径检查不会放宽真实命令的越权判定。
	isWrite := writeCommands[first] || seg.redirect || hasWriteSubcommand(first, cmdFields[1:])
	if readOnly && isWrite {
		return CommandResult{Blocked: true, Reason: fmt.Sprintf("当前为只读模式，禁止写命令/写操作 %q", first)}
	}
	dp := normalizeDirPolicy(dirPolicy)
	for _, f := range cmdFields[1:] {
		if !looksLikePath(f) {
			continue
		}
		if ok, suggest := confinePath(roots, dp, isWrite, f); !ok {
			if suggest == "" {
				return CommandResult{
					Blocked: true,
					Reason:  fmt.Sprintf("路径 %q 越权或命中系统目录，已被拦截", f),
				}
			}
			return CommandResult{
				Blocked: true,
				Reason:  fmt.Sprintf("路径 %q 不在 roots 内", f),
				AddRoot: suggest,
			}
		}
	}
	return CommandResult{Allowed: true}
}

type PathResult struct {
	Allowed bool
	Reason  string
	AddRoot string
}

func ValidateSftpPath(roots []string, dirPolicy, op, p string) PathResult {
	if p == "" {
		return PathResult{Allowed: false, Reason: "空路径"}
	}
	dp := normalizeDirPolicy(dirPolicy)
	if dp == DirOff {
		return PathResult{Allowed: true}
	}
	if isProtected(p) {
		return PathResult{Allowed: false, Reason: fmt.Sprintf("路径 %q 命中系统目录，已被拦截", p)}
	}
	if strings.Contains(unquote(p), "..") {
		return PathResult{Allowed: false, Reason: fmt.Sprintf("路径 %q 含目录穿越，已被拦截", p)}
	}
	isWrite := op == "write"
	if dp == DirReadBeyond && !isWrite {
		return PathResult{Allowed: true}
	}
	ok, suggest := withinRoots(roots, p)
	if ok {
		return PathResult{Allowed: true}
	}
	if suggest == "" {
		return PathResult{Allowed: false, Reason: fmt.Sprintf("路径 %q 越权，已被拦截", p)}
	}
	return PathResult{Allowed: false, Reason: fmt.Sprintf("路径 %q 不在 roots 内", p), AddRoot: suggest}
}

// confinePath 是命令路径门禁的核心。
//   - 把 "a:b"、"a,b"、"key=v" 之类的复合参数拆成片段，全部做系统目录硬封锁检查，
//     修复 "docker -v /etc:/etc" 之类用冒号绕过 isProtected 的问题；
//   - roots 判定取"第一个宿主机绝对路径片段"，避免把容器内路径 /app 误判越权；
//   - ".." 一律硬拦截；远程标识符 remote:path 不受本地 roots 约束。
func confinePath(roots []string, dp string, isWrite bool, raw string) (bool, string) {
	if dp == DirOff {
		return true, ""
	}
	segs := pathSegments(raw)
	if len(segs) == 0 { // URL 等，不是本地路径
		return true, ""
	}
	if isProtected(raw) {
		return false, ""
	}
	if strings.Contains(unquote(raw), "..") {
		return false, ""
	}
	if dp == DirReadBeyond && !isWrite {
		return true, ""
	}
	if !strings.ContainsAny(raw, ":,=") {
		// 单一路径参数：保持原语义（绝对路径校验 / 相对路径拒绝）
		return withinRoots(roots, raw)
	}
	// 复合参数（挂载 / 远程标识符）：只有第一段是"宿主机本地绝对路径"时
	// 才受 roots 约束。docker -v host:container 中冒号后是容器内路径，
	// 命名卷 myvol:/app 中第一段不是路径——这两类都不该按宿主机 roots 判定。
	if !strings.HasPrefix(segs[0], "/") {
		return true, ""
	}
	return withinRoots(roots, segs[0])
}

func withinRoots(roots []string, raw string) (bool, string) {
	p := unquote(raw)
	if i := strings.LastIndex(p, "="); i >= 0 {
		p = p[i+1:]
	}
	if !filepath.IsAbs(p) {
		return false, ""
	}
	clean := filepath.Clean(p)
	for _, root := range roots {
		rc := filepath.Clean(root)
		if clean == rc || strings.HasPrefix(clean, rc+"/") {
			return true, ""
		}
	}
	if root := suggestRoot(p, clean); root != "/" {
		return false, root
	}
	return false, ""
}

// isProtected 判断路径（或复合挂载参数的任一片段）是否命中系统目录硬封锁。
func isProtected(raw string) bool {
	for _, seg := range pathSegments(raw) {
		clean := filepath.Clean(seg)
		for _, sys := range protectedDirs {
			if clean == sys || strings.HasPrefix(clean, sys+"/") {
				return true
			}
		}
	}
	return false
}

// pathSegments 把复合参数拆成候选路径片段。
// 处理：key=value、docker -v host:container、--mount a=x,b=y、rclone remote:path。
// URL（含 ://）不是本地路径，返回 nil。
func pathSegments(raw string) []string {
	if strings.Contains(raw, "://") {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ':' || r == ',' || r == '='
	})
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		// strings.Fields 不解析 shell 引号，路径片段可能带成对或散落的
		// ' / "。若不剥离，filepath.Clean("'/etc/shadow'") 不再以 /etc
		// 开头，可绕过 protectedDirs 硬封锁（如 cat '/etc/shadow'）。
		s = unquote(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// unquote 去掉 token 里的 shell 引号字符（单引号、双引号）。
// 命令行经 strings.Fields 分词后，引号会原样留在参数里；路径门禁必须
// 在引号剥离后再做 Clean/前缀匹配，否则 /etc 这类系统目录可被引号包住绕过。
// 这里刻意去掉所有引号（含零散的 /etc'/shadow'），比只处理成对引号更稳妥。
func unquote(s string) string {
	if !strings.ContainsAny(s, "'\"") {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r == '\'' || r == '"' {
			return -1
		}
		return r
	}, s)
}

func looksLikePath(arg string) bool {
	if arg == "" || strings.Contains(arg, "://") {
		return false
	}
	return isPathLike(arg)
}

func isPathLike(s string) bool {
	if strings.HasPrefix(s, "-") {
		return false
	}
	if s == "." || s == ".." {
		return true
	}
	if strings.Contains(s, "/") || strings.Contains(s, "..") {
		return true
	}
	return false
}

func suggestRoot(raw, clean string) string {
	if !filepath.IsAbs(clean) {
		return ""
	}
	if strings.HasSuffix(raw, "/") {
		return clean
	}
	base := filepath.Base(clean)
	if strings.Contains(base, ".") {
		return filepath.Dir(clean)
	}
	return clean
}

// splitShellSegments 把复合命令按 ; && || | 换行 拆成独立子命令。
// 引号内的分隔符不拆；命令替换 $()/反引号/进程替换 <( >( 与未闭合引号
// 判定为不安全（ok=false），因为它们能执行任意隐藏命令。
// 重定向 > < 与末尾单个 &（后台）保留语义但不引入新子命令。
func splitShellSegments(cmd string) ([]shellSegment, bool) {
	var segs []shellSegment
	var cur strings.Builder
	inSingle, inDouble, escaped := false, false, false
	redirect := false
	end := len(strings.TrimRight(cmd, " \t\r\n"))
	flush := func() {
		t := strings.TrimSpace(cur.String())
		if t != "" {
			segs = append(segs, shellSegment{text: t, redirect: redirect})
		}
		cur.Reset()
		redirect = false
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if escaped {
			cur.WriteByte(c)
			escaped = false
			continue
		}
		if inSingle {
			cur.WriteByte(c)
			if c == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			if c == '`' || (c == '$' && i+1 < len(cmd) && cmd[i+1] == '(') {
				return nil, false
			}
			cur.WriteByte(c)
			if c == '\\' {
				escaped = true
			} else if c == '"' {
				inDouble = false
			}
			continue
		}
		switch c {
		case '\\':
			cur.WriteByte(c)
			escaped = true
		case '\'':
			inSingle = true
			cur.WriteByte(c)
		case '"':
			inDouble = true
			cur.WriteByte(c)
		case '`':
			return nil, false
		case '$':
			if i+1 < len(cmd) && cmd[i+1] == '(' {
				return nil, false
			}
			cur.WriteByte(c)
		case '>', '<':
			if i+1 < len(cmd) && cmd[i+1] == '(' {
				return nil, false // 进程替换
			}
			if c == '>' && !(i+1 < len(cmd) && cmd[i+1] == '&') {
				redirect = true // >&2 / 2>&1 是 fd 复制，不算写文件
			}
			cur.WriteByte(c)
		case ';', '\n', '\r', '|':
			flush()
		case '&':
			// 2>&1、>&2、&>file 中的 & 属于重定向；末尾单个 & 是后台执行
			prev := byte(' ')
			for k := i - 1; k >= 0; k-- {
				if cmd[k] != ' ' && cmd[k] != '\t' {
					prev = cmd[k]
					break
				}
			}
			if prev == '>' || (i+1 < len(cmd) && cmd[i+1] == '>') {
				cur.WriteByte(c)
				continue
			}
			if i == end-1 && (i == 0 || cmd[i-1] != '&') {
				continue // 末尾后台符，丢弃即可
			}
			flush() // && 或 cmd1 & cmd2：拆成独立子命令
		default:
			cur.WriteByte(c)
		}
	}
	if inSingle || inDouble {
		return nil, false
	}
	flush()
	return segs, true
}

func hasWriteSubcommand(first string, args []string) bool {
	set, ok := writeSubcommands[first]
	if !ok {
		return false
	}
	for _, a := range args {
		if set[a] {
			return true
		}
	}
	return false
}

// stripPrefixes 剥离开头的 sudo/env/nohup/setsid 等包装命令及其选项/变量赋值，
// 返回真实命令字段。若剥离后为空则原样返回，交由白名单判定处理。
func stripPrefixes(fields []string) []string {
	i := 0
	for i < len(fields) && prefixCommands[fields[i]] {
		i++
		for i < len(fields) {
			t := fields[i]
			if t == "--" {
				i++
				break
			}
			if strings.HasPrefix(t, "-") {
				if (t == "-u" || t == "-g" || t == "--user" || t == "--group" || t == "-n" || t == "-c") && i+1 < len(fields) {
					i += 2
				} else {
					i++
				}
				continue
			}
			if strings.Contains(t, "=") { // 环境变量赋值
				i++
				continue
			}
			break
		}
	}
	if i >= len(fields) || i == 0 {
		return fields
	}
	return fields[i:]
}

func IsWriteCommand(name string) bool { return writeCommands[name] }
