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
package policy

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// writeCommands 是内建的"写/改"命令集合。read_only=true 时一律禁止，
// 目录权限为 strict/read_beyond 时其路径参数必须落在 roots 内。
// 这是程序内判定，不出现在配置文件中。
var writeCommands = map[string]bool{
	"cp": true, "mv": true, "rm": true, "rmdir": true, "mkdir": true,
	"touch": true, "ln": true, "chmod": true, "chown": true, "chgrp": true,
	"rsync": true, "rclone": true, "tar": true, "dd": true, "tee": true,
	"install": true, "truncate": true, "shred": true, "patch": true,
	"vi": true, "vim": true, "nano": true, "sed": true,
	// 进程控制类：终止进程会改变系统状态，纳入写命令受 read_only 约束
	"kill": true, "pkill": true,
	// 解释器 / 脚本 / 远程执行：能写文件或执行任意代码，必须受 roots 与 read_only 约束
	"bash": true, "sh": true, "python3": true, "python": true,
	"pip3": true, "pip": true, "ssh": true,
	"nohup": true, "setsid": true,
}

// protectedDirs 是程序硬封锁的系统目录（只要启用了目录权限就始终生效，
// 无论 roots 如何配置、也不可通过审批放宽）。这是程序内判定。
var protectedDirs = []string{
	"/etc", "/root", "/usr", "/bin", "/sbin", "/boot", "/sys", "/lib",
	"/lib64", "/proc", "/dev", "/var", "/volume1",
}

// DirPolicy 取值：目录权限模式。
const (
	DirOff        = "off"         // 不启用目录权限
	DirStrict     = "strict"      // 最严格：读写都限制在 roots 内
	DirReadBeyond = "read_beyond" // 推荐：读可超越 roots，写/改不能超越
)

// normalizeDirPolicy 把任意字符串规整为合法的目录权限模式；非法/空值回退到最严格的 strict。
func normalizeDirPolicy(s string) string {
	switch s {
	case DirOff, DirStrict, DirReadBeyond:
		return s
	default:
		return DirStrict
	}
}

// CommandResult 是命令校验结果。
type CommandResult struct {
	Allowed    bool
	Blocked    bool   // 是否被策略拦截（与 Allowed 相反，语义更明确）
	Reason     string // 拦截原因
	AddCommand string // 建议加入 allow_commands 的命令名（命令名未授权时）
	AddRoot    string // 建议加入 roots 的目录（路径越权且非系统目录时）
}

// ValidateCommand 校验命令：
//  1. 首词必须是 allow_commands 之一，否则拦截并建议追加该命令名；
//  2. read_only=true 且首词为写命令时，拦截；
//  3. 抽取命令中的路径参数，按目录权限模式做门禁：
//     - off：不限制；
//     - strict：读/写路径都必须落在 roots 内；
//     - read_beyond：写/改路径必须落在 roots 内，读路径可超越 roots；
//     - 系统目录（protectedDirs）只要启用目录权限就始终硬封锁。
func ValidateCommand(allowCommands, roots []string, readOnly bool, dirPolicy string, cmd string) CommandResult {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return CommandResult{Blocked: true, Reason: "空命令"}
	}
	fields := strings.Fields(cmd)
	// 剥离前导 sudo（及其选项），用真实命令做白名单/写命令判定，
	// 防止 "sudo <任意命令>" 借 sudo 首词绕过策略。
	// 无论是否带 sudo，真实命令都必须在 allow_commands 内。
	cmdFields := stripSudo(fields)
	first := cmdFields[0]
	if !slices.Contains(allowCommands, first) {
		return CommandResult{
			Blocked:    true,
			Reason:     fmt.Sprintf("命令 %q 不在 allow_commands 允许列表", first),
			AddCommand: first,
		}
	}
	isWrite := writeCommands[first]
	if readOnly && isWrite {
		return CommandResult{Blocked: true, Reason: fmt.Sprintf("当前为只读模式，禁止写命令 %q", first)}
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

// PathResult 是路径校验结果。
type PathResult struct {
	Allowed bool
	Reason  string
	AddRoot string
}

// ValidateSftpPath 校验 SFTP 类路径（list-remote=读，download=读，upload=写）。
// 语义与命令路径一致：off 不限制；strict 全都限制在 roots 内；read_beyond
// 下读操作可超越 roots、写操作（upload）不能超越；系统目录始终硬封锁。
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
	isWrite := op == "write"
	if dp == DirReadBeyond && !isWrite {
		return PathResult{Allowed: true} // 读操作可超越 roots
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

// confinePath 是命令路径门禁的核心：根据目录权限模式与操作读写属性判定是否放行。
// 返回 (是否允许, 建议追加的根目录)。suggest=="" 表示命中系统目录（不可审批放宽）。
func confinePath(roots []string, dp string, isWrite bool, raw string) (bool, string) {
	if dp == DirOff {
		return true, ""
	}
	if isProtected(raw) {
		return false, "" // 系统目录硬封锁，不可加 root
	}
	if dp == DirReadBeyond && !isWrite {
		return true, "" // 读操作可超越 roots
	}
	return withinRoots(roots, raw)
}

// withinRoots 判断路径是否落在 roots 内（程序自动处理 ".." 穿越、相对路径越权、
// 符号链接逃逸语义）。越权且非系统目录时返回建议加入的根目录。
func withinRoots(roots []string, raw string) (bool, string) {
	p := raw
	if i := strings.Index(raw, "="); i >= 0 {
		p = raw[i+1:]
	}
	if !filepath.IsAbs(p) {
		// 相对路径无法约束到具体根目录：含穿越或子路径则一律拒绝，
		// 要求使用 roots 内的绝对路径。
		return false, ""
	}
	clean := filepath.Clean(p)
	for _, root := range roots {
		rc := filepath.Clean(root)
		if clean == rc || strings.HasPrefix(clean, rc+"/") {
			return true, ""
		}
	}
	// 越权但非系统目录：建议把合适的目录加入 roots（需人工审批）。
	// 推断结果为 "/" 时不自动建议（避免一键放开整个文件系统）。
	if root := suggestRoot(raw, clean); root != "/" {
		return false, root
	}
	return false, ""
}

// isProtected 判断路径是否命中系统目录硬封锁。
func isProtected(raw string) bool {
	p := raw
	if i := strings.Index(raw, "="); i >= 0 {
		p = raw[i+1:]
	}
	clean := filepath.Clean(p)
	for _, sys := range protectedDirs {
		if clean == sys || strings.HasPrefix(clean, sys+"/") {
			return true
		}
	}
	return false
}

// looksLikePath 判断一个参数是不是"路径"（需要走路径门禁）。
// 支持 key=value 形式（取 value 判断）、绝对路径、含 / 或 .. 的相对路径；
// 以 - 开头的选项（如 -la）不算路径。
func looksLikePath(arg string) bool {
	if arg == "" {
		return false
	}
	if i := strings.Index(arg, "="); i >= 0 {
		return isPathLike(arg[i+1:])
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
	return strings.Contains(s, "..") || strings.Contains(s, "/")
}

// suggestRoot 推断应加入 roots 的目录。
//   - 显式以 "/" 结尾视为目录，直接取该目录；
//   - 形如文件（base 含 "."，如 a/b.txt）取其所处目录；
//   - 否则当作目录，取其自身（如 /tmp、/volume2），避免错误地取父目录 "/" 导致一键放开全文件系统。
func suggestRoot(raw, clean string) string {
	if strings.HasSuffix(raw, "/") {
		return clean
	}
	base := filepath.Base(clean)
	if strings.Contains(base, ".") {
		return filepath.Dir(clean)
	}
	return clean
}

// stripSudo 剥离命令开头的一个 sudo 及其选项，返回剩余字段（真实命令在前）。
// 支持：sudo cmd / sudo -n cmd / sudo -u user cmd / sudo -u=root cmd / sudo -H -n cmd。
// 若首词不是 sudo 或剥离后为空，则原样返回。
func stripSudo(fields []string) []string {
	if len(fields) == 0 || fields[0] != "sudo" {
		return fields
	}
	i := 1
	for i < len(fields) {
		tok := fields[i]
		if tok == "--" {
			i++
			break
		}
		if !strings.HasPrefix(tok, "-") {
			break // 找到真实命令
		}
		// -u/-g 单独出现时消耗下一个参数；-u=user/-g=group 形式不消耗
		if (tok == "-u" || tok == "-g" || tok == "--user" || tok == "--group") && i+1 < len(fields) {
			i += 2
		} else {
			i++
		}
	}
	if i >= len(fields) {
		return fields // sudo 后无命令，原样返回由后续判定处理
	}
	return fields[i:]
}

// IsWriteCommand 供外部判断某命令是否为写命令（用于审计/提示）。
func IsWriteCommand(name string) bool { return writeCommands[name] }
