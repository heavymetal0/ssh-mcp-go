# 变更日志（Changelog）

本文件记录 **ssh-mcp-go** 的所有版本变更。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循[语义化版本 2.0.0](https://semver.org/lang/zh-CN/)。每个版本均对应一个 Git Tag 与一条 GitHub Release，可在 [Releases 页面](https://github.com/heavymetal0/ssh-mcp-go/releases)查看。

变更类型：

- **Added** — 新增功能
- **Changed** — 行为变更
- **Fixed** — 缺陷修复
- **Security** — 安全加固

---

## [v0.3.1] - 2026-11-16

### Security
- 封堵**带引号系统目录路径绕过硬封锁**漏洞（P0）。此前 `strings.Fields` 分词保留 shell 引号，而路径判定链路未剥离引号，`filepath.Clean("'/etc/shadow'")` 不再以 `/etc` 开头，导致 `cat '/etc/shadow'` 及 SFTP path `"/etc/shadow"` 可绕过系统目录硬封锁读取敏感文件。
- 新增 `unquote()` 去掉 token 中的单/双引号（含零散形式如 `/etc'/shadow'`），在 `ValidateSftpPath`、`confinePath` 的 `..` 检查、`withinRoots`、`pathSegments` 中统一调用，确保所有路径判定均在引号剥离后执行。

### Fixed
- 综合回归：正常命令、docker 挂载与命名卷、URL、合法引号路径（如 `grep "err" /volume/docker/log`）全部放行，无回归。

---

## [v0.3.0] - 2026-11-15

本版本为一次大规模审核加固，覆盖安全策略、并发可靠性、审批链路、配置热重载、协议层与 SSH 层。

### Security
- **复合命令逐段校验**：按 `;`、`&&`、`||`、`|`、换行拆段，逐段过白名单，杜绝 `ls ; rm -rf …` 夹带绕过。
- **命令替换硬拒绝**：`$()`、反引号、进程替换 `<( >(`、未闭合引号直接拒绝，且不进入审批流。
- **写子命令识别**：`docker rm/up/down`、`systemctl restart`、`synopkg start`、`curl -o`、`find -delete` 等纳入 `read_only` 约束。
- **复合参数拆分**：按 `: , =` 拆分，封堵 `docker -v /etc:/etc` 冒号绕过系统目录封锁。
- **端口转发强制 loopback**：本地监听固定 `127.0.0.1`，关闭时清理所有活动连接。
- **未知 `host_key_policy` fail-closed**：不再静默降级，直接拒绝连接。

### Changed
- 审批拒绝指纹纳入 `server` / `tool`，避免跨服务器、跨工具误共享拒绝记录。
- 连接池加入参数指纹与 `connAlive()` 探活，配置变更或死连接自动重连；新增 `Pool.Close()`。
- 配置读写与监听锁拆分（`mu` / `writeMu` / `watchMu`），热重载改为监听目录 + 去抖。
- 配置写入改为同目录临时文件 + `chmod 600` + 原子 rename。
- 服务器名找不到时不再静默回退到第一台，改为明确报错并提示核对 `list-servers`。

### Fixed
- `limitedBuffer` 加锁，修复 stdout/stderr 并发写 data race。
- keepalive 仅将 `err != nil` 计为失败，不再误杀约 45 秒后“不支持该扩展”的健康连接。
- 审批：硬拦截不进审批流（无 `AddCommand`/`AddRoot`）；pending 增加 10 分钟 TTL；重试保留原 `timeout`；`dir-sync` 上传方向按写兜底。
- 配置：省略 `allow_commands` 自动填充内置 100 命令默认白名单（此前手写 TOML 省略会导致白名单为空、所有命令被拦）；审批追加命令时自动补写缺失的数组行。
- 协议：JSON 解析失败返回 `-32700 parse error`；`server-status` 的 `uptime`/`df -h`/`free -m` 逐条过白名单，不再绕过。
- SSH：SFTP 操作增加超时；`SyncUploadDir` 逐个关闭 fd 避免耗尽；下载增加远程相对路径 `..` 逃逸防御；`RunCommand` 超时增加 2 秒兜底避免 goroutine 泄漏。
- `insertIntoArray` 修复注释行被补逗号写坏 TOML 的问题。

---

## [v0.2.0] - 2026-11-15

### Added
- 内置 **100 个安全常用命令白名单**（`config.DefaultAllowCommands`），作为配置向导与示例配置的唯一真相源。
- 完整重写 README 为配置手册：从头讲述程序实现、构建运行、配置文件详解、向导、工具参考、审批闭环、安全模型、Agent 自动配置指引与已知边界。

### Changed
- 加固 sudo/前缀剥离与写命令策略，统一白名单维护入口。

---

## [v0.1.1] - 2026-11-15

### Added
- 添加项目 README，介绍用途与基本使用。

---

## [v0.1.0] - 2026-11-15

首个可用版本：以 Go 全量重写 SSH MCP 服务，不再依赖原程序 + 中间件方案。

### Added
- **手写 MCP stdio 服务**（JSON-RPC 2.0）：`initialize`、`ping`、`tools/list`、`tools/call`、`notifications/initialized`，无需外部 MCP SDK。
- **12 个工具**：`execute-command`、`list-servers`、`server-status`、`list-remote`、`upload`、`download`、`dir-sync`、`port-forward`、`setup-wizard`、`approve_last`、`deny_last`、`pending_approval`。
- **简化 TOML 配置**：`[defaults]` 与 `[[server]]`，声明 `allow_commands`、`roots`、`dir_policy`、`read_only`、`approval_mode` 及各超时；复杂策略下沉到 Go 实现。
- **目录权限三模式**：`off`（不检查）、`strict`（读写均不可越界）、`read_beyond`（读可越界、写改不可越界；系统目录始终硬封锁）。
- **交互式审批闭环**：命令/路径不在白名单时默认询问是否添加，可用 `approval_mode = deny` 关闭并直接返回 `PermissionDenied`。
- **配置向导**：无配置文件时自动进入 `setup-wizard` 10 步问答，生成 `chmod 600` 的配置。
- **SSH/SFTP 能力**：连接池、`known_hosts` 主机密钥校验、keepalive、命令超时与输出截断、文件上传下载、目录同步、本地端口转发。
- **安全策略层**：命令首词白名单、目录白名单、目录穿越与系统目录封锁、只读模式。

---

[v0.3.1]: https://github.com/heavymetal0/ssh-mcp-go/releases/tag/v0.3.1
[v0.3.0]: https://github.com/heavymetal0/ssh-mcp-go/releases/tag/v0.3.0
[v0.2.0]: https://github.com/heavymetal0/ssh-mcp-go/releases/tag/v0.2.0
[v0.1.1]: https://github.com/heavymetal0/ssh-mcp-go/releases/tag/v0.1.1
[v0.1.0]: https://github.com/heavymetal0/ssh-mcp-go/releases/tag/v0.1.0
