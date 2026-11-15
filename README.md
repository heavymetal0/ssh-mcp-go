# ssh-mcp-go

基于 Go 全量重写的 SSH MCP 服务，供 AI Agent 通过 MCP 协议安全地控制 SSH / SFTP（如群晖 NAS）。

## 设计原则

把复杂的安全策略判定（命令分类、路径门禁、`..` 穿越拦截、系统目录封锁）全部下沉到 Go 程序里，配置文件只声明"意图"——允许哪些命令、受保护的根目录、目录权限模式。

## 核心特性

- **命令白名单**：只匹配命令首词，`docker ps`、`docker compose up` 等子命令随 `docker` 一并放行。
- **目录权限模式**：`off` / `strict`（读写都限制在 roots）/ `read_beyond`（读可越界、写不可越界，推荐）。
- **对话式审批**：命令或路径被拦截时，可交互询问是否放行（`ask`），或直接返回 `PermissionDenied`（`deny`）以兼容不支持审批流的客户端。
- **配置热重载**：保存配置后约 2 秒自动生效，无需重启。
- **配置向导**：无配置文件时自动进入对话式向导生成配置。
- **超时与输出控制**：连接超时、命令超时、心跳、输出截断均可配置。
- **主机密钥校验**：支持 `known_hosts` 严格校验，防中间人攻击。
- **目录同步 / 端口转发**：内置 `dir-sync` 与 `port-forward` 工具。

## 构建与运行

```bash
go build -o ssh-mcp-go .
./ssh-mcp-go --config ssh-mcp.toml
```

配置示例见 [`ssh-mcp.example.toml`](ssh-mcp.example.toml)。

## 工具列表

`execute-command`、`list-remote`、`upload`、`download`、`dir-sync`、`port-forward`、
`approve_last`、`deny_last`、`pending_approval`、`setup-wizard` 等。

> 注意：请勿将含真实服务器地址或凭据的 `ssh-mcp.toml` 提交到仓库；项目已通过 `.gitignore` 排除该文件。
