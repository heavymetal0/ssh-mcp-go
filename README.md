# ssh-mcp-go

基于 Go 全量重写的 **SSH MCP 服务**，让 AI Agent 通过标准 MCP 协议安全地控制 SSH / SFTP 主机（典型场景：群晖 NAS、任意 Linux 服务器）。

它是原版 `ssh-mcp` 的**完整替代实现**，不依赖原程序。相比原版最大的增强是**对话式审批（HITL）**：命令或路径被安全策略拦截时，不再直接失败，而是让 Agent 询问用户是否放行；放行后自动写回配置、热重载并重试。

---

## 目录

1. [核心设计](#1-核心设计)
2. [程序是如何实现的](#2-程序是如何实现的)
3. [构建与运行](#3-构建与运行)
4. [配置文件详解](#4-配置文件详解)
5. [自动配置：配置向导](#5-自动配置配置向导)
6. [工具参考](#6-工具参考)
7. [对话式审批闭环](#7-对话式审批闭环)
8. [安全模型](#8-安全模型)
9. [给 Agent 的自动配置指引](#9-给-agent-的自动配置指引)
10. [已知边界](#10-已知边界)

---

## 1. 核心设计

**一句话原则：策略语义写在程序里，配置文件只声明意图。**

原版用一大堆复杂正则（sudo 前缀、全路径 docker、目录锚定、黑白名单）来表达安全规则，难维护也易出错。本重写版把这套逻辑下沉到 Go 程序：

| 配置只声明 | 程序自动负责 |
|---|---|
| `allow_commands`：允许哪些命令**首词** | 命令分类、写命令识别、sudo 前缀剥离 |
| `roots`：受保护的根目录 | `..` 穿越拦截、相对路径越权、符号链接逃逸语义 |
| `dir_policy`：目录权限模式 | 系统目录硬封锁、读/写越界判定 |
| `read_only`：是否只读 | 禁止一切写/改命令 |

因此你**不需要**在配置里写任何正则或黑名单。写一个命令名、一个根目录即可。

---

## 2. 程序是如何实现的

### 2.1 进程与通信

- 单个 Go 进程，通过 **stdio** 通信：从 stdin 逐行读 JSON-RPC 2.0，向 stdout 逐行写响应。日志走 stderr，绝不污染协议通道。
- 手写的最小 MCP 服务（`internal/mcp/server.go`），无外部 MCP SDK，支持 `initialize` / `notifications/initialized` / `ping` / `tools/list` / `tools/call`。协议版本 `2024-11-05`。
- 单条消息上限 64MB（避免大命令输出撑爆行缓冲导致进程退出）；stdout 写入用 channel 串行化，保证消息完整。

### 2.2 模块结构

```
main.go                    启动入口：加载配置、起热重载、装配依赖、启动 MCP
internal/config/           配置加载 / 热重载 / 向导写回 / 默认白名单常量
internal/policy/           全部安全策略判定（命令、路径、穿越、系统目录、sudo）
internal/approval/         对话式审批状态机（pending + 拒绝集）
internal/mcp/server.go     stdio JSON-RPC 服务
internal/mcp/tools.go      12 个工具的定义与实现
internal/ssh/ssh.go        SSH 连接池、命令执行、SFTP、目录递归同步、输出截断
internal/ssh/forward.go    本地端口转发管理器
internal/wizard/wizard.go  10 步对话式配置向导
```

### 2.3 一次命令调用的完整链路

```
Agent tools/call(execute-command, {command:"docker ps"})
   │
   ├─ resolveServer()          按 server 名取配置（缺省取第一个）
   ├─ policy.ValidateCommand() ① 剥离 sudo ② 首词在 allow_commands? ③ read_only 拦写命令?
   │                           ④ 路径参数按 dir_policy 门禁（穿越/系统目录/越界）
   ├─ 放行 → ssh.Pool.Get()    取/建 SSH 连接（建连超时、心跳、主机密钥校验）
   ├─ ssh.RunCommand()         执行，带超时与输出上限截断
   └─ 返回结果文本
   若被拦截 → 生成"最小放宽建议"（加命令名 / 加目录），登记待审批，返回对话式询问
```

### 2.4 连接与执行细节

- **连接池**：按服务器名缓存 SSH 连接，复用不重复握手。
- **建连超时** `connection_timeout`、**心跳** `keepalive_interval`/`keepalive_count_max`（连续失败达上限主动断开）均来自配置。
- **主机密钥校验** `host_key_policy`：`insecure`（默认，兼容）或 `known_hosts`（严格校验，防中间人）。
- **命令超时**优先级：调用参数 `timeout` > `defaults.command_timeout` > 代码兜底 120m。
- **输出截断** `max_output_bytes`：超限截断并标注，避免撑爆 stdio。
- **认证**：支持 `password` 与 `private_key`（可同时给）。

---

## 3. 构建与运行

```bash
cd ssh-mcp-go
go build -o ssh-mcp-go .                   # 编译
./ssh-mcp-go --config ssh-mcp.toml         # 以指定配置启动（默认 ./ssh-mcp.toml）
```

- 配置不存在时**不会崩溃**，而是进入"待配置"状态，提示调用 `setup-wizard`。
- 配置文件保存后约 2 秒**自动热重载**，无需重启。

### 接入 AI Agent（MCP 客户端配置示例）

本程序是 stdio 型 MCP server。在任意支持 MCP 的 Agent 里这样注册（把路径换成实际位置）：

```json
{
  "mcpServers": {
    "ssh": {
      "command": "/绝对路径/ssh-mcp-go",
      "args": ["--config", "/绝对路径/ssh-mcp.toml"]
    }
  }
}
```

---

## 4. 配置文件详解

配置文件是 TOML，分 `[defaults]` 全局段和多个 `[[server]]` 服务器段。下面逐字段说明。

### 4.1 `[defaults]` 全局默认段

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `command_timeout` | 字符串(时长) | `"120m"` | 单条命令执行超时。Agent 可在 `execute-command` 用 `timeout` 参数覆盖（如 `"30s"`）。支持 Go 时长写法：`30s`/`5m`/`2h`。 |
| `connection_timeout` | 字符串(时长) | `"30s"` | SSH 建连超时。 |
| `sftp_timeout` | 字符串(时长) | `"5m"` | SFTP 操作超时预留字段。 |
| `keepalive_interval` | 字符串(时长) | `"15s"` | SSH 心跳间隔。 |
| `keepalive_count_max` | 整数 | `3` | 连续心跳失败多少次判定掉线并关闭连接。 |
| `max_output_bytes` | 整数 | `20971520`(20MB) | 命令输出上限字节数，超出截断并标注。`<=0` 不截断。 |
| `transport` | 字符串 | `"exec"` | 传输方式预留字段。 |
| `approval_mode` | 字符串 | `"ask"` | 全局审批模式：`ask`(拦截时对话询问) / `deny`(直接返回 `PermissionDenied`，兼容无审批流的客户端)。可被 server 级覆盖。 |
| `host_key_policy` | 字符串 | `"insecure"` | 主机密钥校验：`insecure`(不校验) / `known_hosts`(严格校验)。 |
| `known_hosts_file` | 字符串 | `"~/.ssh/known_hosts"` | `known_hosts` 文件路径，支持 `~` 展开。`host_key_policy=known_hosts` 时生效。 |

> 时长字段格式非法或为空时，自动回退到上表默认值。

### 4.2 `[[server]]` 服务器段（可多个）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `name` | 字符串 | ✅ | 服务器名，工具用 `server` 参数引用；不传 `server` 时默认用第一个。 |
| `host` | 字符串 | ✅ | 主机 IP 或域名。 |
| `port` | 整数 | 否 | SSH 端口，默认 `22`。 |
| `username` | 字符串 | ✅ | 登录用户名。 |
| `password` | 字符串 | 二选一 | 登录密码。 |
| `private_key` | 字符串 | 二选一 | 私钥文件路径（如 `~/.ssh/id_ed25519`），支持 `~`。与 `password` 可同时配置。 |
| `allow_commands` | 字符串数组 | 否 | 允许的命令**首词**列表。程序内置 100 个安全常用命令作为默认（见 4.4）；**这里写了则整体替换默认值**。无需正则、无需写子命令。 |
| `roots` | 字符串数组 | ✅ | 受保护根目录。命令里的路径参数与所有 SFTP 操作默认必须落在这些目录内。建议带尾斜杠，如 `"/volume/docker/"`。 |
| `dir_policy` | 字符串 | 否 | 目录权限模式：`off` / `strict` / `read_beyond`。默认（空值按最严格）`strict`；**推荐 `read_beyond`**。详见 4.3。 |
| `read_only` | 布尔 | 否 | `true` 禁止一切写/改命令，默认 `false`。 |
| `approval_mode` | 字符串 | 否 | 覆盖全局审批模式；空则继承 `[defaults]`。 |

### 4.3 `dir_policy` 三种模式（关键）

| 模式 | 读操作路径 | 写/改操作路径 | 系统目录 |
|---|---|---|---|
| `off` | 不限制 | 不限制 | 不限制 |
| `strict` | 必须在 roots 内 | 必须在 roots 内 | 始终封锁 |
| `read_beyond`（推荐） | 可超越 roots | 必须在 roots 内 | 始终封锁 |

- **系统目录始终硬封锁**：`/etc` `/root` `/usr` `/bin` `/sbin` `/boot` `/sys` `/lib` `/lib64` `/proc` `/dev` `/var` `/volume1`。只要目录权限启用（`strict`/`read_beyond`），任何模式都不能通过审批放宽对这些目录的访问。
- **写/改命令**由程序内建集合识别（cp/mv/rm/mkdir/rsync/rclone/bash/sh/python3/pip/ssh/vi/sed/kill 等），不必在配置里标注。

### 4.4 完整配置示例

仓库根目录的 `ssh-mcp.example.toml` 是一份带注释的完整模板，可直接复制修改：

```bash
cp ssh-mcp.example.toml ssh-mcp.toml
# 编辑 ssh-mcp.toml：改 host / port / username / 认证凭据 / roots
```

核心骨架（精简版，`allow_commands` 省略则用内置 100 命令）：

```toml
[defaults]
command_timeout     = "120m"
connection_timeout  = "30s"
keepalive_interval  = "15s"
keepalive_count_max = 3
max_output_bytes    = 20971520
approval_mode       = "ask"
host_key_policy     = "insecure"

[[server]]
name     = "synology-nas"
host     = "192.168.1.10"
port     = 22
username = "your_user"
password = "******"          # 或 private_key = "~/.ssh/id_ed25519"
roots      = ["/volume/docker/"]
dir_policy = "read_beyond"
read_only  = false
```

> ⚠️ `ssh-mcp.toml` 含真实凭据，已在 `.gitignore` 中排除，**不要提交到仓库**。示例里的 `******` 是占位符。
>
> 内置默认白名单的 100 个命令定义在 `internal/config/config.go` 的 `DefaultAllowCommands`，并已完整展开在 `ssh-mcp.example.toml` 中，可按需删减。

---

## 5. 自动配置：配置向导

没有配置文件（或配置里没有任何服务器）时，程序进入待配置状态。Agent 通过 `setup-wizard` 工具**对话式**完成配置，无需手写 TOML。

**流程**：首次调用 `setup-wizard`（可传空 `answer`）开始，之后每一步把答案放进 `answer` 参数传回。10 个步骤依次为：

| 步骤 | 收集内容 | 校验/默认 |
|---|---|---|
| 1 | 服务器名称 | 非空，如 `synology-nas` |
| 2 | 主机地址 | 非空，IP 或域名 |
| 3 | SSH 端口 | 正整数，回车默认 `22` |
| 4 | 登录用户名 | 非空 |
| 5 | 认证方式 | `password` 或 `private_key` |
| 6 | 凭据 | 密码或私钥路径 |
| 7 | 受保护根目录 | 必须绝对路径，如 `/volume/docker/` |
| 8 | 目录权限模式 | `off`/`strict`/`read_beyond`，回车默认 `read_beyond` |
| 9 | 是否只读 | `yes`/`no`，回车默认 `no` |
| 10 | 允许的命令 | 回车用内置 100 命令默认列表，或逗号分隔自定义 |

最后一步完成后，程序自动写出配置文件、重载、启动热重载监听，并提示"现在可以直接使用工具了"。

> 中途出错可传 `reset: true` 重新开始。向导生成的 `allow_commands` 就是内置默认白名单（源自原版 hitelist 的安全常用命令）。

---

## 6. 工具参考

所有工具通过 `tools/call` 调用，`arguments` 为对象。带 `server` 的参数都可省略（省略则用第一个服务器）。

| 工具 | 参数 | 作用 |
|---|---|---|
| `execute-command` | `command`(必填), `server`, `timeout` | 在远程执行命令。首词须在 `allow_commands`，路径须符合 `dir_policy`；被拦截时进入审批。 |
| `list-servers` | 无 | 列出已配置服务器。 |
| `server-status` | `server` | 采集状态（自动执行 `uptime`/`df -h`/`free -m`）。 |
| `list-remote` | `path`, `server` | SFTP 列目录；`path` 省略用第一个 roots。读操作受策略约束。 |
| `upload` | `local`(必填), `remote`(必填), `server` | 上传本地文件到远程。远程路径按**写**校验，须在 roots 内。 |
| `download` | `remote`(必填), `local`(必填), `server` | 下载远程文件到本地。远程路径按**读**校验。 |
| `dir-sync` | `src`, `dst`, `direction`, `server` | 递归同步目录。`direction=upload`：`src` 本地→`dst` 远程（远程路径按写校验）；`direction=download`：反向（远程路径按读校验）。默认 `upload`。 |
| `port-forward` | `mode`, `local`, `remote`, `server` | 本地端口转发。`mode=start` 需 `local`/`remote`；`stop` 需 `local`；`list` 列出。`local`/`remote` 支持纯端口（自动补 `127.0.0.1`）。`remote` 是从 SSH 服务器视角可达的地址。用完务必 `stop`。 |
| `setup-wizard` | `answer`, `reset` | 配置向导，见第 5 节。 |
| `approve_last` | `reason`(可选) | 批准最近一次拦截：自动追加命令名/目录、重载、重试。 |
| `deny_last` | `reason`(可选) | 拒绝最近一次拦截，不改配置。 |
| `pending_approval` | 无 | 查询当前是否有待审批请求。 |

### 调用示例（JSON-RPC）

```jsonc
// 执行命令
{"jsonrpc":"2.0","id":1,"method":"tools/call",
 "params":{"name":"execute-command","arguments":{"command":"docker ps","timeout":"30s"}}}

// 列目录
{"jsonrpc":"2.0","id":2,"method":"tools/call",
 "params":{"name":"list-remote","arguments":{"path":"/volume/docker/"}}}

// 批准被拦截的请求
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"approve_last","arguments":{}}}
```

### 关于复合命令

命令白名单**只匹配首词**。因此只要 `docker` 在 `allow_commands` 里，这些都能用：

- `docker ps` / `docker images` / `docker logs xxx`
- `docker compose -f /volume/docker/proj/compose.yaml up -d`
- `sudo docker ps`（sudo 前缀会被程序剥离，再校验真实命令 `docker`）

`docker-compose`（旧版独立命令）首词不同，需单独加入白名单。

---

## 7. 对话式审批闭环

当命令/路径被策略拦截，且 `approval_mode=ask`（默认）时：

1. 工具**不报错**，而是返回一段说明：拦截原因、原命令、最小放宽建议（加命令名 / 加目录），并提示 `APPROVE` / `DENY`。
2. 同时登记一条 pending 请求（只保留最近一条）。
3. Agent 把这段提示展示给用户，询问是否放行。
4. 用户同意 → Agent 调 `approve_last`：
   - 程序追加建议的命令名到 `allow_commands` 或目录到 `roots`（**定点行插入，保留配置注释**）；
   - 热重载配置；
   - **兜底再校验一次**（系统目录封锁等铁律不可被批准绕过）；
   - 自动重试原命令并返回结果。
5. 用户拒绝 → Agent 调 `deny_last`：清空 pending，不改配置；该请求指纹进入拒绝集，之后相同请求不再反复弹窗。

`approval_mode=deny` 时不走上述流程，直接返回 `PermissionDenied`，用于兼容不支持审批交互的客户端。注意：确认是**聊天文本式**的对话确认，不是 GUI 弹窗。

---

## 8. 安全模型

多重防线，全部在程序内实现，不依赖配置里的正则：

1. **命令首词白名单**：`allow_commands` 精确匹配；`sudo` 前缀被剥离后用真实命令校验，防止借 sudo 绕过。
2. **写命令识别**：内建写/改命令集合受 `read_only` 与 roots 约束。
3. **路径门禁**：按 `dir_policy` 区分读/写；相对路径越权、`..` 穿越一律拒绝；要求 roots 内的绝对路径。
4. **系统目录硬封锁**：13 个系统目录始终禁止，审批也无法放宽。
5. **最小放宽**：审批只建议追加单个命令名或目录，不整体放开；推断为 `/` 时不自动建议（避免一键放开整个文件系统）。
6. **主机密钥校验**：可选 `known_hosts` 严格校验防中间人。
7. **审批兜底校验**：放行后重试前再次跑策略，铁律不可绕过。

---

## 9. 给 Agent 的自动配置指引

如果 Agent 读到本 README 并需要**自动完成配置**，按以下决策流程操作：

### 场景 A：没有 `ssh-mcp.toml`

1. 调用 `setup-wizard`，把返回的每个问题依次向用户提问，将答案通过 `answer` 传回，走完 10 步；或
2. 直接询问用户必要的连接信息，手写 TOML 到配置路径（参考 4.4 模板）。关键项：`name`/`host`/`port`/`username`/`password` 或 `private_key`/`roots`。`allow_commands` 可省略以用内置 100 命令，`dir_policy` 建议 `read_beyond`。
3. 配置写好后会热重载生效，随后即可调用工具。建议先调 `list-servers` 确认服务器已就绪。

### 场景 B：命令/路径被拦截

1. 读取工具返回的拦截说明，展示给用户。
2. 用户同意 → 调 `approve_last`；拒绝 → 调 `deny_last`。**不要**自行编辑配置绕过。
3. 也可先用 `pending_approval` 确认待审批内容。

### 参数填写要点

- `server` 参数可省略（默认第一个服务器）；多服务器时填 `name`。
- 时长参数用 Go 格式：`30s`/`5m`/`2h`。
- `upload`/`download` 的 `local` 路径是 **Agent 所在机器**的本地路径；`remote` 是 SSH 服务器上的路径，须落在 roots 内。
- `dir-sync` 的 `direction` 决定 `src`/`dst` 的本地/远程语义，注意远程侧路径受策略约束。
- `port-forward` 的 `remote` 从 **SSH 服务器视角**解析（例如 NAS 上某服务是 `127.0.0.1:5000`）；用完及时 `stop`。

---

## 10. 已知边界

- **路径参数识别基于字符串**：命令里的路径通过词法判断（含 `/` 或 `..` 的参数视为路径）。像 `docker -v /etc:/etc` 这类用冒号分隔的挂载写法，可能被当作单个路径串而绕过 `isProtected` 的前缀匹配——严格控制 docker 挂载时需留意。
- **交互式命令**：`top`/`htop`/`vi`/`less` 等需要 TTY 的命令在非交互 SSH session 中可能无法正常使用或会阻塞。
- **审批只保留最近一条 pending**（MVP 设计）：连续多次拦截以最后一次为准。
- **`sftp_timeout`/`transport` 为预留字段**：当前版本未实际参与逻辑。
- **主机密钥默认不校验**（`insecure`）：如需防中间人，用 `ssh-keyscan` 生成 known_hosts 并把 `host_key_policy` 设为 `known_hosts`。

---

> 项目地址：https://github.com/heavymetal0/ssh-mcp-go
> 协议：MCP stdio（JSON-RPC 2.0，`2024-11-05`）
