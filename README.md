# ssh-mcp-go

[![Latest Release](https://img.shields.io/github/v/release/heavymetal0/ssh-mcp-go)](https://github.com/heavymetal0/ssh-mcp-go/releases) [![Go](https://img.shields.io/badge/built%20with-Go-00ADD8)](https://go.dev/)

> **版本记录**：当前版本见上方徽章；完整迭代说明见 [CHANGELOG.md](./CHANGELOG.md) 与 [Releases](https://github.com/heavymetal0/ssh-mcp-go/releases)。版本从 `v0.1.0` 起，遵循语义化版本。

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
| `allow_commands`：允许哪些命令**首词** | 复合命令分段、命令分类、写子命令识别、sudo/env 前缀剥离 |
| `roots`：受保护的根目录 | `..` 穿越拦截、相对路径越权、复合参数拆分、系统目录封锁 |
| `dir_policy`：目录权限模式 | 读/写越界判定、系统目录硬封锁 |
| `read_only`：是否只读 | 禁止一切写/改命令与有写副作用的子命令 |

因此你**不需要**在配置里写任何正则或黑名单。写一个命令名、一个根目录即可。

---

## 2. 程序是如何实现的

### 2.1 进程与通信

- 单个 Go 进程，通过 **stdio** 通信：从 stdin 逐行读 JSON-RPC 2.0，向 stdout 逐行写响应。日志走 stderr，绝不污染协议通道。
- 手写的最小 MCP 服务（`internal/mcp/server.go`），无外部 MCP SDK，支持 `initialize` / `notifications/initialized` / `ping` / `tools/list` / `tools/call`。协议版本 `2024-11-05`。无 `id` 的通知不回响应；坏帧不再静默丢弃，而是回 `id:null` + `-32700 parse error` 并继续服务。
- **入站请求行**上限 16MB（约束超长 `command` 参数等）；stdout 写入用互斥锁串行化，保证消息完整。**命令输出**另由 `defaults.max_output_bytes` 在 SSH 层截断，两者互不相干，因此再大的输出也不会撑爆 stdio 导致进程退出。

### 2.2 模块结构

```
main.go                    启动入口：加载配置、起热重载、装配依赖、启动 MCP
internal/config/           配置加载 / 热重载 / 向导写回 / 默认白名单常量
internal/policy/           全部安全策略判定（命令分段、路径、穿越、系统目录、前缀）
internal/approval/         对话式审批状态机（pending + 拒绝集 + 过期）
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
   ├─ resolveServer()          按 server 名取配置（缺省取第一个，名字写错不会静默回退）
   ├─ policy.ValidateCommand() ① 按 ; && || | 换行拆成子命令，逐段校验
   │                           ② 拒绝 $()/反引号/进程替换/未闭合引号
   │                           ③ 剥离 sudo/env 前缀后首词须在 allow_commands?
   │                           ④ read_only 拦写命令与写子命令
   │                           ⑤ 路径参数按 dir_policy 门禁（穿越/系统目录/越界）
   ├─ 放行 → ssh.Pool.Get()    取/建 SSH 连接（配置指纹变更或死连接自动重建）
   ├─ ssh.RunCommand()         执行，带超时与输出上限截断
   └─ 返回结果文本
   若被拦截 → 可放宽的：生成"最小放宽建议"（加命令名 / 加目录），登记待审批，返回对话式询问
   　　　　　 硬拦截（系统目录/命令替换/只读/穿越）：直接拒绝，不进审批流
```

### 2.4 连接与执行细节

- **连接池**：按服务器名缓存 SSH 连接，复用不重复握手；配置或凭据文件变化、或连接已死时自动重建。
- **建连超时** `connection_timeout`、**心跳** `keepalive_interval`/`keepalive_count_max`（连续底层错误达上限主动断开）均来自配置。
- **主机密钥校验** `host_key_policy`：`insecure`（默认，兼容）或 `known_hosts`（严格校验，防中间人）；填写未知值会直接拒绝连接（fail-closed）。
- **命令超时**优先级：调用参数 `timeout` > `defaults.command_timeout` > 代码兜底 120m。审批放行后的重试保留原 `timeout`。
- **输出截断** `max_output_bytes`：超限截断并标注，避免撑爆 stdio。
- **SFTP 超时** `sftp_timeout`：列目录、上传、下载、目录同步都在超时保护下执行，超时关闭该次 SFTP 会话。
- **转发安全**：本地端口转发强制只监听 `127.0.0.1`；停止时连活动连接一起关闭。
- **配置热重载**：监听配置文件所在**目录**（兼容编辑器 rename 保存），80ms 去抖；解析失败保留旧配置。
- **认证**：支持 `password` 与 `private_key`（可同时给）。

---

## 3. 构建与运行

```bash
cd ssh-mcp-go
go build -o ssh-mcp-go .                   # 编译
./ssh-mcp-go --config ssh-mcp.toml         # 以指定配置启动（默认 ./ssh-mcp.toml）
```

- 配置不存在时**不会崩溃**，而是进入"待配置"状态，提示调用 `setup-wizard`。
- 配置文件保存后**自动热重载**（目录监听 + 80ms 去抖），无需重启。

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
| `sftp_timeout` | 字符串(时长) | `"5m"` | 单次 SFTP 操作（列目录、上传、下载、目录同步）的超时上限；超时即关闭该次 SFTP 会话并返回错误。 |
| `keepalive_interval` | 字符串(时长) | `"15s"` | SSH 心跳间隔。 |
| `keepalive_count_max` | 整数 | `3` | 连续心跳底层错误多少次判定掉线并关闭连接。 |
| `max_output_bytes` | 整数 | `20971520`(20MB) | 命令输出上限字节数，超出截断并标注。`<=0` 不截断。当前仅作用于 `execute-command` / `server-status`。 |
| `transport` | 字符串 | `"exec"` | 传输方式预留字段，当前版本未参与逻辑。 |
| `approval_mode` | 字符串 | `"ask"` | 全局审批模式：`ask`(拦截时对话询问) / `deny`(直接返回 `PermissionDenied`，兼容无审批流的客户端)。可被 server 级覆盖。 |
| `host_key_policy` | 字符串 | `"insecure"` | 主机密钥校验：`insecure`(不校验) / `known_hosts`(严格校验)。**填写未知值会直接拒绝连接**，不会静默降级为不校验。 |
| `known_hosts_file` | 字符串 | `"~/.ssh/known_hosts"` | `known_hosts` 文件路径，支持 `~` 展开。`host_key_policy=known_hosts` 时生效。 |

> 时长字段格式非法或为空时，自动回退到上表默认值。

### 4.2 `[[server]]` 服务器段（可多个）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `name` | 字符串 | ✅ | 服务器名，工具用 `server` 参数引用；不传 `server` 时默认用第一个，名字写错会明确报错而不会打到别的主机。 |
| `host` | 字符串 | ✅ | 主机 IP 或域名。 |
| `port` | 整数 | 否 | SSH 端口，默认 `22`。 |
| `username` | 字符串 | ✅ | 登录用户名。 |
| `password` | 字符串 | 二选一 | 登录密码。 |
| `private_key` | 字符串 | 二选一 | 私钥文件路径（如 `~/.ssh/id_ed25519`），支持 `~`。与 `password` 可同时配置。 |
| `allow_commands` | 字符串数组 | 否 | 允许的命令**首词**列表。**省略即用程序内置的 100 个安全常用命令**；写了则整体替换默认值。无需正则、无需写子命令（见 6.3）。 |
| `roots` | 字符串数组 | ✅ | 受保护根目录。命令里的路径参数与所有 SFTP 操作默认必须落在这些目录内。建议带尾斜杠，如 `"/volume/docker/"`。 |
| `dir_policy` | 字符串 | 否 | 目录权限模式：`off` / `strict` / `read_beyond`。默认（空值按最严格）`strict`；**推荐 `read_beyond`**。详见 4.3。 |
| `read_only` | 布尔 | 否 | `true` 禁止一切写/改命令与有写副作用的子命令，默认 `false`。 |
| `approval_mode` | 字符串 | 否 | 覆盖全局审批模式；空则继承 `[defaults]`。 |

### 4.3 `dir_policy` 三种模式（关键）

| 模式 | 读操作路径 | 写/改操作路径 | 系统目录 |
|---|---|---|---|
| `off` | 不限制 | 不限制 | 不限制 |
| `strict` | 必须在 roots 内 | 必须在 roots 内 | 始终封锁 |
| `read_beyond`（推荐） | 可超越 roots | 必须在 roots 内 | 始终封锁 |

- **系统目录始终硬封锁**：`/etc` `/root` `/usr` `/bin` `/sbin` `/boot` `/sys` `/lib` `/lib64` `/proc` `/dev` `/var` `/volume1`。只要目录权限启用（`strict`/`read_beyond`），任何模式都不能通过审批放宽对这些目录的访问。
- **写/改命令**由程序内建集合识别（cp/mv/rm/mkdir/rsync/rclone/bash/sh/python3/pip/ssh/vi/sed/kill 等），不必在配置里标注；`docker rm/up/down`、`systemctl restart`、`curl -o`、`find -delete` 这类有写副作用的子命令同样被识别。
- **复合参数**（`docker -v /etc:/etc`、`key=value`、`--mount a=b,c=d`）按 `:` `,` `=` 拆分逐片段检查，堵住用冒号绕过系统目录封锁的写法。

### 4.4 完整配置示例

仓库根目录的 `ssh-mcp.example.toml` 是一份带注释的完整模板，可直接复制修改：

```bash
cp ssh-mcp.example.toml ssh-mcp.toml
# 编辑 ssh-mcp.toml：改 host / port / username / 认证凭据 / roots
```

核心骨架（精简版，`allow_commands` 省略即用内置 100 命令）：

```toml
[defaults]
command_timeout     = "120m"
connection_timeout  = "30s"
sftp_timeout        = "5m"
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
> 内置默认白名单的 100 个命令定义在 `internal/config/config.go` 的 `DefaultAllowCommands`，并已完整展开在 `ssh-mcp.example.toml` 中，可按需删减。**省略 `allow_commands` 时程序会自动填充这份默认值；之后若通过审批放行新命令，程序会把完整数组行自动补写进配置文件**，无需手工编辑。

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

最后一步完成后，程序自动写出配置文件（`chmod 600`、原子替换）、重载、启动热重载监听，并提示"现在可以直接使用工具了"。

> 中途出错可传 `reset: true` 重新开始。向导生成的 `allow_commands` 就是内置默认白名单（源自原版 hitelist 的安全常用命令）。

---

## 6. 工具参考

所有工具通过 `tools/call` 调用，`arguments` 为对象。带 `server` 的参数都可省略（省略则用第一个服务器）。

| 工具 | 参数 | 作用 |
|---|---|---|
| `execute-command` | `command`(必填), `server`, `timeout` | 在远程执行命令。复合命令逐段校验白名单与路径；被拦截时进入审批。 |
| `list-servers` | 无 | 列出已配置服务器。 |
| `server-status` | `server` | 采集状态（`uptime`/`df -h`/`free -m`，逐条通过命令白名单）。 |
| `list-remote` | `path`, `server` | SFTP 列目录；`path` 省略用第一个 roots。读操作受策略约束。 |
| `upload` | `local`(必填), `remote`(必填), `server` | 上传本地文件到远程。远程路径按**写**校验，须在 roots 内。 |
| `download` | `remote`(必填), `local`(必填), `server` | 下载远程文件到本地。远程路径按**读**校验。 |
| `dir-sync` | `src`, `dst`, `direction`, `server` | 递归同步目录。`direction=upload`：`src` 本地→`dst` 远程（远程路径按写校验）；`direction=download`：反向（远程路径按读校验）。默认 `upload`。 |
| `port-forward` | `mode`, `local`, `remote`, `server` | 本地端口转发。**本地监听强制绑定 `127.0.0.1`**（传 `0.0.0.0:8080` 也只监听回环）。`mode=start` 需 `local`/`remote`；`stop` 需 `local`；`list` 列出。`local`/`remote` 支持纯端口。`remote` 从 SSH 服务器视角解析。用完务必 `stop`。 |
| `setup-wizard` | `answer`, `reset` | 配置向导，见第 5 节。 |
| `approve_last` | `reason`(可选) | 批准最近一次拦截：自动追加命令名/目录、重载、重试（请求 10 分钟内有效）。 |
| `deny_last` | `reason`(可选) | 拒绝最近一次拦截，不改配置。 |
| `pending_approval` | 无 | 查询当前是否有待审批请求及剩余有效期。 |

### 6.1 调用示例（JSON-RPC）

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

### 6.2 关于复合命令

命令最终整条交给远端 shell，因此程序**按 `;` `&&` `||` `|` 和换行拆成子命令逐段校验**，任何一段不合法整条拒绝。白名单匹配的是每段的**首词**（`sudo` / `env` / `nohup` / `setsid` / `nice` / `command` 等前缀会先剥离）：

- `docker ps` / `docker images` / `docker logs xxx` — `docker` 在白名单即可用
- `docker compose -f /volume/docker/proj/compose.yaml up -d` — 子命令不单独校验，但 `-f` 路径仍须落在 `roots` 内
- `ps aux | grep docker` / `cmd1 && cmd2` — 两段各自都须合法
- `sudo docker ps` / `env FOO=1 docker ps` — 剥离前缀后按真实命令 `docker` 校验

`docker-compose`（旧版独立命令）首词不同，需单独加入白名单。注意 **`docker` 在白名单里不代表所有子命令在 `read_only` 下都放行**：`docker rm/up/down`、`systemctl restart`、`curl -o`、`find -delete` 这类有写副作用的子命令由程序识别并拦截。

以下命令**一律拒绝**（无法静态判定内容，且不可通过审批放宽）：命令替换 `$()`、反引号、进程替换 `<( >(`、未闭合引号。

---

## 7. 对话式审批闭环

当命令/路径被策略拦截，且 `approval_mode=ask`（默认）时：

1. 工具**不报错**，而是返回一段说明：拦截原因、原命令、最小放宽建议（加命令名 / 加目录），并提示 `APPROVE` / `DENY`。
2. 同时登记一条 pending 请求（只保留最近一条，**有效期 10 分钟**，过期自动失效，避免误批早已脱离上下文的旧请求）。
3. Agent 把这段提示展示给用户，询问是否放行。
4. 用户同意 → Agent 调 `approve_last`：
   - 程序追加建议的命令名到 `allow_commands` 或目录到 `roots`（**定点行插入，保留配置注释**；若配置里压根没有该数组行则自动补写）；
   - 原子写盘后热重载配置；
   - **兜底再校验一次**（系统目录封锁等铁律不可被批准绕过），`dir-sync` 上传方向按**写**校验；
   - 自动重试原操作并返回结果，保留原 `timeout`。
5. 用户拒绝 → Agent 调 `deny_last`：清空 pending，不改配置；该请求指纹进入拒绝集，之后相同请求不再反复弹窗。

以下情况**不进入审批流**、直接拒绝（因为批准后也无事可做）：系统目录硬封锁、`read_only` 违规、命令替换/进程替换、路径穿越等没有任何"最小放宽建议"的硬拦截。这样不会弹出一个批准后什么都不发生的无效询问。

`approval_mode=deny` 时所有拦截都直接返回 `PermissionDenied`，用于兼容不支持审批交互的客户端。注意：确认是**聊天文本式**的对话确认，不是 GUI 弹窗。拒绝集按"服务器 + 工具 + 类型 + 详情 + 建议"记指纹，在 A 服务器拒绝过的规则不会压制 B 服务器上的同类请求。

---

## 8. 安全模型

多重防线，全部在程序内实现，不依赖配置里的正则：

1. **复合命令逐段校验**：按 `;` `&&` `||` `|` 换行拆分，每段单独过白名单，堵住 `ls ; rm -rf ...` 借首词夹带。
2. **危险语法硬拒绝**：`$()`、反引号、进程替换 `<( >(`、未闭合引号一律拒绝，不进审批流。
3. **命令首词白名单 + 前缀剥离**：`allow_commands` 精确匹配；`sudo`/`env`/`nohup`/`setsid`/`nice`/`command` 等前缀剥离后用真实命令校验，防止借包装命令绕过。
4. **写命令与写子命令识别**：内建写/改命令集合，以及 `docker rm/up/down`、`systemctl restart`、`curl -o`、`find -delete` 等带写副作用的子命令，均受 `read_only` 与 roots 约束。
5. **路径门禁**：按 `dir_policy` 区分读/写；相对路径越权、`..` 穿越一律拒绝；要求 roots 内的绝对路径。复合参数按 `:` `,` `=` 拆分，逐片段做系统目录检查，堵住冒号绕过。
6. **系统目录硬封锁**：13 个系统目录始终禁止，审批也无法放宽。
7. **最小放宽**：审批只建议追加单个命令名或目录，不整体放开；推断为 `/` 时不自动建议（避免一键放开整个文件系统）。
8. **主机密钥校验**：可选 `known_hosts` 严格校验防中间人；未知策略值 fail-closed 拒绝连接。
9. **审批兜底校验**：放行后重试前再次跑策略，铁律不可绕过；重试保留原 `timeout`，`dir-sync` 上传方向按**写**校验。
10. **转发与进程安全**：端口转发强制仅监听回环；SFTP 全部带超时；输出截断；配置原子写入 + `chmod 600`；退出时清理连接、转发与监听 goroutine。

---

## 9. 给 Agent 的自动配置指引

如果 Agent 读到本 README 并需要**自动完成配置**，按以下决策流程操作：

### 场景 A：没有 `ssh-mcp.toml`

1. 调用 `setup-wizard`，把返回的每个问题依次向用户提问，将答案通过 `answer` 传回，走完 10 步；或
2. 直接询问用户必要的连接信息，手写 TOML 到配置路径（参考 4.4 模板）。关键项：`name`/`host`/`port`/`username`/`password` 或 `private_key`/`roots`。**`allow_commands` 可省略**，程序会用内置 100 命令；`dir_policy` 建议 `read_beyond`。省略 `allow_commands` 后若通过审批放行新命令，程序会自动把数组补写进配置，无需你手工编辑。
3. 配置写好后会热重载生效，随后即可调用工具。建议先调 `list-servers` 确认服务器已就绪。

### 场景 B：命令/路径被拦截

1. 读取工具返回的拦截说明，展示给用户。若说明是"策略硬拦截（不可通过审批放宽）"，说明这是铁律，请直接改命令或路径，**不要**尝试审批。
2. 用户同意 → 调 `approve_last`；拒绝 → 调 `deny_last`。**不要**自行编辑配置绕过。
3. 也可先用 `pending_approval` 确认待审批内容与剩余有效期（10 分钟内有效，过期需重新触发操作）。

### 参数填写要点

- `server` 参数可省略（默认第一个服务器）；多服务器时填 `name`，填错会明确报错。
- 时长参数用 Go 格式：`30s`/`5m`/`2h`。
- `upload`/`download` 的 `local` 路径是 **Agent 所在机器**的本地路径；`remote` 是 SSH 服务器上的路径，须落在 roots 内。
- `dir-sync` 的 `direction` 决定 `src`/`dst` 的本地/远程语义；`upload` 时远程侧按**写**校验，注意越界会被拦。
- `port-forward` 的 `remote` 从 **SSH 服务器视角**解析（例如 NAS 上某服务是 `127.0.0.1:5000`）；本地监听只会绑在 `127.0.0.1`，用完及时 `stop`。
- 复合命令用 `;`/`|`/`&&` 拼接时，每一段的命令都必须在白名单内，路径也要合法。

---

## 10. 已知边界

- **这是意图级门禁，不是完整 shell 解析器，也不是沙箱**：命令名白名单不隔离命令内部行为。一旦 `allow_commands` 含 `bash` / `sh` / `python3` / `ssh` 等解释器或远程执行器，它们照样能运行任意子程序（`-c` 里的字符串不会被二次逐段解析）。生产环境建议从白名单里删掉这些命令。
- **路径校验发生在本地字符串层面**：不做远程 `realpath` 解析，远程符号链接若指向 roots 之外，仍可能被读到/写到。
- **路径词法识别**：含 `/` 或 `..` 的参数才视为路径；`-v /etc:/etc` 这类复合挂载已按 `:` 拆分逐段检查，但更花哨的 shell 变量展开不在支持范围。
- **交互式命令**：`top`/`htop`/`vi`/`less` 等需要 TTY 的命令在非交互 SSH session 中可能无法正常使用或会阻塞。
- **审批只保留最近一条 pending**（MVP 设计）：连续多次拦截以最后一次为准，且 10 分钟后过期；不支持按 ID 批准多条。
- **`transport` 为预留字段**：当前版本未参与逻辑；`sftp_timeout` 已实际生效。
- **`max_output_bytes` 只截断命令输出**：`list-remote` 的目录列表输出尚未纳入统一上限。
- **入站请求行上限 16MB**：单条 JSON-RPC 请求（含超长 command 参数）超过该值会被 scanner 拒绝；常规运维命令远小于此。
- **主机密钥默认不校验**（`insecure`）：如需防中间人，用 `ssh-keyscan` 生成 known_hosts 并把 `host_key_policy` 设为 `known_hosts`。

---

> 项目地址：https://github.com/heavymetal0/ssh-mcp-go
> 协议：MCP stdio（JSON-RPC 2.0，`2024-11-05`）
