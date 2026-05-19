# sshmcp

让 AI 编程工具安全地操作你的服务器。SSH 密钥和密码永远不经过 AI，每次操作都需要你通过验证器 App 确认。

## 核心理念

AI 编程工具越来越强大，但让它直接 SSH 到服务器有两个风险：

1. **密钥泄露** — 你得把密钥路径告诉 AI，AI 可以读取密钥内容并上传到云端
2. **失控操作** — AI 可能自行执行危险命令，你来不及阻止

sshmcp 作为中间层隔离了 AI 和服务器：

- AI 永远接触不到 SSH 密钥或密码
- 每次执行命令都需要你的验证器 App（Bitwarden、Google Authenticator 等）生成的 TOTP 验证码
- 验证通过后有超时窗口，期间免重复验证（默认 5 分钟，可自定义）

- 本人能力有限，欢迎大家积极参与，推动本项目的改进。**如您发现了此项目的安全漏洞，麻烦您立即提起issue，并详细描述安全漏洞的内容。**

## 工作原理

```
你说："看下 web 服务器的 docker 状态"
        │
  Claude Code / Codex / OpenCode
        │ 调用 MCP tool: vault_exec("web", "docker ps")
        ▼
  sshmcp MCP Server（本地进程）
        │ 弹出 TOTP 验证提示
        ▼
  你输入 6 位验证码
        │ 验证通过 → 用加密存储的密钥建立 SSH 连接
        ▼
  远程服务器执行命令，返回结果
        │
  AI 拿到输出（看不到密钥、密码、TOTP secret）
```

## 安全保障

| 威胁 | 防护 |
|------|------|
| AI 读取密钥 | 密钥通过 CLI 添加，AI 无法访问 |
| AI 上传密钥到云端 | AI 从头到尾不接触密钥内容 |
| 黑客入侵本机 | 密钥和密码用 Fernet 加密存储，master key 在系统密钥环中 |
| AI 自行执行危险命令 | 每次操作需要 TOTP 验证码 |
| 验证码被暴力破解 | 30 秒刷新 + 时间窗口限制 |

## 安装

需要 Python 3.10+。

```bash
git clone https://github.com/yourname/sshmcp.git
cd sshmcp
uv sync          # 推荐
# 或 pip install -e .
```

Windows 用户额外安装：`uv sync --extra win`

## 使用

### 1. 添加服务器

```bash
# 密钥登录（默认端口 22）
uv run sshmcp add web --host 1.2.3.4 --username root --key-path ~/.ssh/id_rsa

# 密钥登录（自定义端口）
uv run sshmcp add web --host 1.2.3.4 --username root --port 2222 --key-path ~/.ssh/id_rsa

# 密码登录（交互式输入密码，不会出现在命令历史中）
uv run sshmcp add db --host 1.2.3.5 --username root --port 3306
# 然后选择 (p)assword 并输入密码
```

> **注意**：首次连接的服务器需要先手动 SSH 一次，让系统记录 host key：
> ```bash
> ssh username@host -p port
> ```

### 2. 导入 TOTP

```bash
uv run sshmcp totp
```

把输出的 URI 导入你的验证器 App。所有服务器共用一个 TOTP。

### 3. 配置 AI 工具

```bash
uv run sshmcp setup              # 自动配置所有已检测到的工具
uv run sshmcp setup --tool claude  # 只配置某个
```

支持 Claude Code、OpenAI Codex CLI、OpenCode。重启 AI 工具后生效。

### 4. 使用

直接跟 AI 说 "帮我看下 web 上的 docker 状态"，AI 会调用 sshmcp，弹出验证码输入框，你输入后命令执行。

## 命令速查

所有命令前加 `uv run`（如果全局安装了可以省略）。

| 命令 | 说明 |
|------|------|
| `uv run sshmcp add <别名> [--host] [--username] [--port] [--key-path]` | 添加服务器 |
| `uv run sshmcp list` | 列出服务器 |
| `uv run sshmcp remove <别名>` | 删除服务器 |
| `uv run sshmcp totp` | 显示 TOTP URI |
| `uv run sshmcp config [--totp-timeout <分钟>]` | 查看/修改超时时间（默认 5 分钟） |
| `uv run sshmcp setup [--tool claude\|codex\|opencode\|all]` | 配置 AI 工具 |
| `uv run sshmcp run` | 启动 MCP 服务器（通常自动启动） |

## 常见问题

**Q: 支持哪些 AI 工具？**
A: 所有支持 MCP 协议的工具。已内置配置：Claude Code、OpenAI Codex CLI、OpenCode。

**Q: TOTP 验证太频繁？**
A: 验证一次后同一台服务器超时时间内免验证。`uv run sshmcp config --totp-timeout 10` 改成 10 分钟。

**Q: 跨平台吗？**
A: 是。Windows、macOS、Linux 均支持。

**Q: 报错 "Host key not in known_hosts"？**
A: sshmcp 会验证 SSH 主机密钥防止中间人攻击。首次连接需要先手动 SSH 一次：`ssh username@host -p port`，确认后 host key 会记录到 `~/.ssh/known_hosts`。

**Q: TOTP 验证码输错了会怎样？**
A: 允许 5 次失败，之后锁定 5 分钟。成功验证后锁定计数清零。

## 开源协议

MIT

## 鸣谢
[Linux DO社区](https://linux.do/)
