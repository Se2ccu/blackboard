# 快速开始：Cairn 漏洞挖掘动态闭环

基于 Cairn 黑板架构，用 claude code worker 对真实运行中的服务做漏洞挖掘与 PoC 验证。本文档覆盖环境搭建、web/命令行运行、查看过程产物。

设计原理见 [`docs/design-summary.md`](design-summary.md)。核心：**图是索引（Fact/Intent 只存结论），盘是正文（trace/反汇编/PoC/崩溃现场落盘）**。

---

## 一、环境要求

| 组件 | 用途 | 安装 |
|------|------|------|
| `uv` ≥ 0.9 | Python 环境与依赖管理 | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| `gcc` | 编译靶机二进制 | `sudo apt install build-essential` |
| `bpftrace` | 内核侧数据流跟踪（需 root） | `sudo apt install bpftrace` |
| `objdump` / `readelf` | 反汇编与符号 | `sudo apt install binutils` |
| `radare2` (`r2`) | 深度逆向 | `sudo apt install radare2` |
| `strace` / `gdb` | 系统调用跟踪、崩溃现场 | `sudo apt install strace gdb` |
| `nc` | 发包 | `sudo apt install netcat-openbsd` |
| `claude` (Claude Code CLI) | worker 执行体 | 见 [Claude Code 安装](https://claude.com/claude-code) |
| Anthropic 兼容网关 | claude CLI 的后端 | 环境变量 `ANTHROPIC_*` |

验证：
```bash
which uv gcc bpftrace objdump r2 strace gdb nc claude
claude --version          # 需要 Claude Code
```

> **root 说明**：bpftrace 的 kprobe/uprobe 需要 root。最小闭环用 `strace` 路径（用户态即可，不需 root）就能跑通 SOURCE 发现与崩溃捕获。需要内核侧跟踪时再 `sudo bpftrace`。

---

## 二、部署（一次性）

仓库根目录：`/home/zt/ai/blackboard`（下文相对该目录）。

### 2.1 编译靶机二进制

```bash
cd /home/zt/ai/blackboard
gcc -O0 -g -Wall -o targets/bpftrace_udp/vuln_udp_server targets/bpftrace_udp/vuln_udp_server.c
```

验证有符号：
```bash
nm targets/bpftrace_udp/vuln_udp_server | grep vulnerable_parse   # 应输出一行 T vulnerable_parse
```

### 2.2 准备 dispatcher 配置（含真实 API 凭据）

`dispatch_local.yaml` 不入库（含 token），从模板创建并注入环境变量：

```bash
cp dispatch_local.example.yaml dispatch_local.yaml
python3 - <<'PY'
import os, re
p = "dispatch_local.yaml"
s = open(p, encoding="utf-8").read()
s = re.sub(r'ANTHROPIC_MODEL:.*',     f'ANTHROPIC_MODEL: {os.environ["ANTHROPIC_MODEL"]!r}',     s)
s = re.sub(r'ANTHROPIC_BASE_URL:.*',  f'ANTHROPIC_BASE_URL: {os.environ["ANTHROPIC_BASE_URL"]!r}', s)
s = re.sub(r'ANTHROPIC_AUTH_TOKEN:.*',f'ANTHROPIC_AUTH_TOKEN: {os.environ["ANTHROPIC_AUTH_TOKEN"]!r}', s)
open(p, "w", encoding="utf-8").write(s)
print("dispatch_local.yaml 已注入 ANTHROPIC_*")
PY
```

> 前提：当前 shell 已有 `ANTHROPIC_MODEL` / `ANTHROPIC_BASE_URL` / `ANTHROPIC_AUTH_TOKEN` 三个环境变量（claude CLI 所用网关）。验证：`echo $ANTHROPIC_BASE_URL`。

校验配置可加载（含 prompt_group 校验、worker env 校验）：
```bash
uv run --project cairn python -c "
from pathlib import Path
from cairn.dispatcher.config import DispatchConfig
cfg = DispatchConfig.load(Path('dispatch_local.yaml'))
print('prompt_group:', cfg.runtime.prompt_group)
print('worker:', cfg.workers[0].name, cfg.workers[0].type)
print('explore.timeout:', cfg.tasks.explore.timeout)
print('OK')
"
```

---

## 三、运行闭环

### 3.1 一键启动（推荐）

完成第二节部署后，直接：

```bash
./start.sh
```

脚本幂等，已起的服务不会重复起：
- 编译靶机（已有跳过）
- 起 cairn serve（已起跳过，一次性服务）
- 起靶机 UDP 服务（已监听 9090 跳过）
- 复用现有 active 的 UDP PoC 项目（没有才建）
- 起 dispatcher（已起跳过，长跑）

全部后台起，脚本立刻退出。结束后按提示看进度：

```bash
./start.sh           # 默认起或复用 UDP PoC 工程
./start.sh --fresh   # 先停所有旧进程再起（DB 不清，项目仍复用）
./stop.sh            # 停所有服务（项目数据保留）
```

跑起来后：
- **web 看图**：`http://127.0.0.1:8000/`
- **实时推理**：`uv run python tools/render_session.py --live`
- **dispatcher 日志**：`tail -f /tmp/cairn-dispatch.log`

### 3.2 手动分终端启动（可选）

想分别控制每个服务时用。需 3 个终端，每个先 `cd /home/zt/ai/blackboard`。

### 终端 A：起 cairn server（中枢 + web）

```bash
uv run --project cairn cairn serve
```

看到 `Uvicorn running on http://127.0.0.1:8000` 即可。**浏览器开 `http://127.0.0.1:8000/` 看 web 界面**（项目列表、Fact/Intent 图）。

> server 是中枢，dispatcher 和 web 都连它。一直开着。

### 终端 B：起靶机（被攻击的真实服务）

```bash
targets/bpftrace_udp/vuln_udp_server 9090
```

看到 `waiting for packets on 0.0.0.0:9090` 即可。保持前台开着，agent 发的包会在这里显示。PoC 触发崩溃后进程会死，agent 会自己重启。

### 终端 C：创建项目 + 跑 dispatcher

先创建项目（一次性，返回 project id）：
```bash
uv run --project cairn python create_target_project.py
```
记下输出的 `项目已创建 id=proj_00X`。

再跑 dispatcher（长跑，真正调 claude 干活）：
```bash
uv run --project cairn cairn dispatch --config dispatch_local.yaml --log-level info
```

### 终端 D（可选）：看进度

把 `proj_00X` 替换成上一步的 id：

```bash
# 看图状态（facts 数量随 agent 推进增长）
curl -s http://127.0.0.1:8000/projects/proj_00X/export | python3 -c "
import sys, yaml
d = yaml.safe_load(sys.stdin)
print('status:', d['project'].get('status'))
print('facts:', len(d['facts']))
for f in d['facts']:
    print(f\"  {f['id']}: {f['description'][:100]}\")
"

# 看 agent 落盘的过程产物
find runs -type f
```

### 完整时序

```
终端A: cairn serve            （一直开）
终端B: ./vuln_udp_server 9090 （一直开）
终端C: create_target_project   （一次性，拿 project id）
终端C: cairn dispatch         （长跑，调 claude 探索）
终端D: curl .../export         （随时查图）
```

---

## 四、查看过程产物

web 界面只显示图节点（Fact/Intent/Hint/Complete 的结论）。agent 的完整推理链、工具调用、原始证据都在 **`runs/` 目录**（设计如此：图是索引，盘是正文）。

### 4.1 推理链总结（最该先看）

```bash
cat runs/bpftrace_udp/notes/SUMMARY_poc.md
```

agent 自写的完整报告，含每个 lens 的结论：SOURCE 在哪、CALLCHAIN 怎么走、SINK 地址+指令+触发条件、POC 选了什么、REACH 怎么复现。

### 4.2 各类原始证据

```bash
cd runs/bpftrace_udp

cat trace/strace_poc002.log          # SOURCE/REACH：strace 抓的真实系统调用序列（recvfrom -> 崩溃信号）
cat crash/gdb_poc002.out             # REACH/POC：gdb 崩溃现场 + backtrace + RIP
cat asm/vulnerable_parse_src001.asm  # SINK：反汇编的漏洞函数（关键指令+地址）
xxd poc/poc_magic_sigsegv_002.bin    # POC：PoC 字节内容
cat notes/server_poc002.log          # 靶机侧 printf 输出
```

### 4.3 claude 推理过程（逐步，可读渲染）

每个 worker 的完整推理轨迹（thinking / tool_use / tool_result）拷在 `runs/<project>/sessions/<session_id>.jsonl`。

**归档 md 自动生成**：worker 进程一结束，dispatcher 自动把它的 jsonl 渲染成同目录的 `<session_id>.md`（人类可读，带标题+来源）。所以归档 session 看 md 即可，不用手动渲染。

```bash
# 看 worker 自动生成的归档 md（最新的一次）
ls runs/proj_005/sessions/*.md
cat runs/proj_005/sessions/3d45f6fe-....md

# 手动重新渲染某个 jsonl（md 被删或想改截断长度时）
uv run python tools/render_session.py --latest --out runs/proj_005/session.md

# 只看执行了哪些命令
uv run python tools/render_session.py --latest --no-color | grep "▶ Bash"

# dispatcher 跑时实时盯当前正在写的 session（--live 手动，追到结束自动退出）
uv run python tools/render_session.py --live
```

输出形如（带颜色、时间戳、截断的长结果）：
```
01:22:04 ▶ Read: /tmp/.../graph.yaml
  ◀ Read result
    1  project:
    2    title: UDP靶场-漏洞挖掘与PoC验证
        ... (6111 chars, truncated)
  thinking
    Now I understand the situation. Let me analyze: ...
01:22:16 ▶ Bash: ls -la .../vuln_udp_server; pgrep -af vuln_udp_server; ...
01:23:02 ▶ Bash: printf 'MAGIC:CRASH' > poc-i004-v1.bin
```

参数：`--result-len N`（tool_result 截断长度，默认 300，0=不截）、`--no-color`（管道/grep 时用）。

### 4.4 目录布局

```
runs/<project>/
├── sessions/    claude 完整推理 jsonl（用 render_session.py 渲染）
├── session-*.log  进程级 I/O（命令、session_id、退出码）
├── trace/      bpftrace/strace 日志（SOURCE/REACH 的动态证据）
├── asm/        objdump/r2 反汇编切片（SINK 的静态证据）
├── poc/        PoC 字节 .bin
├── crash/      coredump、gdb backtrace
└── notes/      agent 自写笔记、SUMMARY
```

### 4.5 复现 PoC

```bash
# 1. 确保靶机在跑（终端 B）
# 2. 发 PoC
cd runs/bpftrace_udp
python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(open('poc/poc_magic_sigsegv_002.bin','rb').read(),('127.0.0.1',9090));s.close()"
# 3. 终端 B 应看到靶机收到包并崩溃（SIGSEGV）
```

---

## 五、web 界面用法

浏览器开 `http://127.0.0.1:8000/`：

- **项目列表**：首页列出所有项目及状态（active/completed）
- **进入项目**：点进去看 Fact/Intent 图
- **图节点**：Fact（已确认结论）、Intent（探索意图）、Hint（策略提示）、Complete（goal 达成）
- **局限**：web 只显示离散结论节点，**中间分析过程看不到**（这是黑板本质）。过程在 `runs/` 落盘（见第四节）。

如果根路径返回 500（旧 serve 进程残留），重启：
```bash
pkill -f "cairn serve"
uv run --project cairn cairn serve
```

---

## 六、参数调优

`dispatch_local.yaml` 关键字段：

| 字段 | 作用 | 默认（vuln）| 调整建议 |
|------|------|------------|---------|
| `runtime.prompt_group` | 提示词组 | `vuln` | 决定 lens 分类、工具指引、落盘约定 |
| `runtime.worker_healthcheck` | 启动健康检查 | `disabled` | local 场景建议 disabled，避免 startup curl 挡住 dispatcher |
| `runtime.max_workers` | 并发 worker | `2` | 调高可并行多 Intent 探索，但更费 API 额度 |
| `tasks.bootstrap.timeout` | bootstrap 超时 | `600` | 真实 RE+发包+bpftrace 远超原 8s，保持 ≥300 |
| `tasks.explore.timeout` | explore 超时 | `600` | 同上 |
| `tasks.explore.conclude_timeout` | conclude fallback 超时 | `120` | bootstrap 超时后走 conclude 写 Fact |
| `tasks.reason.max_intents` | reason 每轮最多提几个 Intent | `2` | 控制探索宽度 |

> server 端 `intent_timeout` / `reason_timeout`（心跳相关）默认 15s，只要 > dispatcher `interval`(3s) 即可，不用动。

---

## 七、常见问题

**Q: dispatcher 日志显示 `skip dispatch because no active projects`**
A: dispatcher 连的 server 上没有 active 项目。检查：① server 是否在跑（终端 A）② 是否已创建项目（终端 C 第一步）③ 配置里 `server:` 指向的端口和 serve 的端口是否一致。

**Q: bootstrap 跑很久（5-8 分钟）才出结果**
A: 当前 vuln 的 bootstrap prompt 让 agent "keep working" 不主动返回，要等 timeout 走 conclude fallback 才写 Fact。这是已知缺陷（见 `docs/design-summary.md` 12.3）。耐心等到日志出现 `intent concluded` 或 `bootstrap completed`。

**Q: dispatcher 日志 `bootstrap command failed code=143`**
A: claude 子进程被 SIGTERM 杀（非超时）。偶发不稳定，dispatcher 会自动重试下一轮。多跑几轮通常能成。

**Q: agent 报端口连不上**
A: 靶机被 PoC 打崩了。回终端 B 重起：`./vuln_udp_server 9090`。或确认 hint 已告诉 agent 自行重启（`create_target_project.py` 的 hint 里有运维约定）。

**Q: web 根路径 500**
A: 旧 serve 残留。`pkill -f "cairn serve"` 后重起。

**Q: 想中断**
A: 终端 C 按 Ctrl+C，dispatcher graceful 释放。残留 claude 子进程清理：`pkill -9 -f "claude --session-id"`。

**Q: 会消耗多少 API 额度**
A: 一轮 bootstrap 实测几百次工具调用、约 5-8 分钟。成本不低，谨慎起 dispatcher。

---

## 八、想看 agent 每一步的推理+工具调用

dispatcher 日志只有调度层（dispatched/concluded），看不到 claude 内部调了哪些 shell、怎么推理的。三种拿法：

1. **看 `runs/.../notes/SUMMARY_poc.md`**：agent 自写总结，过程最完整（推荐先看）。
2. **claude session 回放**：dispatcher 起的 claude 带 `--session-id <uuid>`，每次跑会在 `runs/<project_id>/session-*.log` 留下进程级 I/O 日志，文件头部直接给出 `session_id` 和 `claude -r <id> --resume` 复现命令。看完整推理轨迹用 resume。
3. **session 日志（已实现）**：dispatcher 已自动把每个 worker 子进程的 stdout/stderr 全量 dump 到 `runs/<project_id>/session-<hex8>.log`，含命令、session_id、退出码、是否超时/被杀。对应到图上哪个 Fact 由哪次 session 产出。code=143 / stdout 空这类异常也能从这里看出 claude 被杀前到底输出了什么。

---

## 九、清理

```bash
# 停所有
pkill -f "cairn serve"
pkill -f "cairn dispatch"
pkill -f "vuln_udp_server"
pkill -9 -f "claude --session-id"

# 清产物（可选，会删掉 PoC/trace）
rm -rf runs/

# 清 server 数据库（可选，会删所有项目）
rm -f /home/zt/.local/share/cairn/cairn.db
```

---

## 附：一图速览

```
        ┌─────────────────────────────────────────────┐
        │            cairn serve :8000                │
        │  (FastAPI + SQLite + web UI)                │
        │  存 projects/facts/intents/hints             │
        └──────────┬──────────────────┬───────────────┘
                   │ HTTP              │ HTTP
        ┌──────────▼──────┐  ┌─────────▼──────────┐
        │  dispatcher     │  │  浏览器 / curl      │
        │  (cairn dispatch)│  │  看图（结论）       │
        │  调度 reason/    │  └────────────────────┘
        │  explore/bootstrap│
        └──────┬──────────┘
               │ subprocess: claude --session-id ... -p
        ┌──────▼──────────────────────────────────────┐
        │  claude worker（真实调用）                   │
        │  按 vuln prompt 的 lens 探索：                │
        │  [SOURCE] strace/recvfrom                    │
        │  [CALLCHAIN/SINK] objdump/r2                │
        │  [REACH/POC] 发包+gdb+strace                │
        └──────┬──────────────────────────────────────┘
               │ 落盘
        ┌──────▼──────────┐    ┌─────────────────┐
        │  runs/<proj>/   │    │  靶机            │
        │  trace/asm/poc/  │    │  vuln_udp_server │
        │  crash/notes/    │    │  :9090           │
        │  (过程证据)       │    │  (被攻击目标)    │
        └─────────────────┘    └─────────────────┘
```
