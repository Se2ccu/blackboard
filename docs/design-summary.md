# 漏洞挖掘与漏洞验证：基于 Cairn 黑板架构的设计总结

本仓库围绕 [Cairn](https://github.com/oritera/Cairn) 的黑板架构落地漏洞工作。当前方向已收敛为**单一动态验证循环**：

> 假设只有真实运行环境 + 二进制（**有符号**，无源码），在逆向过程中即时挖掘漏洞，bpftrace 做数据流跟踪定位 SOURCE 入口，objdump / radare2 按需逆向定位 SINK，发包验证可达性与可触发性，自动生成 PoC 并用 bpftrace 动态跟踪修正 PoC。

早期设计里"静态源码级挖掘（`blackboard_vuln` 模块）"与"动态 PoC 级验证"是两条互补线。实践后发现：当一个 Cairn explore worker 本身就是一个能跑 shell 的 coding agent 时，"分析某个 sink"和"发包 + bpftrace 跟踪 + 看崩溃"是**同一个原语（一次 explore 任务）**，不是两个阶段。因此 `blackboard_vuln` 作为独立模块废弃，其三个好设计作为**约定**吸收进 Cairn 图。本文记录融合后的完整设计。

---

## 一、Cairn 核心设计思路

### 1.1 三原语

| 原语 | 含义 | 不可变性 |
|------|------|---------|
| **Fact** | 已确认的客观事实，图中的节点 | 只增不改，永久保留 |
| **Intent** | 从一个或多个 Fact 出发的探索意图，图中的边 | 声明后可认领 / 释放，结论后落定 |
| **Hint** | 图外输入，策略提示 | 供读图者参考，不参与因果 |

Fact 不带状态标记；状态变化通过**追加新 Fact** 表达（如 `f003 获得shell` + `f025 shell已断开`），时序即状态。`Intent.from` 允许多个 Fact id（超边语义），完整保留"多事实共同支撑一次探索"的因果关系。

### 1.2 黑板架构 + 信息素协调（Stigmergy）

多个 agent 围绕一块共享黑板工作，各自读取当前状态、贡献新知识，**没有中央调度、没有直接通信**。agent 读图、写 Fact 就是在环境上留下"信息素"，其他 agent 据此决策。这与蚁群的信息素机制同构。

每个 agent 的工作循环（读图 -> 判断 -> 声明意图 -> 执行 -> 产出事实）构成独立的 **OODA 循环**（Observe-Orient-Decide-Act），多个循环通过共享图间接同步。决策速度不受中心调度瓶颈限制。

### 1.3 origin -> goal 的有向搜索

Cairn 不定义角色、不定义工作流。给定 origin（起点）和 goal（终点），它在未知状态空间里搜索路径。每个新 Fact 是一块垫脚石，每个 Intent 是迈向未知的一步。图从 origin 长向 goal。

### 1.4 三类任务（运行时由图状态生成，而非预定义）

| 任务 | 作用 |
|------|------|
| **bootstrap** | 项目起始时直接尝试整体解决（融合后：产出第一个 [SOURCE] Fact 作为起点）|
| **reason** | 读全图判断：goal 是否已满足？若否，提出下一个探索 Intent |
| **explore** | 认领一个 Intent，执行探索，产出一个 Fact |

Intent 有完整的 **claim / heartbeat / release / conclude** 生命周期：未认领 -> 进行中（某 worker 持有）-> 已结论（产出 Fact）。这套生命周期是协调的物理基础。

### 1.5 worker 与 driver

dispatcher 把 task 交给 worker 执行。worker 配置（`task_types` / `max_running` / `priority` / `env`）在 `dispatch_*.yaml` 声明，执行细节由 driver 封装：

- `WorkerDriver` 基类暴露 `build_healthcheck` / `build_execute` / `build_conclude` / `extract_session` / `extract_response_text` / `supports_conclude`。
- **SeedSessionDriver**：worker 自生成 uuid 当 session（claudecode、mock）。
- **RegexSessionDriver**：从输出 regex 抓 session（codex）。
- **裸 WorkerDriver + JSON 事件解析**：自写 sh 包装 + 解析事件流抽 session/响应（pi）。

driver 只负责"怎么把 prompt 喂给某个 coding agent 并拿回 JSON"，与图协议无关。

### 1.6 Cairn 的优点

1. **去中心化协调**：agent 间无直接通信，加 / 减 agent 不影响其他 agent，天然可水平扩展。
2. **最小完备原语**：Fact / Intent / Hint 三个原语覆盖"知识 / 行动 / 外部输入"，无需更多。
3. **完整因果审计**：Intent 保留 `from` / `to`，图同时是知识库和推理路径审计日志。
4. **角色无关**：任务运行时由图状态生成，同一引擎可承载渗透测试、漏洞研究、CTF 等不同域。
5. **目标驱动**：origin / goal 把开放式探索收敛为有界搜索。

---

## 二、方向 pivot：从静态审计到动态融合

### 2.1 为什么废弃 `blackboard_vuln` 独立模块

`blackboard_vuln`（scanner / analyzer / synthesizer 三件套）当初是为**静态源码**设计的：没有运行环境，agent 只能读代码文本、不能动手，所以需要 in-process 黑板 + 线程池做"规则扫描 -> 深度分析 -> 汇总"。

当前设定是"只有真实环境 + 二进制，无源码"，恰是 Cairn 原生动态循环的主场：

- **一次 explore = 一次动手**：`claudecode` driver 直接 `claude --session-id ... --dangerously-skip-permissions -p -- <prompt>`，worker 是一个能跑任意 shell 的 agent。in-process 黑板做不了的事（发包、uprobe、r2、objdump），Cairn worker 天生能做。
- **逆向即挖掘**：逆向产出的 sink 假设直接写成 Fact，立刻被发包 agent 消费，没有"先审计再验证"的两段式。

### 2.2 继承的三个约定

`blackboard_vuln` 丢弃，但其三个设计决策作为图上的**约定**保留：

| blackboard_vuln 的设计 | 融合后的落点 |
|---|---|
| `Fact` 携带结构化 `finding`（verdict / severity / location / evidence）| Fact 仍是 description 文本（Cairn 原生 schema），但约定一个紧凑内联标签 `[SINK@parse_request+0xb4 sev=high]`；重型产物落盘，description 只引用路径 |
| `dedup_key` 去重 | 交给 reason agent：提 Intent 时按"同一 sink / 同一触发假设"合并；Cairn 的 Intent 语义 + 标签约定即可，无需改 schema |
| 误报是一等公民（`false_positive` Fact 带理由）| 原样保留：探针 agent 把"可达但不可触发"或"伪 sink"写成 `[FP]` Fact，留理由，不丢弃 |

---

## 三、融合后的图本体

整条流程建模成一张 origin -> goal 的因果图。节点 = Fact，边 = Intent。每条 Intent 的 description 带 **lens 标签**，标识这次探索的维度：

| lens | 含义 | 典型工具 |
|------|------|---------|
| **SOURCE** | 攻击者可控数据的入口点 | bpftrace kprobe（内核 ingress）+ uprobe（用户态接收点）|
| **CALLCHAIN** | 从 SOURCE 回溯到处理函数的调用链 | objdump / r2（有符号下极轻量）|
| **SINK** | 对可控数据做无界 / 危险操作的位置 | objdump / r2 反汇编切片 |
| **REACH** | 确认攻击者字节确实流到 sink | uprobe 抓 arg、bpftrace 传参链 |
| **POC** | 构造触发崩溃的 PoC | nc / 自写 sender + 抓崩溃信号 |
| **REFINE** | 崩溃点不在预期 sink 时修正 PoC | uprobe 抓 memcpy 长度/目标，反算覆盖偏移 |
| **FP** | 判定为误报 / 不可达 / 不可触发 | （结论，不产新 Intent）|

### 3.1 一次完整走通的样例

```
origin  二进制 ./vuln_srv（有符号），监听 UDP 9090，无源码
goal    找到一个可被外部数据包稳定触发的漏洞，并产出可复现 PoC + 崩溃点定位

  f001 [SOURCE] recvfrom 返回的 buffer 是攻击者可控字节
        (bootstrap: 发探针包，uprobe recvfrom 拿到返回长度/内容)
     │  i: "回溯 recvfrom 的调用链，定位把 buffer 送进哪个解析函数"  [CALLCHAIN]
     ▼
  f002 [CALLCHAIN] objdump 显示 recvfrom 调用者 -> parse_request() @0x401180
     │  i: "反汇编 parse_request，找对 buffer 做无界操作的位置"  [SINK]
     ▼
  f003 [SINK@parse_request+0xb4 sev=high] memcpy(stack[64], src, user_len) 无边界检查
     │  i: "uprobe parse_request+0xb4，发正常包，确认 sink 被命中且携带攻击者字节"  [REACH]
     ▼
  f004 [REACH] sink 命中，recvfrom 返回 200 字节直达 memcpy  ← 确认可控+可达
     │  i: "构造超长包触发栈溢出，捕获崩溃 + 定位 RIP"  [POC]
     ▼
  f005 [POC poc-i09-v1.bin] 200B UDP -> SIGSEGV，RIP 落在栈上随机地址
     │  i: "RIP 偏移表明覆盖了返回地址，重算偏移，PoC 定向改写返回地址"  [REFINE]
     ▼
  f006 [POC poc-i09-v2.bin] 精修后 RIP 落在受控地址 -> 控制流劫持确认
  goal complete: from=[f005,f006]  漏洞 + PoC + 定位齐全
```

reason agent 读图时按 `SOURCE -> CALLCHAIN -> SINK -> REACH -> POC -> REFINE` 的依赖顺序判断"下一步缺哪一环"，提对应标签的 Intent。这就是 `blackboard_vuln` 多 lens scanner 思想的演化：从"并行扫源码"变成"reason 根据已有 trace / RE 事实按需提出"。

### 3.2 bpftrace 的两个用法

1. **找 SOURCE 入口**：从内核 ingress（`ip_rcv` / `udp_rcv`，靶机 `udp_recv_trace.bt` 已有 21 探针）追到用户态 `recvfrom` 返回点，再用 **uprobe** 挂到二进制的 `parse_request` / 候选 sink 上，确认攻击者字节确实流到那里。这一步把"数据 SOURCE 入口"从内核侧一直连到用户态 sink —— 纯静态分析做不到。
2. **PoC 修正**：PoC 触发了崩溃但 RIP 不在预期 sink 时，用 uprobe + `arg0/arg1` 抓 memcpy 的长度 / 目标地址，反算实际覆盖偏移，喂给 reason 提 `REFINE` intent。

### 3.3 有符号二进制的简化

待测二进制有符号，让本体在两处变轻：

- **uprobe 挂函数名，不挂地址**：`bpftrace -e 'uprobe:./vuln_srv:parse_request { printf("%s arg1=%d", probe, arg1) }'`。Fact 里写函数名（`parse_request+0xb4`），跨编译版本更稳。
- **CALLCHAIN 阶段几乎不需要落盘**：有符号时 `objdump -d` 的调用链可直接 `grep '<call>'` 一行行提取，结论（`recvfrom -> parse_request -> memcpy`）短到能直接进 description。无符号场景才需要存大段反汇编做交叉引用。

---

## 四、落盘策略

核心矛盾：Fact 只有一段 `description` 文本（Cairn 原生 schema，explore 的合法 payload 只有 `{"description": "..."}`），但每次 explore 产出的东西——bpftrace 日志、反汇编、PoC 字节、coredump——动辄几十 KB 到几 MB，塞进 description 会把 graph snapshot 撑爆，后续每个 worker 读图时都要付这个 token 成本。

### 4.1 核心原则：图是索引，盘是正文

- **Fact = 结论 + 指针**。description 只放"定了什么"（sink 地址、偏移、崩溃信号、RIP）和"证据在哪"（文件路径）。原始证据落盘。
- **local 后端下所有 worker 共享同一台机器的文件系统**（`local_runtime.py` 的 `write_text_file` 直接写宿主机），worker A 写的 trace，worker B 能直接 `cat` 读。这是落盘策略能成立的前提；Docker 后端下每个容器隔离，需靠 volume mount。
- **谁产出谁写盘**：worker 是 coding agent，直接 `mkdir -p` + 重定向即可，不需要 Cairn 引擎代写。

### 4.2 目录布局

```
runs/<project_id>/
├── trace/      # bpftrace 日志（.log）、uprobe 抓取的参数序列
├── asm/        # objdump / r2 反汇编片段（按函数切片，不是整个 binary）
├── poc/        # PoC 字节（.bin，非文本）
├── crash/      # 崩溃日志、coredump、gdb backtrace
└── notes/      # worker 自由笔记（中间推理、待验证假设）
```

`project_id` 在 graph yaml 里就有。**把根目录路径写进一条 Hint**（"图外输入、策略提示"，正是路径约定的归属），这样每个 worker 从图里直接读到根目录，不用拼路径。

### 4.3 命名约定：文件名回溯到图节点

文件名带 `intent_id`，这样任何 worker 读到一个产物文件，能反查它由哪条探索产出，进而读到那条 Intent 的描述和它 `from` 的 Fact：

```
runs/<pid>/trace/recvfrom-<intent_id>.log
runs/<pid>/asm/parse_request-<intent_id>.asm
runs/<pid>/poc/poc-<intent_id>-v2.bin
runs/<pid>/crash/sigsegv-<intent_id>.txt
```

explore 的 prompt 里已注入 `{intent_id}`（见 `prompts/default/explore.md`），worker 能直接用。版本号（`-v2`）用于 PoC 修正：一次 REFINE intent 产出一个新版本文件，不覆盖旧的，保留迭代历史——复刻了"旧结论不删，追加新 Fact"的时序语义。

### 4.4 description 引用格式

约定一个紧凑、可解析的格式：第一行是**结论行（带 lens 标签）**，后续行是**证据路径**。

```
[SINK] memcpy(stack[64], src, user_len) 无边界检查 @ parse_request+0xb4
  reach: confirmed via uprobe arg1=200 user-controlled bytes
  asm:   runs/<pid>/asm/parse_request-i07.asm
  trace: runs/<pid>/trace/uprobe-parse_request-i07.log
```

```
[POC poc-i09-v2.bin] 200B UDP -> SIGSEGV, RIP=0x401234, 覆盖偏移=72
  poc:    runs/<pid>/poc/poc-i09-v2.bin
  crash:  runs/<pid>/crash/sigsegv-i09.txt
  refine: 前版 poc-i09-v1.bin RIP 落在栈上随机地址，本版按偏移 72 定向改写返回地址
```

reason agent 读图时扫一眼结论行就够判断"下一步缺哪一环"；要深挖某条证据时，按路径 `cat` 即可。**结论行进图，证据行也进图但只是路径**——路径本身是廉价文本，不会爆 token。

### 4.5 判据表：什么落盘 vs 什么进 description

| 产物 | 落盘 | 进 description |
|---|---|---|
| bpftrace 完整日志 | ✅ `.log` | 时间窗内命中的探针序列摘要（如 `ip_rcv->udp_rcv->recvfrom ret=200`）|
| objdump / r2 反汇编 | ✅ `.asm`（按函数切片）| 关键几行 + 函数名 + 偏移 |
| PoC 字节 | ✅ `.bin` | 长度、触发信号、关键字段布局 |
| coredump | ✅ `core` | gdb backtrace 摘要 + RIP + 几个关键寄存器 |
| uprobe 抓的参数序列 | ✅ `.log` | 一次命中的 arg0/arg1/arg2 数值 |
| 结论、地址、偏移、判据 | ❌ | ✅ 直接写 |

一条红线：**任何超过 ~20 行或非文本的东西，必须落盘**。description 的体感上限是"一眼能读完"，超了就只留指针。

### 4.6 有符号二进制带来的再简化

落盘的刚需集中在四类：**bpftrace 日志、PoC 字节、coredump、uprobe 参数序列**——都是动态产物，不是静态分析产物。静态部分（符号、调用链）轻到留在图里。这跟"在动态验证过程中做挖掘"的思路正好吻合：静态部分（符号、调用链）轻到留在图里，动态部分（实际跑出来的数据流、崩溃）重，落盘。

---

## 五、worker 模型与提示词

### 5.1 先用通用 worker，不做特化路由

一个调度事实：`scheduler/worker_select.py` + `scheduler/loop.py` 的 `_select_worker` 显示，**worker 选择只按 `task_type` 过滤，不按 intent 种类路由**；调度器永远挑"最新未认领 intent"分配给任意空闲 explore worker。所以"特化 worker"目前**没有路由基础**——除非改 `_select_worker` 让它按 intent 标签匹配 worker。

当前选择：**N 个完全相同的 claudecode 通用 worker**。

- local 后端下所有 worker 跑在同一台机器，bpftrace / objdump / radare2 / nc 对每个 worker 都可见，**唯一的差异是 root**。
- bpftrace 需要 root（`ANALYSIS.md` 里 `unprivileged_bpf_disabled=2`）。两种做法：dispatcher 整体以 root 跑（lab 最简单），或给 worker 配 `sudo bpftrace` 的免密 sudoers（更克制）。通用 worker 直接 `sudo bpftrace ...` 即可，不需要特化。
- "专注点"由 intent 标签 + 提示词带，不由 worker 身份带。零代码改动。

### 5.2 提示词改造

在 `cairn/.../prompts/` 下新增一个 `vuln` prompt_group（或直接改 default），改三处：

1. **reason.md**：加 lens 分类法——读图时按 `SOURCE -> CALLCHAIN -> SINK -> REACH -> POC -> REFINE` 的依赖顺序判断"下一步缺哪一环"，提对应标签的 Intent；goal 满足判据改为"存在 [POC] Fact 且其触发被 trace / 崩溃证实"。
2. **explore.md**：加工具指引——按 intent 标签选工具（`SOURCE/REACH` -> bpftrace+uprobe+kprobe；`CALLCHAIN/SINK` -> objdump/r2；`POC/REFINE` -> 构造包+发包+抓崩溃）；强约束"重型产物落盘、description 只放结论 + 路径"（即第四节约定）。
3. **bootstrap.md**：bootstrap 不再"尝试整体解决"，而是**产出第一个 [SOURCE] Fact**——发探针包、确认 recvfrom 入口，给后续 reason 一个起点。

prompt_group 通过 `dispatch_local.yaml` 的 `runtime.prompt_group: "vuln"` 切换，不动 Cairn 引擎代码。

---

## 六、现实约束（必须先解决，否则跑不起来）

1. **超时**：`dispatch_local.yaml` 里 `explore.timeout: 8` 对真实 RE / 跟踪是灾难性的（一次 r2 分析 + 发包 + 抓 trace 轻松几十秒）。`config.tasks.explore.timeout` 是包住整个 `claude -p` 的硬超时（`tasks/common.py` 用 `timeout -k`）。需要把 `explore.timeout` 提到 300s 量级、`conclude_timeout` 同步上调。注意这跟服务端的 `intent_timeout` / `reason_timeout`（心跳相关）是两回事，后者只要 > interval 即可。
2. **项目产物目录**：PoC 字节、trace 日志、反汇编不能进图（Fact 是文本）。约定 `runs/<project_id>/` 目录（第四节），worker 写文件、Fact 引用路径。local 后端直接写宿主机，worker 能读到。
3. **靶机生命周期**：PoC 会把服务打崩。需要一个 `targetctl restart` 薄包装，prober worker 每次发包前先拉起；或写成一条 Hint 让所有 worker 遵守。
4. **授权范围**：`--dangerously-skip-permissions` + 发包 + r2，这个 harness 只适用于**本地 lab / 自有靶机**。保持现状范围即可，别指向外部目标。

---

## 七、bpftrace 靶机 + Cairn local 后端（基础设施）

### 7.1 靶机设计（`targets/bpftrace_udp/`）

`vuln_udp_server.c` 监听 UDP 9090，`vulnerable_parse()` 内两处可触发崩溃：

- `OVERFLOW:<超 64 字节>` -> 栈缓冲区越界写 -> `abort()`
- `MAGIC:CRASH` -> 空指针解引用 -> `SIGSEGV`

崩溃发生在**用户态 `vulnerable_parse()` 内部**，可被 `strace -e signal` / bpftrace `uprobe` / coredump 捕获。

**融合方向下的调整**：原靶机 hints（`OVERFLOW:` / `MAGIC:` 前缀）是给 worker 透底的，新方向要去掉，让 agent 自己探。另外应提供一个**保留符号但去调试信息的二进制**（`gcc -s` 或保留 `-g` 但后续可考虑 strip 调试段）作为"无源码"靶机；`.c` 只作开发者的 oracle，不暴露给 worker。

### 7.2 bpftrace 跟踪（`udp_recv_trace.bt`）

21 个探针覆盖 UDP 接收完整路径：软中断侧（`ip_rcv` -> `udp_rcv` -> `__udp4_lib_lookup` -> `__udp_enqueue_schedule_skb` -> `sock_def_readable`）+ 用户态侧（`__x64_sys_recvfrom` -> `udp_recvmsg` -> `skb_copy_datagram_iter`）。按 `comm` / `@in_napi` 动态过滤。详见 `targets/bpftrace_udp/ANALYSIS.md`。

这套脚本覆盖的是**内核侧 SOURCE 发现**（第三节用法 1）。用户态 uprobe 跟踪（挂到二进制函数上）需要另写 `.bt`，作为 `tools/` 下的模板。

### 7.3 Cairn `local` 执行后端（`cairn/.../runtime/local_runtime.py`）

Cairn 原生 worker 跑在 Docker 项目容器内。为让 dispatcher 直接在本机跑 worker 去打靶机，新增 `LocalContainerManager`：实现 `ContainerManager` 同一接口面（`ensure_running` / `build_exec_process` / `write_text_file` / `cleanup_*`），但用本地子进程替代容器。配套 `config.py` 加 `container.backend: "docker" | "local"` 字段，`scheduler/loop.py` 按字段分发。

`dispatch_local.yaml` 设 `container.backend: "local"`，无需 Docker 即可演示闭环。这是动态融合循环能跑起来的基石——所有 worker 共享宿主机文件系统，落盘策略（第四节）才成立。

### 7.4 靶机即 Cairn 项目（`create_target_project.py`）

把靶机描述成 Cairn 项目：

- **origin**：二进制路径 + 监听端口 + 无源码（去掉原版透底的 `OVERFLOW:` / `MAGIC:`）
- **goal**：找到一个可被外部数据包稳定触发的漏洞，产出可复现 PoC + 崩溃点定位
- **hints**：`runs/` 根目录路径、lens 标签约定、落盘约定（即第四、五节的策略提示）

agent 通过 Fact / Intent 黑板协作探索触发条件：bootstrap 先产出 SOURCE、reason 读图提新 Intent、explore 认领执行（发包抓 trace / 逆向）、最终 complete。

---

## 八、件改造清单

| 件 | 动作 |
|---|---|
| `blackboard_vuln/` | 废弃（已从 git index 清除）。逻辑价值吸收进第二、三、四节的图本体约定 |
| `cairn/.../runtime/local_runtime.py` | 保留，动态循环的基石 |
| `cairn/.../prompts/` | 新增 `vuln` prompt_group（reason / explore / bootstrap 三件套，带 lens 分类法 + 工具指引 + 落盘约定）|
| `dispatch_local.yaml` | worker 改成 N 个 claudecode（配 `ANTHROPIC_*` env）；`explore.timeout` / `conclude_timeout` 调到 300s；`prompt_group: "vuln"` |
| `create_target_project.py` | 重写 origin / goal / hints（去透底 hints，加 `runs/` 路径与 lens / 落盘约定）|
| `targets/bpftrace_udp/` | 加保留符号的"无源码"二进制；`.c` 只作 oracle |
| 新增 `tools/targetctl` + `tools/uprobe_source.bt` | 靶机启停包装 + SOURCE 发现用的 uprobe 脚本模板 |

---

## 九、worker 适配：opencode（延后）

当前先用 **claude code**。后续切 opencode 时，需要新增 `OpencodeDriver`。调研结论留存如下，避免重复探索：

### 9.1 opencode CLI 现状（v1.15.13，已装 `/home/zt/.opencode/bin/opencode`）

`opencode run [message]` 关键参数：

| 参数 | 作用 |
|---|---|
| `--format json` | raw JSON 事件流（对应 `extract_session` / `extract_response_text`）|
| `-s, --session <id>` | 续接 session（conclude 阶段用）|
| `-c, --continue` | 续接最近 session |
| `-m, --model provider/model` | 指定模型 |
| `--variant high|max|minimal` | reasoning effort |
| `--agent <name>` | 指定 agent |
| `--dir <path>` | 工作目录 |
| `--dangerously-skip-permissions` | 自动批准权限（对应 claude code 同名 flag）|

### 9.2 provider 配置

走 `~/.config/opencode/opencode.json` 的 `provider` 块，`npm: @ai-sdk/openai-compatible` + `options.baseURL`，可接自定义网关（与现有 claudecode / codex 走代理的模式对齐）。本地已配 providers：Google（oauth）、Z.AI、AIHubMix、MiniMax、DeepSeek。

### 9.3 适配风格选择

参考现有三种 driver：claudecode（SeedSession）、codex（RegexSession）、pi（裸 + JSON 事件解析）。opencode 用 `--format json` 事件流，**最接近 pi 的风格**：需要 `extract_session` 从事件流抽 session id、`extract_response_text` 抽 assistant 文本。

**未决项**：`--format json` 的具体事件 type 名（如 `session` / `message` / `assistant` / `tool_call` / `finish`）尚未从源码确认（GitHub raw 404、网络受限、二进制 strings 未直接命中明确 type 字面量）。切 opencode 前需先实跑一次 `opencode run --format json "ping"` 抓事件流样本，再定 `extract_*` 的解析逻辑。

### 9.4 阻塞项

本地 opencode DB 有迁移报错（`Failed to run the query 'ALTER TABLE session ADD cost real DEFAULT 0 NOT NULL'`），`opencode session list` / `opencode debug config` 均受影响。切 opencode 前需先修 DB（清理 / 重建 `~/.local/share/opencode/opencode.db`）。

---

## 十、设计优点总览（更新）

1. **单一动态循环**：挖掘与验证融合为一次 explore 原语，逆向即挖掘，无两段式切换。
2. **统一协作范式**：继承 Fact / Intent / Hint，lens 标签承载多视角，学习成本与心智模型一致。
3. **图是索引，盘是正文**：Fact 只放结论 + 路径，重型产物落盘并按 intent_id 回溯，读图成本恒定。
4. **去中心化、可扩展**：agent 间无直接通信，增减 agent / 更换 driver 不影响整体。
5. **完整审计链**：图同时是结果（PoC + 崩溃定位）和过程（谁发现了什么 sink、谁验证了什么 PoC、为何判误报）。
6. **误报可追溯**：误报作为带理由的 `[FP]` Fact 留存，而非静默丢弃。
7. **角色无关、目标驱动**：origin / goal 把开放探索收敛为有界搜索，同一引擎跨静态 / 动态两域。
8. **渐进可插拔**：mock -> LLM、in-process -> HTTP / Docker、claudecode -> opencode，按需升级，协议层稳定。

---

## 十一、可扩展方向

- **特化 worker 路由**：当通用 worker 在某类 lens 上效率不足时，改 `_select_worker` 让它按 intent 标签匹配 worker（如 `RE/SINK` worker 配 r2、`POC/REFINE` worker 配 fuzzer），仍不动图协议。
- **迭代加深**：reason 发现 `needs_review` 类结论后重新声明 Intent 再分析（Cairn 的 reason 重触发机制天然支持）。
- **trace 写回黑板**：bpftrace 函数流作为 Fact 写回，让 agent 据此推理触发条件（已部分体现在 SOURCE / REACH lens）。
- **黑板 HTTP 化**：in-process 简化套 HTTP（方法已对齐 Cairn 协议），即可跨进程 / 持久化。
- **opencode 切换**：见第九节，待 DB 修复与事件流 schema 确认后落地 `OpencodeDriver`。

---

## 十二、最小可跑通闭环验证记录（2026-07-11 实测）

用 claude code 真实调用跑通了一遍动态闭环。靶机 `targets/bpftrace_udp/vuln_udp_server`（有符号、not stripped），端口 9090，dispatcher `dispatch_local.yaml`（local 后端 + 1 个 claudecode worker + vuln prompt_group + bootstrap/explore timeout 600s）。

### 12.1 实测产物

claude agent 在一次 bootstrap 任务里自主完成了整个 lens 链，产出 Fact `f001`：

```
[POC] 11-byte UDP packet 'MAGIC:CRASH' 触发 SIGSEGV
[SOURCE] recvfrom(fd=3)=11 in main @0x18c7, 然后 vulnerable_parse(buf,11) @0x19f2
[SINK] NULL-deref write at vulnerable_parse+0xd0: 'movb $0x58,(%rax)' rax=0
       reached when len==0xb && memcmp(buf,"MAGIC:CRASH",11)==0
[REACH/POC] strace: recvfrom(...)=11 -> SIGSEGV si_addr=NULL
            gdb backtrace: #0 vulnerable_parse+0xd0 <- #1 main+0x3c2, RIP=0x5555555554f1
            复现两次。
Artifacts: runs/bpftrace_udp/{poc/poc_magic_sigsegv_002.bin,
            trace/strace_poc002.log, crash/gdb_poc002.out,
            asm/vulnerable_parse_src001.asm, asm/main_src001.asm, notes/SUMMARY_poc.md}
```

项目 `proj_003` 最终 `status=completed`（goal 满足：PoC + 崩溃信号 + 崩溃点定位三者齐备）。落盘约定（第四节）被 agent 完全遵守：PoC 字节、strace、gdb、反汇编全落盘，Fact 只放结论 + 路径。

### 12.2 验证通过项

| 环节 | 结果 |
|---|---|
| vuln prompt_group 五件套加载 + 占位符校验 | ✅ |
| dispatch_local.yaml（claudecode worker env 非空、timeout 600s、local 后端）| ✅ |
| cairn serve + create_target_project（4 hints，不透底触发条件）| ✅ |
| claude CLI 子进程按 driver 方式启动 + 真实 API 调用 | ✅ |
| agent 按 lens 序列工作（SOURCE->SINK->REACH->POC）| ✅ |
| 落盘约定（trace/asm/poc/crash/notes 分目录、文件名带 intent 标识）| ✅ |
| 真实发包 + 崩溃捕获（strace SIGSEGV + gdb backtrace）| ✅ |
| Fact 写回图 + goal complete | ✅ |

### 12.3 发现的问题（待修）

1. **bootstrap keep-working 导致延迟与不稳定**：`bootstrap.md` 沿用了 default 的"keep working until goal solved"语义，agent 不主动输出 JSON，要等 `timeout` 杀进程后走 conclude fallback 才写回 Fact。实测 bootstrap 实际跑了 ~451s 才完成。更糟的是前两轮在 254s / 318s 被外部 SIGTERM 杀且 stdout/stderr 全空（非 600s timeout、非 heartbeat），第三轮才成功。**根因待查**：SIGTERM 来源尚未定位（疑似 dispatcher shutdown 路径或 `--once` 边界，但长跑第三轮成功排除了 `--once`）。改进方向：bootstrap prompt 改为"产出第一个 [SOURCE] Fact 后立即返回 JSON"，不要 keep-working，让起点 Fact 快速落定交给后续 reason/explore。

2. **bootstrap 把整条链做完了**：因为 prompt 让它 keep working，agent 一口气把 SOURCE->POC 全做完并直接 complete，绕过了 reason/explore 的多步分工。这与设计里"bootstrap 只产起点、reason 提 Intent、explore 逐步推进"的预期不符。修了问题 1 后，bootstrap 提前返回，分工自然恢复。

3. **runs 目录命名用了 `bpftrace_udp` 而非 project_id**：agent 没严格按 hint 里 `runs/<project_id>/` 建，而是用了靶机名。hint 约定需强化，或在 prompt 里直接给出绝对路径变量。

---

## 十三、运行时进程拓扑：到底几个 agent

### 13.1 三个层面的实体

运行时实际存在三种进程，只有第三种才叫"agent"：

| 实体 | 是什么 | 生命周期 | 数量 |
|------|--------|----------|------|
| **server** | `cairn serve`，SQLite 黑板 + HTTP API | 长驻 | 1 |
| **dispatcher** | `cairn dispatch`，轮询 + fork 任务 | 长驻 | 1 |
| **agent** | 一次 `claude` 子进程 | 一次性，跑完即退 | 取决于配置 |

### 13.2 没有 subagent

`vuln` prompt_group 通篇指示 agent 直接调 shell 工具（checksec / readelf / objdump / r2 / strace / gdb / nc）后返回一个 JSON，**不使用 Claude Code 的 Task / subagent 机制**。所有 `claude` 进程都是 dispatcher 用 subprocess fork 的顶层调用，彼此平级，谁也不是谁的 subagent。agent 之间也不直接通信，只通过黑板（SQLite）间接协作——即第一节的信息素协调。

### 13.3 本配置实际并发 = 1

`dispatch_local.yaml`：1 个 worker（`vuln-researcher`）+ `max_running: 1` + `max_running_projects: 1`。任一时刻最多 1 个 claude 进程在跑，reason 与 explore 串行交替，而非并行。按任务类型数进程：

| 任务 | claude 进程数 | 命令 |
|------|--------------|------|
| reason | 1 | `claude --session-id <uuid> -p -- <prompt>` |
| bootstrap / explore | 2（先后）| execute `claude --session-id <uuid> -p` → conclude `claude -r <uuid> -p` |

### 13.4 进程关系

```
        server (黑板: SQLite)
        ▲ HTTP 读写
        │
        dispatcher (每 3s 轮询: 看图状态 -> 派 reason / explore)
        │ subprocess fork (一次一个)
        ▼
        claude A (reason)  →退出→  claude B (explore execute)  →退出→  claude B' (explore conclude, -r 续 session)
```

explore / bootstrap 的两阶段共用一个 session id：execute 跑完退出，conclude 用 `claude -r <uuid>` resume 其上下文。这是**同一 agent 的两个回合**（读 session 文件，不是活着的父进程），不是父子 agent 关系。reason 单进程单回合，无 conclude。

### 13.5 并发旋钮（4 个 cap）

| 参数 | 含义 | 本配置 |
|------|------|--------|
| `runtime.max_workers` | 全局线程池硬上限 | 2 |
| `runtime.max_running_projects` | 同时几个项目 | 1 |
| `runtime.max_project_workers` | 单项目并发任务数 | 2 |
| `workers[].max_running` | 单 worker 并发数 | 1 |

约束：`max_project_workers <= max_workers`。真正的并行是"同一项目的多个 open intent 被多个 explore 同时消费"，受 `reason.max_intents`（每轮产出 intent 数）与上述 4 个 cap 共同限制。reason 是 per-project 互斥锁（projects 表 `reason_worker` 列），同一项目任一时刻只能 1 个 reason；explore 是 per-intent 认领，可并行。

> 注：本仓库靶机单端口（:9090）下并行 explore 会互相踩——bind 冲突、strace / gdb 争抢同一进程、trace 日志互串。要真正吃下并行需 docker backend（每项目独立容器 + 网络隔离）或多项目并行（各自独立 target 实例）。`dispatch_local.yaml` 的 local 单端口场景，并行收益有限。

---

## 十四、与 agent + subagent 调度范式的对比

### 14.1 核心区别

- **黑板报**：协调逻辑是**代码**（scheduler），agent 是被调度的工人，通过**中心化持久状态**（SQLite 黑板）间接协作。
- **agent + subagent**：协调逻辑是 **LLM 自身**（root agent），subagent 是 root 派生的子单元，通过 **root 的 context** 综合结果。

同样是"多 agent 协作"，谁来当协调者、状态存哪，是分水岭。

### 14.2 维度对比

| 维度 | 黑板报（cairn） | agent + subagent |
|------|----------------|------------------|
| 协调者 | 外部 scheduler 代码 | root agent 自己 |
| 状态载体 | SQLite 黑板（持久化） | root 的 context window |
| agent 关系 | 全部平级，不直接通信 | 父子树，结果回传 root |
| 可见性 | 看不到彼此在跑，但能读沉淀的 fact | subagent 间不可见，只经 root 中转 |
| 任务结构 | 固定 schema（reason / explore / bootstrap） | 自由，root 任意描述子任务 |
| 并行控制 | 代码精确管理（4 个 cap） | root 决定，受平台上限约束 |
| 持久化 / 恢复 | 黑板是 source of truth，crash 可续跑 | context 是 source of truth，root 崩全丢 |
| 可观测性 | 黑板可 SQL 查、web 可视化图 | 依赖 root 转述或平台事件流 |
| context 压力 | 每个 agent 只看快照，不膨胀 | root context 随子任务结果累积膨胀 |
| 容错 | 单 agent 失败只丢一个任务 | subagent 失败 root 重试；root 失败整树崩 |
| 异构 worker | 天然支持（claude / codex / pi / mock 混用） | 较难，通常同模型同驱动 |

### 14.3 黑板报的优缺点

**优点**：可恢复可审计（黑板是数据库，进程死了重启续跑）；协调确定可调试（scheduler 是代码，可单测）；context 不爆（每个 agent 冷启动只看快照）；容错粒度细（一个 explore 失败只丢一个 intent）；异构混用；并行精确可控。

**缺点**：schema 僵硬（加工作模式要改协议 / prompt / 校验）；协调不智能（只按固定规则触发，无多步前瞻规划）；agent 无跨任务累积记忆；无实时协商；前期成本高（要设计状态结构、prompt 模板、调度规则、API 协议）。

### 14.4 subagent 的优缺点

**优点**：灵活、启动快（无需预定义 schema）；root 全局视野；动态重规划；实现成本低（一个 Task 调用即 fan-out）。

**缺点**：context 膨胀；不可恢复（root 崩全丢）；可观测性弱；容错粗（root 单点）；协调不稳定（拆解质量随 root 能力波动）；并行度不可控。

### 14.5 适用场景

| 场景 | 选谁 |
|------|------|
| 长周期（小时~天）、断点续跑、要审计 | 黑板报 |
| 短周期（分钟）、开放式、一次性、快速原型 | subagent |
| 多异构模型协作、精确控并发 | 黑板报 |
| 单模型、灵活拆解、动态重规划 | subagent |

### 14.6 对本仓库选择的解读

漏洞挖掘命中全是黑板报的强项：**长周期**（一次 RCE 链几十轮 reason↔explore，几小时）；**要审计**（每个 fact 留痕，`runs/` 落盘可复盘整条链）；**要断点续跑**（dispatcher 重启读 SQLite 续推）；**异构**（example 配置三家模型混用）；**context 隔离**（每个 explore 只看当前 intent + 图快照，跑几十轮不爆）。

若用 subagent 做同件事：root 要在一个 context 里维护整条 exploit 链的中间产物（strace 日志、反汇编、payload 字节），几十轮必爆；root 崩则整条链归零，没有 `runs/` + 黑板这种"进度已落盘"的安全感。

**一句话**：黑板报用"工程化的确定性"换掉 subagent 的"灵活但不可控"，在长周期、高状态、要审计的场景下划算；subagent 在短平快、开放式场景更轻。本仓库目标（无权限 RCE 闭环）属前者，故选黑板报。

