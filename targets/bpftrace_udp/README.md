# bpftrace UDP 靶机

带"异常数据包处理漏洞"的 UDP 服务靶场，配套 bpftrace 内核/用户态跟踪脚本，用于
验证"发包 → 抓 trace → 定位崩溃函数 → 验证 PoC"的闭环。可用 [Cairn](https://github.com/oritera/Cairn)
dispatcher（本仓库已加 local 执行后端）驱动 agent 自动构造 PoC。

## 文件

| 文件 | 说明 |
|------|------|
| `vuln_udp_server.c` | 靶机源码：监听 UDP 9090，含两处漏洞 |
| `udp_receiver.c`    | bpftrace 跟踪用的 UDP 收包程序（用于学习内核收包路径） |
| `udp_recv_trace.bt` | bpftrace 脚本，21 个探针覆盖 UDP 接收路径 |
| `run_trace.sh`      | 一键联合运行 bpftrace + 收包 + nc 发包 |
| `ANALYSIS.md`       | UDP 收包内核函数流动态跟踪分析报告 |

## 漏洞点（`vuln_udp_server.c`）

`vulnerable_parse()` 内两处可触发崩溃：

- `OVERFLOW:<超 64 字节>` — 栈缓冲区越界写 → `abort()`（模拟栈溢出）
- `MAGIC:CRASH` — 空指针解引用 → `SIGSEGV`

崩溃发生在用户态 `vulnerable_parse()` 内部，可被 `strace -e signal` / bpftrace `uprobe` / coredump 捕获。

## 编译与运行

```bash
# 靶机（-O0 -g 保留调试信息，便于符号化到行号）
gcc -O0 -g -Wall -o vuln_udp_server vuln_udp_server.c
./vuln_udp_server                # 监听 0.0.0.0:9090

# 另一终端：正常包 / 触发崩溃
printf "hello"                       | nc -u -w1 127.0.0.1 9090
printf "OVERFLOW:$(python3 -c 'print("A"*300))" | nc -u -w1 127.0.0.1 9090
printf "MAGIC:CRASH"                 | nc -u -w1 127.0.0.1 9090
```

bpftrace 跟踪（需 root）：

```bash
gcc -O2 -Wall -o udp_receiver udp_receiver.c
sudo ./run_trace.sh
```

详见 `ANALYSIS.md`。

## 用 Cairn 驱动 PoC 验证

本仓库已为 Cairn dispatcher 加了 `local` 执行后端（`cairn/src/cairn/dispatcher/runtime/local_runtime.py`），
无需 Docker 即可在本机跑 worker 去打这个靶机：

```bash
# 终端 1：起 Cairn server
uv run --project cairn cairn serve

# 终端 2：建项目（origin/goal/hints 描述靶机与验证目标）
uv run --project cairn python create_target_project.py

# 终端 3：跑 dispatcher（mock worker 演示闭环，配真实 LLM 后端请改 dispatch_local.yaml）
uv run --project cairn cairn dispatch --config dispatch_local.yaml
```

`create_target_project.py` 把靶机描述成 Cairn 项目：origin = 靶机位置，goal = 构造稳定触发
崩溃的 PoC 并基于 trace 定位崩溃函数，hints 指向 `OVERFLOW:`/`MAGIC:` 前缀与
`vulnerable_parse()` 崩溃点。agent 通过 Cairn 的 Fact/Intent 黑板协作探索触发条件。
