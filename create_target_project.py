#!/usr/bin/env python3
"""创建一个 Cairn 项目，目标是对 UDP 靶场做漏洞挖掘与 PoC 验证。

调用 Cairn Server API 创建项目，origin/goal/hints 描述靶场与验证目标。
不依赖 Docker；只调 HTTP API。

靶场：targets/bpftrace_udp/ 下的有符号二进制（无源码暴露给 agent）。
origin 告诉 agent 二进制路径 + 监听端口；goal 要求可复现 PoC + 崩溃点定位；
hints 给出 lens 分类、落盘约定、靶机运维约定，但不透底触发条件。

用法（前提：cairn serve 已在 127.0.0.1:8000 跑起来）：
    uv run --project cairn python create_target_project.py
"""
import json
import sys
import urllib.request
from pathlib import Path

SERVER = "http://127.0.0.1:8000"

# 产物落盘根目录（worker 在其下按 project_id 建子目录）。绝对路径注入 hint。
RUNS_ROOT = str(Path(__file__).resolve().parent / "runs")

# 靶机二进制（需先编译；见 targets/bpftrace_udp/README.md）。
BINARY = str(Path(__file__).resolve().parent / "targets" / "bpftrace_udp" / "vuln_udp_server")
PORT = 9090

PROJECT = {
    "title": "UDP靶场-漏洞挖掘与PoC验证",
    "origin": (
        f"目标：本地 UDP 服务，二进制路径 {BINARY}（ELF，有符号，无源码），"
        f"监听 127.0.0.1:{PORT}。可用 bpftrace/strace/objdump/radare2。"
        "已知存在异常数据包处理漏洞，但触发条件未知。"
        "靶机可能因 PoC 崩溃，需在发包前确保其运行（见 hints 的运维约定）。"
    ),
    "goal": (
        "找到一个可被外部 UDP 数据包稳定触发的漏洞，产出可复现的 PoC 数据包，"
        "并基于动态 trace / 崩溃捕获定位崩溃函数。完成时需同时具备："
        "可复现 PoC（落盘 .bin）+ 触发到的崩溃信号 + 崩溃点函数定位。"
    ),
    "bootstrap_enabled": True,
    "hints": [
        {
            "content": (
                "探索分 lens 依序推进，每条 Fact 的 description 首行带 lens 标签："
                "[SOURCE] 攻击者可控数据入口 -> [CALLCHAIN] 调用链 -> "
                "[SINK] 对可控数据的无界/危险操作 -> [REACH] 确认字节到达 sink -> "
                "[POC] 触发崩溃的包 -> [REFINE] 修正未命中预期点的 PoC。"
                "误报用 [FP] 标注并留理由。"
            ),
            "creator": "human",
        },
        {
            "content": (
                "重型产物必须落盘到 " + RUNS_ROOT + "/<project_id>/ 下的子目录"
                "（trace/asm/poc/crash/notes），文件名带 intent_id 以回溯图节点。"
                "description 只放结论行（lens 标签 + 地址/偏移/信号/RIP）+ 文件路径引用，"
                "不内联大段日志/反汇编/PoC 字节。"
            ),
            "creator": "human",
        },
        {
            "content": (
                "二进制有符号，uprobe 用函数名挂（不用地址），objdump 按函数名切片。"
                "bpftrace 需 root；可用 sudo bpftrace。"
                "内核侧 ingress 跟踪脚本参考 targets/bpftrace_udp/udp_recv_trace.bt。"
            ),
            "creator": "human",
        },
        {
            "content": (
                "靶机运维：PoC 会把服务打崩。发包前先确认进程在运行，"
                f"若不在则重启：{BINARY} {PORT} &。"
                "崩溃捕获建议在发包进程外用 strace -e signal 跟踪目标 PID，"
                "或开启 coredump。"
            ),
            "creator": "human",
        },
    ],
}


def post(path: str, body: dict) -> dict:
    url = SERVER + path
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    if not Path(BINARY).exists():
        print(f"[!] 靶机二进制不存在: {BINARY}", file=sys.stderr)
        print(f"    先编译: gcc -O0 -g -Wall -o {BINARY} "
              f"targets/bpftrace_udp/vuln_udp_server.c", file=sys.stderr)
        return 1
    try:
        result = post("/projects", PROJECT)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] 创建项目失败: {exc}", file=sys.stderr)
        return 1
    pid = result.get("project", {}).get("id") or result.get("id")
    print(f"[+] 项目已创建 id={pid}")
    print(f"    title={PROJECT['title']}")
    print(f"    binary={BINARY} port={PORT}")
    print(f"    runs_root={RUNS_ROOT}/{pid}/")
    print(f"    hints={len(PROJECT['hints'])} 条")
    print()
    print("现在让 dispatcher 跑起来：")
    print("  uv run --project cairn cairn dispatch --config dispatch_local.yaml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
