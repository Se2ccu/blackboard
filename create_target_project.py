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
    "title": "UDP靶场-渗透测试与RCE攻击链",
    "origin": (
        f"目标：本地 UDP 服务，二进制路径 {BINARY}（ELF，有符号，无源码），"
        f"监听 127.0.0.1:{PORT}。可用 bpftrace/strace/objdump/radare2/gdb/checksec。"
        "这是一次渗透测试：枚举所有可达攻击链并尽可能推到 RCE，不要停在第一个 PoC。"
        "靶机可能因 PoC 崩溃，需在发包前确保其运行（见 hints 的运维约定）。"
    ),
    "goal": (
        "渗透测试目标：枚举所有可达攻击链，每条尽可能推到 RCE；若 RCE 论证为不可能，"
        "达到 PoC（可复现触发 + 崩溃证据 + RCE 不可行论证）即可关闭该 sink。"
        "PoC 数量越多越好——多个独立 PoC 比单个更有价值。"
        "完成判据（三者全需满足）："
        "(1) 每个已发现的 sink 都有终态结论：[RCE]/[PoC]/[BLOCKED]/[FP]；"
        "(2) 至少一个 sink 被推到 [TRIGGER]+（有 PoC、CONTROL 或 RCE 证据），仅 RECON/SINK 不算；"
        "(3) 存在一条 [CHAIN] 汇总 Fact，列出所有已闭合的攻击链、PoC 数量及价值定级。"
        "不要在单个 [TRIGGER] 即停止，继续发现更多 sink。"
    ),
    "bootstrap_enabled": True,
    "hints": [
        {
            "content": (
                "攻击链 lens 依序推进，每条 Fact description 首行带 lens+价值标签："
                "[RECON] 防护指纹(checksec: canary/NX/PIE/RELRO) -> [AUTH] 认证边界(无认证可达=高价值) -> "
                "[SOURCE] 可控数据入口 -> [CALLCHAIN] 调用链 -> "
                "[SINK:exec|crash] 危险操作(exec 型=RCE相关, crash 型=仅DoS) -> [REACH] 确认字节到达 sink -> "
                "[TRIGGER] 触发漏洞(信号+崩溃点) -> [CONTROL] 控制流劫持(RIP受控/ROP/shellcode) -> "
                "[RCE:unauth|auth] 远程代码执行(需有执行证据如id输出) / "
                "[PoC:unauth|auth] RCE不可行但触发已确认(含payload+崩溃+不可行论证) / "
                "[BLOCKED] 受阻(记原因+绕过条件)。"
                "[CHAIN] 汇总攻击链, [REFINE] 修正偏移, [FP] 误报。"
                "价值排序: [RCE:unauth]>[RCE:auth]>[CONTROL:unauth]>[PoC:unauth]>[PoC:auth]>[BLOCKED]>[FP]。"
                "PoC 数量越多越好，不要停在第一个 TRIGGER，每个 sink 都要走到终态。"
            ),
            "creator": "human",
        },
        {
            "content": (
                "重型产物必须落盘到 " + RUNS_ROOT + "/<project_id>/ 下的子目录"
                "（trace/asm/poc/crash/notes），文件名带 intent_id 以回溯图节点。"
                "description 只放结论行（lens+价值标签 + 地址/偏移/信号/RIP/RCE输出）+ 文件路径引用，"
                "不内联大段日志/反汇编/payload。RCE 的执行证据也要落盘（crash/rce-<intent>.out）。"
            ),
            "creator": "human",
        },
        {
            "content": (
                "二进制有符号，gdb/uprobe 用函数名挂（不用地址），objdump 按函数名切片。"
                "ptrace_scope=1：strace/gdb 只能跟踪自己起的子进程，不能 attach 已有进程——"
                "所以用 strace/gdb --args 把靶机作为子进程启动跟踪，不要 -p attach。"
                "bpftrace 需 root（若需内核侧跟踪用 sudo bpftrace，需配 sudoers）。"
            ),
            "creator": "human",
        },
        {
            "content": (
                "靶机运维：PoC/TRIGGER 会把服务打崩。发包前先确认进程在运行，"
                f"若不在则重启：{BINARY} {PORT} &。"
                "崩溃/控制流捕获建议用 gdb --args 起靶机作为子进程，发包后 gdb 抓 SIGSEGV/SIGABRT + backtrace + RIP。"
                "CONTROL 验证：gdb 确认 RIP 落在受控地址。"
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
