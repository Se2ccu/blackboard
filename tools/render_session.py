#!/usr/bin/env python3
"""渲染 session jsonl 为人类可读的时间线。支持 claude 和 opencode 两种事件格式。

用法：
    uv run python tools/render_session.py runs/proj_003/sessions/3d45f6fe....jsonl
    uv run python tools/render_session.py runs/proj_003/sessions/3d45f6fe....jsonl --follow
    uv run python tools/render_session.py --live          # 实时看当前正在跑的 session

每一步按顺序展示：thinking（推理）/ tool_use（调用哪个工具+参数）/ tool_result（输出，截断）/
assistant 文本。比原始 jsonl 好读，可 grep。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# ANSI 颜色（输出到终端时用；管道/重定向自动去色见 _supports_color）
C_THINK = "\033[2;37m"   # 暗灰
C_TOOL = "\033[1;36m"    # 青色加粗
C_RESULT = "\033[0;33m"  # 暗黄
C_TEXT = "\033[0m"       # 默认
C_TIME = "\033[2m"       # 暗灰
C_RESET = "\033[0m"


def _supports_color() -> bool:
    return sys.stdout.isatty()


def render_event(event: dict, pending_results: dict, *, result_len: int, color: bool) -> list[str]:
    """把一条 jsonl 事件渲染成若干行。返回行列表。

    支持两种格式：
    - claude: {"type":"user"|"assistant","message":{"content":[{"type":"thinking"|"text"|"tool_use",...}]}}
    - opencode: {"type":"step_start"|"text"|"tool_use"|"step_finish","part":{"type":"step-start"|"text"|"tool"|"step-finish",...}}
    """
    etype = event.get("type", "")
    lines: list[str] = []
    ts = _fmt_ts(event.get("timestamp"))

    # --- opencode format ---
    if "part" in event and isinstance(event["part"], dict):
        return _render_opencode_event(event, ts, pending_results, result_len=result_len, color=color)

    # --- claude format ---
    if etype == "user":
        msg = event.get("message", {})
        content = msg.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "tool_result":
                    tid = item.get("tool_use_id", "")
                    tool_name = pending_results.pop(tid, "?")
                    body = item.get("content", "")
                    if isinstance(body, list):
                        body = "\n".join(
                            x.get("text", "") for x in body if isinstance(x, dict)
                        )
                    body = str(body).strip()
                    prefix = f"  ◀ {tool_name} result"
                    if color:
                        lines.append(f"{C_RESULT}{prefix}{C_RESET}")
                    else:
                        lines.append(prefix)
                    for ln in _truncate(body, result_len).split("\n"):
                        lines.append(f"    {ln}")
        return lines

    if etype != "assistant":
        return lines

    msg = event.get("message", {})
    content = msg.get("content", [])
    if not isinstance(content, list):
        return lines

    for item in content:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind == "thinking":
            body = item.get("thinking", "").strip()
            if not body:
                continue
            if color:
                lines.append(f"{C_THINK}  💭 thinking{C_RESET}")
            else:
                lines.append("  thinking")
            for ln in body.split("\n"):
                lines.append(f"    {ln}" if color else f"    {ln}")
        elif kind == "text":
            body = item.get("text", "").strip()
            if not body:
                continue
            if color:
                lines.append(f"{C_TEXT}💬 assistant{C_RESET}")
            else:
                lines.append("assistant")
            for ln in body.split("\n"):
                lines.append(f"  {ln}")
        elif kind == "tool_use":
            name = item.get("name", "?")
            inp = item.get("input", {})
            tid = item.get("id", "")
            pending_results[tid] = name
            one_liner = _tool_one_liner(name, inp)
            if ts:
                prefix = f"{C_TIME}{ts}{C_RESET} " if color else f"{ts} "
            else:
                prefix = ""
            if color:
                lines.append(f"{prefix}{C_TOOL}▶ {name}{C_RESET}: {one_liner}")
            else:
                lines.append(f"{prefix}▶ {name}: {one_liner}")
    return lines


def _render_opencode_event(event: dict, ts: str, pending_results: dict, *, result_len: int, color: bool) -> list[str]:
    """渲染 opencode JSON 事件流格式。"""
    lines: list[str] = []
    etype = event.get("type", "")
    part = event.get("part", {})
    if not isinstance(part, dict):
        return lines

    ptype = part.get("type", "")

    if etype == "step_start" or ptype == "step-start":
        if color:
            lines.append(f"{C_TIME}--- step start ---{C_RESET}")
        else:
            lines.append("--- step start ---")
        return lines

    if etype == "step_finish" or ptype == "step-finish":
        tokens = part.get("tokens", {})
        total = tokens.get("total", "?")
        if color:
            lines.append(f"{C_TIME}--- step finish (tokens={total}) ---{C_RESET}")
        else:
            lines.append(f"--- step finish (tokens={total}) ---")
        return lines

    if etype == "text" or ptype == "text":
        body = part.get("text", "").strip()
        if not body:
            return lines
        if color:
            lines.append(f"{C_TEXT}💬 assistant{C_RESET}")
        else:
            lines.append("assistant")
        for ln in body.split("\n"):
            lines.append(f"  {ln}")
        return lines

    if etype == "tool_use" or ptype == "tool":
        tool_name = part.get("tool", "?")
        call_id = part.get("callID", "")
        state = part.get("state", {})
        if not isinstance(state, dict):
            state = {}
        status = state.get("status", "")
        inp = state.get("input", {})
        if not isinstance(inp, dict):
            inp = {}
        output = state.get("output", "")

        one_liner = _tool_one_liner(tool_name, inp)
        if ts:
            prefix = f"{C_TIME}{ts}{C_RESET} " if color else f"{ts} "
        else:
            prefix = ""

        if status in ("completed", "success"):
            if color:
                lines.append(f"{prefix}{C_TOOL}▶ {tool_name}{C_RESET}: {one_liner}")
            else:
                lines.append(f"{prefix}▶ {tool_name}: {one_liner}")
            if output:
                body = str(output).strip()
                if color:
                    lines.append(f"  {C_RESULT}◀ {tool_name} result{C_RESET}")
                else:
                    lines.append(f"  ◀ {tool_name} result")
                for ln in _truncate(body, result_len).split("\n"):
                    lines.append(f"    {ln}")
        elif status == "pending":
            if color:
                lines.append(f"{prefix}{C_TOOL}▶ {tool_name} (pending){C_RESET}: {one_liner}")
            else:
                lines.append(f"{prefix}▶ {tool_name} (pending): {one_liner}")
        else:
            if color:
                lines.append(f"{prefix}{C_TOOL}▶ {tool_name} ({status}){C_RESET}: {one_liner}")
            else:
                lines.append(f"{prefix}▶ {tool_name} ({status}): {one_liner}")
        return lines

    return lines


def _tool_one_liner(name: str, inp: dict) -> str:
    """把工具参数压缩成一行可读摘要。"""
    if not isinstance(inp, dict):
        return str(inp)[:120]
    if name == "Bash":
        cmd = str(inp.get("command", "")).replace("\n", " ⏎ ")
        return cmd[:160]
    if name in ("Read", "Write", "Edit"):
        return inp.get("file_path", "")
    if name == "Grep":
        return f"pattern={inp.get('pattern','')} path={inp.get('path','')}"
    if name == "Glob":
        return inp.get("pattern", "")
    # 通用：取前几个键值
    parts = [f"{k}={str(v)[:40]}" for k, v in list(inp.items())[:4]]
    return " ".join(parts)


def _truncate(text: str, limit: int) -> str:
    if limit and len(text) > limit:
        return text[:limit] + f"\n    ... ({len(text)} chars, truncated)"
    return text


def _fmt_ts(ts) -> str:
    if not ts:
        return ""
    s = str(ts)
    # claude: ISO string "2026-07-12T01:23:45.xxxZ" -> 01:23:45
    if "T" in s:
        return s.split("T")[1].split(".")[0].split("Z")[0]
    # opencode: epoch milliseconds (int) -> HH:MM:SS
    try:
        import datetime
        return datetime.datetime.fromtimestamp(int(s) / 1000).strftime("%H:%M:%S")
    except (ValueError, OSError):
        return s


def render_file(path: Path, *, result_len: int, color: bool) -> None:
    pending: dict[str, str] = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            for ln in render_event(event, pending, result_len=result_len, color=color):
                print(ln)


def follow_file(path: Path, *, result_len: int, color: bool, poll: float = 0.5, from_start: bool = True, idle_timeout: float = 60.0) -> None:
    """tail -f 风格：从头读已有事件后持续追新。dispatcher 跑时用。

    from_start=True 先把已有内容全部渲染再 tail（看历史+实时）；
    from_start=False 只看启动后新到的事件。
    idle_timeout 秒没新事件则提示退出（避免对已结束的 session 死等）。"""
    # 等文件出现（claude 启动后约 1-2s 才创建 jsonl）
    waited = 0.0
    while not path.is_file():
        if waited > 30:
            print(f"\n[gave up waiting for {path}]", file=sys.stderr)
            return
        time.sleep(poll)
        waited += poll
        continue
    pending: dict[str, str] = {}
    with path.open(encoding="utf-8") as f:
        if not from_start:
            f.seek(0, 2)
        idle = 0.0
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll)
                idle += poll
                if idle >= idle_timeout:
                    print(f"\n[no new events for {idle_timeout:.0f}s, session likely ended]", file=sys.stderr)
                    return
                continue
            idle = 0.0
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            for ln in render_event(event, pending, result_len=result_len, color=color):
                print(ln, flush=True)


def find_latest_archived() -> Path | None:
    """runs/<project>/sessions/ 下 mtime 最新的 jsonl（归档拷贝，进程结束后才有）。"""
    import subprocess
    try:
        out = subprocess.check_output(
            ["find", "runs", "-path", "*/sessions/*.jsonl"], text=True
        ).strip().splitlines()
    except Exception:
        return None
    files = [Path(p) for p in out if p]
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def find_latest_live() -> Path | None:
    """Find the newest live session file being written now.

    Checks two locations:
    - opencode: runs/*/sessions/live.jsonl (written in realtime by LocalManagedProcess)
    - claude: ~/.claude/projects/<cwd-dashes>/*.jsonl (written by claude during execution)
    """
    import os
    import subprocess
    # opencode live file (runs/<project>/sessions/live.jsonl)
    try:
        out = subprocess.check_output(
            ["find", "runs", "-name", "live.jsonl", "-path", "*/sessions/*"], text=True
        ).strip().splitlines()
        files = [Path(p) for p in out if p]
        if files:
            return max(files, key=lambda p: p.stat().st_mtime)
    except Exception:
        pass

    # claude live file
    cwd = os.getcwd()
    project_dir = Path("~/.claude/projects/" + cwd.replace("/", "-")).expanduser()
    if project_dir.is_dir():
        files = sorted(project_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
        if files:
            return files[0]
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="render claude session jsonl to readable timeline")
    ap.add_argument("file", type=Path, nargs="?", help="path to <session-id>.jsonl (omit with --latest/--live)")
    ap.add_argument("--follow", "-f", action="store_true", help="tail new events as they arrive")
    ap.add_argument("--latest", action="store_true", help="use newest jsonl under runs/*/sessions/ (archived)")
    ap.add_argument("--live", action="store_true", help="use newest jsonl claude is writing now (realtime)")
    ap.add_argument("--out", "-o", type=Path, help="write rendered output to this markdown file (auto --no-color)")
    ap.add_argument("--result-len", type=int, default=300, help="truncate tool_result to N chars (0=no limit)")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = ap.parse_args()

    if args.latest and args.live:
        print("--latest and --live are mutually exclusive", file=sys.stderr)
        return 2

    # --latest points at an archived copy (written after the worker process ended);
    # the file is immutable, so --follow would just idle until the timeout.
    if args.latest and args.follow:
        print("[--latest targets an archived (immutable) file; --follow ignored]", file=sys.stderr)
        args.follow = False

    # --live always follows: the whole point of --live is to watch the current
    # session in realtime until it ends. --follow is implicit, not a separate mode.
    if args.live:
        args.follow = True

    path = args.file
    if args.latest:
        path = find_latest_archived()
        if path is None:
            print("no archived session found under runs/*/sessions/", file=sys.stderr)
            return 1
    elif args.live:
        path = find_latest_live()
        if path is None:
            print("no live session found (checked runs/*/sessions/live.jsonl and ~/.claude/projects/)", file=sys.stderr)
            return 1
    elif path is None:
        ap.error("need a file path, or use --latest / --live")
        return 2

    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 1

    # --out: render to a markdown file. Auto-disable color (ANSI in .md is noise),
    # and prepend a title + source provenance so the file is self-describing.
    if args.out is not None:
        args.no_color = True
        out = args.out
        out.parent.mkdir(parents=True, exist_ok=True)
        out_f = out.open("w", encoding="utf-8")
        title = f"# claude session trace\n\nsource: `{path}`\n\n---\n"
        out_f.write(title)
        real_stdout = sys.stdout
        sys.stdout = out_f
        try:
            color = False
            if args.follow:
                follow_file(path, result_len=args.result_len, color=color)
            else:
                render_file(path, result_len=args.result_len, color=color)
        finally:
            sys.stdout = real_stdout
            out_f.close()
        print(f"wrote {out}", file=sys.stderr)
        return 0

    print(f"# {path}", file=sys.stderr)
    color = _supports_color() and not args.no_color
    if args.follow:
        follow_file(path, result_len=args.result_len, color=color)
    else:
        render_file(path, result_len=args.result_len, color=color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
