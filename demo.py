#!/usr/bin/env python3
"""黑板报漏洞挖掘机制 demo。

默认用 MockDriver 跑通完整链路（零依赖、无需 API key）：
  python demo.py [repo_path]

配置 LLM_* 环境变量后自动切换到真实模型做分析/汇总：
  LLM_BASE_URL=https://api.openai.com/v1 LLM_API_KEY=sk-... LLM_MODEL=gpt-4o-mini python demo.py path/to/repo
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from blackboard_vuln import Blackboard, Scheduler
from blackboard_vuln.agents.scanner import SCANNER_PROFILES, ScannerAgent
from blackboard_vuln.agents.synthesizer import SynthesizerAgent
from blackboard_vuln.drivers import build_default_driver


def main() -> int:
    repo = sys.argv[1] if len(sys.argv) > 1 else "examples/vuln_app"
    repo = os.path.abspath(repo)
    if not os.path.isdir(repo):
        print(f"目标不是目录: {repo}", file=sys.stderr)
        return 2

    driver = build_default_driver()
    mode = "LLM" if driver.__class__.__name__ == "LLMDriver" else "Mock"
    print(f"== 黑板报漏洞挖掘 ({mode} 模式) == 目标: {repo}\n")

    board = Blackboard()
    board.create_project(
        title="源码漏洞挖掘",
        origin=f"仓库: {repo}",
        goal="产出已核验漏洞列表（含误报标注）",
    )

    scanners = [ScannerAgent(p) for p in SCANNER_PROFILES]
    synthesizer = SynthesizerAgent("synthesizer", driver)
    sched = Scheduler(
        board, scanners, analyzer_driver=driver,
        synthesizer=synthesizer, n_analyzers=4,
        log=lambda m: print(m),
    )
    report = sched.run(repo)

    print("\n== 最终报告 ==")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print("\n== 黑板图快照 (YAML) ==")
    print(board.export_yaml())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
