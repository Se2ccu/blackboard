"""端到端单测 -- 在 examples/vuln_app 上跑完整 scan->analyze->synthesize，断言结论分布。"""

import unittest

from blackboard_vuln import Blackboard, Scheduler
from blackboard_vuln.agents.scanner import SCANNER_PROFILES, ScannerAgent
from blackboard_vuln.agents.synthesizer import SynthesizerAgent
from blackboard_vuln.drivers.mock import MockDriver

EXAMPLES = "examples/vuln_app"


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.board = Blackboard()
        self.board.create_project("t", f"repo:{EXAMPLES}", "verified vuln list")
        self.driver = MockDriver()
        self.synth = SynthesizerAgent("synth", self.driver)

    def test_end_to_end(self):
        sched = Scheduler(
            self.board,
            [ScannerAgent(p) for p in SCANNER_PROFILES],
            analyzer_driver=self.driver,
            synthesizer=self.synth,
            n_analyzers=4,
        )
        report = sched.run(EXAMPLES)

        s = report["summary"]
        # 8 个疑似点：5 确认 / 2 误报 / 1 待复核
        self.assertEqual(s["total"], 8)
        self.assertEqual(s["confirmed"], 5)
        self.assertEqual(s["false_positive"], 2)
        self.assertEqual(s["needs_review"], 1)
        self.assertEqual(self.board.project.status, "completed")

    def test_dedup_reduces_overlap(self):
        """scanner:broad 的规则与 injection/dangerous_api 完全重叠，应被全部合并 -> 0 新声明。"""
        broad = ScannerAgent(SCANNER_PROFILES[3])  # scanner:broad
        # 先让其他 scanner 声明
        for p in SCANNER_PROFILES[:3]:
            ScannerAgent(p).scan(self.board, EXAMPLES)
        before = len(self.board.open_intents())
        broad.scan(self.board, EXAMPLES)
        after = len(self.board.open_intents())
        self.assertEqual(before, after)  # broad 没有新增任何条目


if __name__ == "__main__":
    unittest.main()
