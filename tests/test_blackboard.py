"""黑板语义单测 -- 验证 Fact/Intent/Hint 协议核心行为，对齐 Cairn 语义。

用 stdlib unittest，零依赖：python -m unittest discover
"""

import unittest

from blackboard_vuln import Blackboard
from blackboard_vuln.models import Finding


class TestBlackboard(unittest.TestCase):
    def setUp(self):
        self.b = Blackboard()
        self.b.create_project("t", "origin here", "goal here")

    def test_origin_and_goal_facts(self):
        self.assertIn("origin", self.b.facts)
        self.assertIn("goal", self.b.facts)
        self.assertEqual(self.b.facts["origin"].description, "origin here")

    def test_dedup_merges_duplicate_suspicions(self):
        """两个 scanner 命中同一点 -> 黑板只保留一条。"""
        i1 = self.b.declare_intent(
            from_=["origin"], description="x", creator="scanner-A",
            suspicion={"file": "a", "line": 1}, dedup_key="a:1:eval",
        )
        i2 = self.b.declare_intent(
            from_=["origin"], description="x", creator="scanner-B",
            suspicion={"file": "a", "line": 1}, dedup_key="a:1:eval",
        )
        self.assertIsNotNone(i1)
        self.assertIsNone(i2)  # 合并
        self.assertEqual(len(self.b.open_intents()), 1)

    def test_claim_and_conclude_produces_fact(self):
        """claim -> conclude 原子产出 Fact 并落定 Intent.to。"""
        it = self.b.declare_intent(from_=["origin"], description="x", creator="scanner-A")
        self.assertTrue(self.b.claim_intent(it.id, "analyzer-0"))
        finding = Finding(verdict="confirmed", severity="high", title="t",
                          location="a:1", rule="r", evidence="e", reason="why")
        result = self.b.conclude(it.id, "analyzer-0", "desc", finding=finding)
        self.assertIsNotNone(result)
        fact, intent = result
        self.assertIsNotNone(fact.finding)
        self.assertEqual(intent.to, fact.id)
        self.assertEqual(len(self.b.findings()), 1)

    def test_claim_any_picks_unclaimed(self):
        a = self.b.declare_intent(from_=["origin"], description="a", creator="s")
        self.b.declare_intent(from_=["origin"], description="b", creator="s")
        got = self.b.claim_any("analyzer-0")
        self.assertIsNotNone(got)
        self.assertEqual(got.id, a.id)
        # 第三次无未认领
        self.b.claim_any("analyzer-1")
        self.assertIsNone(self.b.claim_any("analyzer-2"))

    def test_claim_conflict(self):
        it = self.b.declare_intent(from_=["origin"], description="x", creator="s")
        self.assertTrue(self.b.claim_intent(it.id, "analyzer-0"))
        self.assertFalse(self.b.claim_intent(it.id, "analyzer-1"))  # 已被他人持有

    def test_release_returns_to_unclaimed(self):
        it = self.b.declare_intent(from_=["origin"], description="x", creator="s")
        self.b.claim_intent(it.id, "analyzer-0")
        self.assertTrue(self.b.release(it.id, "analyzer-0"))
        self.assertIsNone(self.b.intents[it.id].worker)
        # 现在另一 analyzer 可接手
        self.assertTrue(self.b.claim_intent(it.id, "analyzer-1"))

    def test_complete_sets_completed(self):
        it = self.b.declare_intent(from_=["origin"], description="x", creator="s")
        self.b.claim_intent(it.id, "analyzer-0")
        self.b.conclude(it.id, "analyzer-0", "d",
                        finding=Finding("confirmed", "high", "t", "a:1", "r", "e"))
        edge = self.b.complete(from_=["f001"], description="done", worker="synth",
                               report={"summary": {}})
        self.assertIsNotNone(edge)
        self.assertEqual(self.b.project.status, "completed")
        self.assertEqual(edge.to, "goal")
        self.assertEqual(self.b.project.report, {"summary": {}})

    def test_findings_excludes_origin_goal(self):
        self.assertEqual(self.b.findings(), [])  # origin/goal 无 finding


if __name__ == "__main__":
    unittest.main()
