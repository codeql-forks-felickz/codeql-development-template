"""Offline tests for gap_overlap.py. Run: python -m unittest test_gap_overlap"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True
import gap_overlap as go  # noqa: E402


def ai(path="a.py", start=10, end=12, cwes=(89,)):
    return {"path": path, "start_line": start, "end_line": end, "cwes": list(cwes)}


def cq(path="a.py", line=11, end=11, cwes=(89,), rule="py/sql-injection", repo="r"):
    return {"path": path, "line": line, "end_line": end, "tags": [f"external/cwe/cwe-{c:03d}" for c in cwes], "rule": rule, "repo": repo, "url": "u"}


class Classify(unittest.TestCase):
    def test_same_cwe_on_overlapping_lines_is_an_exact_duplicate(self):
        self.assertEqual(go.classify(ai(), {**cq(), "cwes": [89]})[0], "exact-duplicate")

    def test_the_same_family_a_few_lines_away_is_a_near_duplicate_and_further_away_a_possible_flow(self):
        self.assertEqual(go.classify(ai(cwes=(89,)), {**cq(line=16, end=16), "cwes": [564]})[0], "near-duplicate")
        self.assertEqual(go.classify(ai(cwes=(89,)), {**cq(line=40, end=40), "cwes": [89]})[0], "possible-same-flow")

    def test_an_unrelated_weakness_at_the_same_lines_is_only_the_same_spot(self):
        self.assertEqual(go.classify(ai(cwes=(89,)), {**cq(), "cwes": [79]})[0], "same-spot-other-cwe")

    def test_another_file_or_a_far_line_does_not_match_and_the_path_is_case_insensitive(self):
        self.assertIsNone(go.classify(ai(), {**cq(path="b.py"), "cwes": [89]}))
        self.assertIsNone(go.classify(ai(), {**cq(line=500, end=500), "cwes": [89]}))
        self.assertEqual(go.classify(ai(path="A.PY"), {**cq(path="a.py"), "cwes": [89]})[0], "exact-duplicate")


class Tags(unittest.TestCase):
    def test_cwe_numbers_come_from_the_tags_and_ignore_other_tags(self):
        self.assertEqual(go.cwes_from_tags(["security", "external/cwe/cwe-079", "external/cwe/cwe-020", "experimental"]), [20, 79])
        self.assertEqual(go.cwe_relation([79], [80]), "family")
        self.assertIsNone(go.cwe_relation([79], [89]))


class Matching(unittest.TestCase):
    def test_the_best_match_per_finding_and_the_count_per_issue(self):
        planned = [{"repo": "r", "alert": 1, "issue": 7, "group": "planned"}, {"repo": "r", "alert": 2, "issue": 7, "group": "planned"},
                   {"repo": "r", "alert": 3, "issue": 8, "group": "planned"}]
        known = {("r", 1): ai(), ("r", 2): ai(path="z.py"), ("r", 3): ai(cwes=(79,))}
        new = [cq(cwes=(89,), rule="far", line=40, end=40), cq(cwes=(89,), rule="near"), cq(cwes=(79,), rule="py/xss", path="a.py")]
        rows = go.match_all(planned, known, new)
        self.assertEqual([r["class"] for r in rows], ["exact-duplicate", None, "exact-duplicate"])
        self.assertEqual(rows[0]["match"]["rule"], "near")
        issues = {str(e["issue"]): (e["findings"], e["covered"]) for e in go.by_issue(rows)}
        self.assertEqual(issues, {"7": (2, 1), "8": (1, 1)})

    def test_a_finding_whose_ai_alert_is_unknown_is_reported_as_not_found(self):
        rows = go.match_all([{"repo": "r", "alert": 9, "issue": 1, "group": "planned"}], {}, [])
        self.assertFalse(rows[0]["found"])


if __name__ == "__main__":
    unittest.main()
