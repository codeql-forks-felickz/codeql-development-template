"""Offline tests for verify_alerts.py: the matching rules, with no network."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_alerts as va  # noqa: E402

RULE = "githubsecuritylab/actions/encoded-secret-in-log"


class Rules(unittest.TestCase):
    def test_language_of_a_community_packs_rule(self):
        self.assertEqual(va.rule_language(RULE), "actions")
        self.assertEqual(va.rule_language("githubsecuritylab/js/some-name"), "javascript-typescript")
        self.assertEqual(va.rule_language("githubsecuritylab/cs/some-name"), "csharp")
        self.assertEqual(va.rule_language("githubsecuritylab/audit/py/some-name"), "python")

    def test_other_ids_have_no_language(self):
        self.assertIsNone(va.rule_language("actions/excessive-secrets-exposure"))
        self.assertIsNone(va.rule_language("githubsecuritylab/unknown/name"))
        self.assertIsNone(va.rule_language("githubsecuritylab"))

    def test_rule_ids_are_restricted_before_they_reach_a_jq_filter(self):
        self.assertTrue(va.RULE_RE.match(RULE))
        for bad in ('x"; drop', "a b", "a|b", "a$b"):
            self.assertFalse(va.RULE_RE.match(bad), bad)


class Links(unittest.TestCase):
    BODY = """| Repo | CWE | Severity | AI scan alert | Summary |
|---|---|---|---|---|
| DVWA | CWE-532 | high | https://github.com/o/DVWA/security/code-scanning/77 | text |
| other | CWE-532 | high | https://github.com/o/other/security/code-scanning/5 | text |
again https://github.com/o/DVWA/security/code-scanning/77 and an unrelated https://github.com/o/DVWA/issues/3
"""

    def test_alert_links_are_found_once_and_sorted(self):
        self.assertEqual(va.linked_alerts(self.BODY), [("o", "DVWA", 77), ("o", "other", 5)])

    def test_no_body(self):
        self.assertEqual(va.linked_alerts(""), [])
        self.assertEqual(va.linked_alerts(None), [])


class Matching(unittest.TestCase):
    AI = {"path": ".github/workflows/vulnerable.yml", "start": 59, "end": 59}

    def found(self, start, end, state="open", path=".github/workflows/vulnerable.yml", n=1):
        return {"url": f"https://github.com/o/r/security/code-scanning/{n}", "state": state, "path": path, "start": start, "end": end}

    def test_overlap_needs_the_same_file_and_lines(self):
        self.assertTrue(va.overlaps(self.AI, {"path": self.AI["path"], "start": 39, "end": 59}))
        self.assertTrue(va.overlaps(self.AI, {"path": self.AI["path"], "start": 59, "end": 70}))
        self.assertFalse(va.overlaps(self.AI, {"path": self.AI["path"], "start": 39, "end": 58}))
        self.assertFalse(va.overlaps(self.AI, {"path": "other.yml", "start": 39, "end": 59}))

    def test_covered_by_an_open_alert_whose_lines_contain_the_finding(self):
        out = va.classify(self.AI, [self.found(39, 59)], "actions", {"/language:actions"})
        self.assertEqual(out["status"], "COVERED")
        self.assertEqual(len(out["alerts"]), 1)

    def test_a_language_that_was_never_analyzed_is_not_a_miss(self):
        out = va.classify(self.AI, [], "actions", {"/language:python", "/language:javascript-typescript"})
        self.assertEqual(out["status"], "NOT_ANALYZED")
        self.assertIn("/language:actions", out["reason"])

    def test_analyzed_but_not_found_is_a_real_miss(self):
        out = va.classify(self.AI, [self.found(10, 20)], "actions", {"/language:actions"})
        self.assertEqual(out["status"], "NOT_COVERED")

    def test_a_dismissed_alert_does_not_count_as_covered_but_is_reported(self):
        out = va.classify(self.AI, [self.found(39, 59, state="dismissed")], "actions", {"/language:actions"})
        self.assertEqual(out["status"], "NOT_COVERED")
        self.assertIn("dismissed", out["reason"])

    def test_unreadable_analyses_are_not_reported_as_not_analyzed(self):
        out = va.classify(self.AI, [], "actions", None)
        self.assertEqual(out["status"], "NOT_COVERED")

    def test_a_rule_without_a_known_language_is_judged_on_alerts_only(self):
        out = va.classify(self.AI, [], None, {"/language:python"})
        self.assertEqual(out["status"], "NOT_COVERED")

    def test_location_uses_the_start_line_when_there_is_no_end(self):
        alert = {"most_recent_instance": {"location": {"path": "a.yml", "start_line": 4}}}
        self.assertEqual(va.location(alert), {"path": "a.yml", "start": 4, "end": 4})


if __name__ == "__main__":
    unittest.main()
