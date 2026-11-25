"""Offline tests for rule_value.py. Run: python -m unittest test_rule_value"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True
import rule_value as rv  # noqa: E402


def alert(repo, rule, path="a.py", line=1):
    return {"repo": repo, "rule": rule, "path": path, "line": line, "category": "/language:python", "severity": "warning", "created_at": "2026-11-20T21:00:00Z", "number": 1}


class Namespace(unittest.TestCase):
    def test_pack_family_comes_from_the_rule_id(self):
        self.assertEqual(rv.namespace("githubsecuritylab/actions/unpinned-tag"), "community-packs")
        self.assertEqual(rv.namespace("tob/cpp/x"), "trail-of-bits")
        self.assertEqual(rv.namespace("py/sql-injection"), "codeql")


class SarifMeta(unittest.TestCase):
    def test_rules_of_the_driver_and_of_extensions_are_read_and_a_missing_precision_is_none(self):
        sarif = {"runs": [{"tool": {"driver": {"rules": [{"id": "py/a", "properties": {"precision": "high", "kind": "path-problem", "tags": ["security"]}}]},
                                    "extensions": [{"rules": [{"id": "githubsecuritylab/b", "properties": {"kind": "problem"}}]}]}}]}
        meta = rv.rule_meta_from_sarif(sarif)
        self.assertEqual(meta["py/a"]["precision"], "high")
        self.assertEqual(meta["githubsecuritylab/b"]["precision"], "none")
        self.assertEqual(rv.rule_meta_from_sarif({}), {})


class Summary(unittest.TestCase):
    def test_alerts_are_grouped_by_rule_with_repos_and_two_examples(self):
        alerts = [alert("r1", "py/a"), alert("r1", "py/a", line=2), alert("r2", "py/a"), alert("r2", "js/b")]
        rows = rv.summarize(alerts, {"py/a": {"precision": "low", "kind": "problem"}})
        self.assertEqual([(r["rule"], r["alerts"], r["repos"], r["precision"]) for r in rows], [("py/a", 3, 2, "low"), ("js/b", 1, 1, "unknown")])
        self.assertEqual(len(rows[0]["examples"]), 2)

    def test_precision_table_counts_alerts_and_rules_per_family(self):
        rows = [{"rule": "py/a", "namespace": "codeql", "precision": "low", "alerts": 3, "repos": 1},
                {"rule": "py/b", "namespace": "codeql", "precision": "low", "alerts": 2, "repos": 1},
                {"rule": "githubsecuritylab/c", "namespace": "community-packs", "precision": "medium", "alerts": 1, "repos": 1}]
        self.assertEqual(rv.by_precision(rows), {"codeql": {"low": {"alerts": 5, "rules": 2}}, "community-packs": {"medium": {"alerts": 1, "rules": 1}}})

    def test_languages_split_stock_rules_by_precision_and_other_families_by_name(self):
        alerts = [alert("r", "py/a"), alert("r", "py/b"), alert("r", "githubsecuritylab/c")]
        meta = {"py/a": {"precision": "low"}, "py/b": {"precision": "high"}}
        table = rv.by_language(alerts, meta)
        self.assertEqual(dict(table["python"]), {"low": 1, "high": 1, "community-packs": 1})
        self.assertEqual(rv.language_of({"category": None}), "unknown")


if __name__ == "__main__":
    unittest.main()
