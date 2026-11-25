"""Offline tests for default_setup_languages.py: what is sent to the API, and which repositories are touched."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import default_setup_languages as dsl  # noqa: E402


def row(**kw):
    base = {"repository": "o/r", "archived": False, "state": "configured", "languages": ["python"], "raw_languages": ["python"],
            "query_suite": "extended", "threat_model": "remote", "runner_type": "standard", "runner_label": None, "files": 3,
            "registered": 2, "properties": {}}
    base.update(kw)
    return base


class Canonical(unittest.TestCase):
    def test_aliases_collapse_to_the_names_a_patch_accepts(self):
        self.assertEqual(dsl.canonical(["javascript", "javascript-typescript", "python", "typescript"]),
                         ["javascript-typescript", "python"])
        self.assertEqual(dsl.canonical(["java", "java-kotlin", "kotlin", "c", "cpp", "c-cpp"]), ["java-kotlin", "c-cpp"])

    def test_other_languages_are_kept_as_they_are_in_order(self):
        self.assertEqual(dsl.canonical(["rust", "go", "ruby", "rust"]), ["rust", "go", "ruby"])


class Detection(unittest.TestCase):
    def test_counts_yaml_files_only(self):
        listing = [{"type": "file", "name": "ci.yml"}, {"type": "file", "name": "Release.YAML"},
                   {"type": "file", "name": "README.md"}, {"type": "dir", "name": "nested.yml"}]
        self.assertEqual(dsl.workflow_files(listing), 2)

    def test_a_missing_directory_or_an_error_object_is_zero(self):
        self.assertEqual(dsl.workflow_files(None), 0)
        self.assertEqual(dsl.workflow_files({"message": "Not Found"}), 0)
        self.assertEqual(dsl.workflow_files([]), 0)


class Decide(unittest.TestCase):
    def test_enable_only_a_configured_repository_with_files_and_without_the_language(self):
        self.assertEqual(dsl.decide(row(), "actions"), "enable")

    def test_each_skip_reason(self):
        self.assertEqual(dsl.decide(row(archived=True), "actions"), "skip: archived")
        self.assertEqual(dsl.decide(row(state="not-configured"), "actions"), "skip: default setup is not configured")
        self.assertEqual(dsl.decide(row(languages=["python", "actions"]), "actions"), "skip: already analyzed")
        self.assertEqual(dsl.decide(row(files=0), "actions"), "skip: no files of the language")

    def test_a_fork_whose_workflows_are_not_enabled_is_not_ready(self):
        self.assertEqual(dsl.decide(row(registered=0), "actions"), "skip: workflows are not enabled (the API would refuse)")

    def test_a_repository_with_rust_is_left_to_the_settings_form(self):
        self.assertEqual(dsl.decide(row(languages=["c-cpp", "rust"]), "actions"),
                         "skip: the API does not accept rust (use the settings form)")
        self.assertEqual(dsl.decide(row(languages=["rust"], registered=0), "actions"),
                         "skip: workflows are not enabled (the API would refuse)")


class Registered(unittest.TestCase):
    def test_a_language_is_removed_by_its_canonical_name_or_an_alias(self):
        current = ["javascript", "javascript-typescript", "python", "typescript", "actions"]
        self.assertEqual(dsl.without_language(current, "python"), ["javascript-typescript", "actions"])
        self.assertEqual(dsl.without_language(current, "typescript"), ["python", "actions"])
        self.assertEqual(dsl.without_language(["python"], "go"), ["python"])

    def test_only_active_own_workflows_are_disabled(self):
        listing = {"workflows": [{"id": 1, "path": ".github/workflows/a.yml", "state": "active"},
                                 {"id": 2, "path": ".github/workflows/b.yml", "state": "disabled_fork"},
                                 {"id": 3, "path": ".github/workflows/c.yml", "state": "disabled_manually"},
                                 {"id": 4, "path": "dynamic/github-code-scanning/codeql", "state": "active"}]}
        self.assertEqual([w["id"] for w in dsl.active_own_workflows(listing)], [1])
        self.assertEqual(dsl.active_own_workflows(None), [])
        self.assertEqual(dsl.active_own_workflows({"message": "Not Found"}), [])
    def test_counts_the_repositorys_own_workflows_and_ignores_dynamic_ones(self):
        listing = {"workflows": [{"path": ".github/workflows/ci.yml", "state": "active"},
                                 {"path": ".github/workflows/old.yml", "state": "disabled_fork"},
                                 {"path": "dynamic/github-code-scanning/codeql", "state": "active"}]}
        self.assertEqual(dsl.registered_workflows(listing), 2)

    def test_a_fork_with_only_dynamic_workflows_has_none(self):
        self.assertEqual(dsl.registered_workflows({"workflows": [{"path": "dynamic/github-code-scanning/codeql"}]}), 0)

    def test_missing_or_malformed_listings_are_zero(self):
        self.assertEqual(dsl.registered_workflows(None), 0)
        self.assertEqual(dsl.registered_workflows({"message": "Not Found"}), 0)
        self.assertEqual(dsl.registered_workflows([]), 0)


class Payload(unittest.TestCase):
    def test_existing_languages_and_settings_are_sent_back_with_the_new_one(self):
        r = row(raw_languages=["javascript", "javascript-typescript", "python", "typescript"])
        body = dsl.payload(r, dsl.canonical(r["raw_languages"] + ["actions"]))
        self.assertEqual(body, {"state": "configured", "languages": ["javascript-typescript", "python", "actions"],
                                "query_suite": "extended", "threat_model": "remote"})

    def test_a_labeled_runner_is_kept_and_a_standard_one_is_not_sent(self):
        labeled = dsl.payload(row(runner_type="labeled", runner_label="big"), ["python", "actions"])
        self.assertEqual((labeled["runner_type"], labeled["runner_label"]), ("labeled", "big"))
        self.assertNotIn("runner_type", dsl.payload(row(), ["python", "actions"]))

    def test_unknown_settings_are_not_invented(self):
        body = dsl.payload(row(query_suite=None, threat_model=None), ["actions"])
        self.assertEqual(body, {"state": "configured", "languages": ["actions"]})


class Selection(unittest.TestCase):
    class Args:
        def __init__(self, only=(), property=None):
            self.only, self.property = list(only), property

    PLAN = {"rows": [
        {**row(repository="o/a", properties={"Synthetic": "true"}), "action": "enable"},
        {**row(repository="o/b"), "action": "enable"},
        {**row(repository="o/c", properties={"Synthetic": "true"}), "action": "skip: already analyzed"},
        {**row(repository="o/d", properties={"Synthetic": "true"}), "action": "enable", "result": {"applied": True}},
    ]}

    def names(self, rows):
        return [r["repository"] for r in rows]

    def test_apply_takes_only_rows_marked_enable(self):
        self.assertEqual(self.names(dsl.selected(self.PLAN, self.Args(), "apply")), ["o/a", "o/b", "o/d"])

    def test_the_property_limits_the_rows(self):
        self.assertEqual(self.names(dsl.selected(self.PLAN, self.Args(property="Synthetic=true"), "apply")), ["o/a", "o/d"])

    def test_only_limits_to_named_repositories_by_short_or_full_name(self):
        self.assertEqual(self.names(dsl.selected(self.PLAN, self.Args(only=["A"]), "apply")), ["o/a"])
        self.assertEqual(self.names(dsl.selected(self.PLAN, self.Args(only=["o/b"]), "apply")), ["o/b"])

    def test_revert_takes_only_rows_that_were_applied(self):
        self.assertEqual(self.names(dsl.selected(self.PLAN, self.Args(), "revert")), ["o/d"])


if __name__ == "__main__":
    unittest.main()
