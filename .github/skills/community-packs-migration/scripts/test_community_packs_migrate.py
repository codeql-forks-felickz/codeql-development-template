"""Offline tests for community_packs_migrate.py. Run: python -m unittest test_community_packs_migrate"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True
import community_packs_migrate as migrate  # noqa: E402


def git(repo, *args):
    # unsigned: the user's global config signs commits, which would wait for a prompt
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com",
                    "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
                   check=True, capture_output=True)


class LockChurn(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        git(self.repo, "init", "-q")
        (self.repo / "rust" / "src").mkdir(parents=True)
        self.lock = self.repo / "rust" / "src" / "codeql-pack.lock.yml"
        self.lock.write_text("---\nlockVersion: 1.0.0\ndependencies:\n  codeql/util:\n    version: 2.0.49\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_lock_file_that_pack_install_rewrote_is_restored_and_not_a_finding(self):
        before = migrate.lock_changes(self.repo)
        self.lock.write_text("---\nlockVersion: 1.0.0\n")
        undone = migrate.undo_lock_churn(self.repo, before)
        self.assertEqual((before, undone), ({}, ["rust/src/codeql-pack.lock.yml"]))
        self.assertIn("codeql/util", self.lock.read_text())
        self.assertEqual(migrate.lock_changes(self.repo), {})

    def test_a_lock_file_that_pack_install_created_is_removed(self):
        before = migrate.lock_changes(self.repo)
        created = self.repo / "rust" / "test" / "codeql-pack.lock.yml"
        created.parent.mkdir()
        created.write_text("---\nlockVersion: 1.0.0\n")
        self.assertEqual(migrate.undo_lock_churn(self.repo, before), ["rust/test/codeql-pack.lock.yml"])
        self.assertFalse(created.exists())

    def test_a_change_that_was_there_before_the_gates_ran_is_kept_for_the_finding(self):
        self.lock.write_text("---\nlockVersion: 1.0.0\n")
        before = migrate.lock_changes(self.repo)
        self.assertEqual(list(before), ["rust/src/codeql-pack.lock.yml"])
        self.assertEqual(migrate.undo_lock_churn(self.repo, before), [])
        self.assertNotIn("codeql/util", self.lock.read_text())

    def test_a_change_of_the_unit_that_pack_install_rewrote_again_is_put_back(self):
        edited = self.lock.read_text() + "  codeql/rust-queries:\n    version: 0.1.47\n"
        self.lock.write_text(edited)
        before = migrate.lock_changes(self.repo)
        contents = {path: (self.repo / path).read_bytes() for path in before}
        self.lock.write_text("---\nlockVersion: 1.0.0\ndependencies: {}\n")
        self.assertEqual(migrate.undo_lock_churn(self.repo, before, contents), ["rust/src/codeql-pack.lock.yml"])
        self.assertEqual(self.lock.read_text(), edited)

    def test_a_change_of_the_unit_that_pack_install_left_alone_is_not_touched(self):
        edited = self.lock.read_text() + "  codeql/rust-queries:\n    version: 0.1.47\n"
        self.lock.write_text(edited)
        before = migrate.lock_changes(self.repo)
        contents = {path: (self.repo / path).read_bytes() for path in before}
        self.assertEqual(migrate.undo_lock_churn(self.repo, before, contents), [])
        self.assertEqual(self.lock.read_text(), edited)


class HelpFiles(unittest.TestCase):
    def test_a_markdown_help_file_with_a_qhelp_twin_is_dropped_and_a_lone_one_is_kept(self):
        twin = [{"rel": "Q.md"}, {"rel": "Q.qhelp"}, {"rel": "QBad.rs"}]
        self.assertEqual([i["rel"] for i in migrate.without_duplicate_help(twin, "Q")], ["Q.qhelp", "QBad.rs"])
        lone = [{"rel": "Q.md"}, {"rel": "QBad.rs"}]
        self.assertEqual(migrate.without_duplicate_help(lone, "Q"), lone)
        other = [{"rel": "Other.md"}, {"rel": "Q.qhelp"}]
        self.assertEqual(migrate.without_duplicate_help(other, "Q"), other)


class SharedLibraries(unittest.TestCase):
    def test_a_library_that_a_query_imports_follows_it_with_the_libraries_it_imports(self):
        files = {
            "languages/rust/custom/src/QueryA/QueryA.ql": "import rust\nimport common.Keys\n",
            "languages/rust/custom/src/QueryA/Help.md": "help\n",
            "languages/rust/custom/src/common/Keys.qll": "import rust\nprivate import common.Steps\n",
            "languages/rust/custom/src/common/Steps.qll": "import rust\n",
            "languages/rust/custom/src/common/Unused.qll": "import rust\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            git(repo, "init", "-q")
            for rel, text in files.items():
                (repo / rel).parent.mkdir(parents=True, exist_ok=True)
                (repo / rel).write_text(text)
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "x")
            git(repo, "update-ref", "refs/prs/7", "HEAD")
            entries = [(p, migrate.classify(p)) for p in files]
            query_dirs = {c["dir"] for _, c in entries if c["kind"] == "query"}
            libraries = migrate.shared_libraries(repo, 7, entries, query_dirs, [files["languages/rust/custom/src/QueryA/QueryA.ql"]])
        self.assertEqual([lib["rel"] for lib in libraries], ["common/Keys.qll", "common/Steps.qll"])
        self.assertEqual(libraries[0]["source"], "languages/rust/custom/src/common/Keys.qll")


class GeneratedTestFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        git(self.repo, "init", "-q", "-b", "main")
        (self.repo / "README.md").write_text("x\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        git(self.repo, "checkout", "-q", "-b", "rust/work")
        self.dir = self.repo / "rust" / "test" / "security" / "CWE-001" / "Thing"
        self.dir.mkdir(parents=True)
        for name in ("Thing.ql", "Thing.expected", "main.rs", "Cargo.lock"):
            (self.dir / name).write_text("kept\n")
        # what `codeql test run` leaves behind
        (self.dir / "Cargo.toml").write_text("[package]\n")
        (self.dir / "lib.rs").write_text("")
        (self.dir / "target" / "debug").mkdir(parents=True)
        (self.dir / "target" / "debug" / "junk.rlib").write_bytes(b"\0\1")
        self.messages = tempfile.TemporaryDirectory()
        self.message = Path(self.messages.name) / "message.txt"
        self.message.write_text("A neutral message\n")

    def tearDown(self):
        self.tmp.cleanup()
        self.messages.cleanup()

    def test_what_a_local_test_run_generated_is_not_part_of_the_change(self):
        paths = migrate.changed_paths(self.repo, "main")
        self.assertNotIn("rust/test/security/CWE-001/Thing/Cargo.toml", paths)
        self.assertNotIn("rust/test/security/CWE-001/Thing/lib.rs", paths)
        self.assertFalse([p for p in paths if "/target/" in p])
        self.assertIn("rust/test/security/CWE-001/Thing/main.rs", paths)

    def test_the_same_names_outside_a_rust_test_directory_are_kept(self):
        (self.repo / "rust" / "src").mkdir(parents=True)
        (self.repo / "rust" / "src" / "lib.rs").write_text("x\n")
        self.assertIn("rust/src/lib.rs", migrate.changed_paths(self.repo, "main"))

    def test_commit_stages_the_unit_unsigned_and_leaves_out_a_cargo_lock_no_spec_supplies(self):
        spec = {"tests": [{"target": "rust/test/security/CWE-001/Thing", "files": [{"rel": "main.rs"}]}]}
        result = migrate.commit_unit(self.repo, "main", [spec], self.message, [])
        self.assertEqual(result["left_out"], ["rust/test/security/CWE-001/Thing/Cargo.lock"])
        self.assertNotIn("rust/test/security/CWE-001/Thing/Cargo.lock", result["files"])
        self.assertEqual(len(migrate.git_bytes(self.repo, "ls-tree", "-r", "--name-only", "HEAD").decode().split()), 4)
        self.assertEqual(migrate.git_bytes(self.repo, "log", "-1", "--format=%s").decode().strip(), "A neutral message")
        self.assertFalse(any("target" in f or f.endswith(("Cargo.toml", "lib.rs")) for f in result["files"]))

    def test_a_cargo_lock_that_a_spec_supplies_or_that_is_included_is_committed(self):
        lock = "rust/test/security/CWE-001/Thing/Cargo.lock"
        spec = {"tests": [{"target": "rust/test/security/CWE-001/Thing", "files": [{"rel": "Cargo.lock"}]}]}
        self.assertIn(lock, migrate.commit_unit(self.repo, "main", [spec], self.message, [])["files"])

    def test_include_keeps_a_hand_added_cargo_lock(self):
        lock = "rust/test/security/CWE-001/Thing/Cargo.lock"
        self.assertIn(lock, migrate.commit_unit(self.repo, "main", [], self.message, [lock])["files"])

    def test_commit_refuses_main(self):
        git(self.repo, "checkout", "-q", "main")
        with self.assertRaises(SystemExit):
            migrate.commit_unit(self.repo, "main", [], self.message, [])


class CostClass(unittest.TestCase):
    BUDGET = 60.0

    def item(self, **fields):
        return {"completed": True, "wall_s": 30.0, "own_ms": 1000, "own_top": [], "blowups": [], **fields}

    def test_a_cheap_query_is_low(self):
        self.assertEqual(migrate.classify_cost(self.item(), self.BUDGET), ("low", []))

    def test_little_headroom_is_moderate_and_says_why(self):
        cls, notes = migrate.classify_cost(self.item(own_ms=12_000), self.BUDGET)
        self.assertEqual(cls, "moderate")
        self.assertIn("12.0 s", notes[0])
        cls, notes = migrate.classify_cost(self.item(own_top=[{"name": "Q::slow", "ms": 6_000, "size": 5}]), self.BUDGET)
        self.assertEqual((cls, "Q::slow" in notes[0]), ("moderate", True))
        cls, notes = migrate.classify_cost(self.item(wall_s=900.0), self.BUDGET)
        self.assertEqual((cls, "15 minutes" in notes[0]), ("moderate", True))

    def test_what_the_gate_fails_is_high(self):
        self.assertEqual(migrate.classify_cost(self.item(completed=False, timed_out="killed after 7200s"), self.BUDGET)[0], "high")
        self.assertEqual(migrate.classify_cost(self.item(blowups=[{"predicate": "Q::p", "tuples": 10 ** 7}]), self.BUDGET)[0], "high")
        cls, notes = migrate.classify_cost(self.item(own_ms=75_000), self.BUDGET)
        self.assertEqual((cls, "budget of 60 s" in notes[0]), ("high", True))

    def test_the_budget_is_the_edge_between_moderate_and_high(self):
        self.assertEqual(migrate.classify_cost(self.item(own_ms=60_000), self.BUDGET)[0], "moderate")
        self.assertEqual(migrate.classify_cost(self.item(own_ms=60_001), self.BUDGET)[0], "high")

    def test_a_real_log_summary_is_classified_by_its_own_predicates_only(self):
        log = "\n".join([
            "[2026-01-01 00:00:00] Evaluated non-recursive predicate Library::bigRelation/1#abc in 90000ms (size: 5)",
            "[2026-01-01 00:00:01] Evaluated non-recursive predicate Thing::isSink/1#def in 6500ms (size: 3)",
            "[2026-01-01 00:00:02] Evaluated non-recursive predicate Thing::isSource/1#ghi in 300ms (size: 3)",
        ])
        summary = migrate.parse_log_summary(log, "Thing", blowup_tuples=1_000_000)
        self.assertEqual(summary["own_ms"], 6800)
        cls, notes = migrate.classify_cost({"completed": True, "wall_s": 100.0, **summary}, self.BUDGET)
        self.assertEqual(cls, "moderate")
        self.assertIn("Thing::isSink", notes[0])


class LocalRoot(unittest.TestCase):
    def test_the_top_directory_of_a_windows_checkout_is_a_local_path(self):
        pattern = migrate.local_root_pattern("D:\\work\\wt\\140")
        self.assertTrue(pattern.search("see D:\\work\\notes.md"))
        self.assertTrue(pattern.search("see d:/work/notes.md"))
        self.assertFalse(pattern.search("D:\\workshop\\notes.md"))
        self.assertFalse(pattern.search("E:\\work\\notes.md"))

    def test_a_path_without_a_directory_below_the_drive_has_no_local_root(self):
        self.assertIsNone(migrate.local_root_pattern("/home/me/checkout"))
        self.assertIsNone(migrate.local_root_pattern("D:\\"))


def selects(**suites):
    """The shape of suite_effect: a suite name and the unit targets it selects (None: it does not resolve)."""
    return {name: {"resolves": chosen is not None, "selects": chosen, "queries": len(chosen or [])} for name, chosen in suites.items()}


CORS = "rust/src/audit/CWE-942/Cors.ql"
SSRF = "rust/src/security/CWE-918/Ssrf.ql"


class SuiteGaps(unittest.TestCase):
    def spec(self, *queries):
        return {"language": "rust", "queries": [{"target": t, "audit": audit} for t, audit in queries], "models": []}

    def test_a_security_query_that_the_default_suite_selects_is_fine(self):
        self.assertEqual(migrate.suite_gaps(self.spec((SSRF, False)), selects(**{"rust.qls": [SSRF]})), [])

    def test_an_audit_query_with_no_audit_suite_is_the_rust_gap(self):
        problems = migrate.suite_gaps(self.spec((CORS, True)), selects(**{"rust.qls": []}))
        self.assertEqual(len(problems), 1)
        self.assertIn("no rust/src/suites/rust-audit.qls", problems[0])

    def test_an_audit_query_selected_by_the_audit_suite_alone_is_fine(self):
        effect = selects(**{"rust.qls": [], "rust-audit.qls": [CORS]})
        self.assertEqual(migrate.suite_gaps(self.spec((CORS, True)), effect), [])

    def test_an_audit_query_that_the_default_suite_selects_too_is_not_fine(self):
        effect = selects(**{"rust.qls": [CORS], "rust-audit.qls": [CORS]})
        self.assertIn("must stay out of rust.qls", migrate.suite_gaps(self.spec((CORS, True)), effect)[0])

    def test_a_security_query_that_kind_or_precision_keeps_out_is_not_fine(self):
        problems = migrate.suite_gaps(self.spec((SSRF, False)), selects(**{"rust.qls": []}))
        self.assertIn("does not select it", problems[0])

    def test_a_suite_that_does_not_resolve_is_not_fine(self):
        self.assertIn("does not resolve", migrate.suite_gaps(self.spec((SSRF, False)), selects(**{"rust.qls": None}))[0])


class UnitGaps(unittest.TestCase):
    """The config and suite gaps that matter to a unit, in a repository that has the Rust pack on its base."""

    QUERY = "/**\n * @name Q\n * @kind path-problem\n * @id githubsecuritylab/rust/q\n * @tags security%s\n */\n"

    def put(self, rel, text):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        git(self.repo, "init", "-q")
        self.put("rust/src/qlpack.yml", "name: githubsecuritylab/codeql-rust-queries\n")
        self.put("rust/src/security/CWE-918/Ssrf.ql", self.QUERY % "")
        self.put("rust/src/suites/rust.qls", "- queries: '.'\n")
        self.put("rust/ext/qlpack.yml", "name: githubsecuritylab/codeql-rust-extensions\nlibrary: true\n")
        for name in ("default.yml", "synthetics.yml", "audit.yml"):
            self.put(f"configs/{name}", "packs:\n  - githubsecuritylab/codeql-go-queries\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")

    def tearDown(self):
        self.tmp.cleanup()

    def spec(self, queries=(), models=()):
        return {"language": "rust", "queries": [{"target": t, "audit": a} for t, a in queries],
                "models": [{"target": m} for m in models]}

    def kinds(self, gaps):
        return sorted((g["kind"], g["when"]) for g in gaps)

    def test_a_new_audit_query_needs_its_suite_now_and_the_audit_line_after_the_release(self):
        self.put("rust/src/audit/CWE-942/Cors.ql", self.QUERY % " audit")
        gaps = migrate.unit_gaps(self.spec([(CORS, True)]), self.repo, "HEAD")
        self.assertEqual(self.kinds(gaps), [("audit-config", "after-release"), ("audit-suite", "now")])

    def test_a_new_security_query_needs_the_pack_in_both_configs_when_the_pack_exists_on_the_base(self):
        gaps = migrate.unit_gaps(self.spec([(SSRF, False)]), self.repo, "HEAD")
        self.assertEqual(self.kinds(gaps), [("config-queries-pack", "now")] * 2)

    def test_the_lines_of_a_pack_that_is_new_wait_for_its_first_release(self):
        git(self.repo, "rm", "-q", "--cached", "rust/src/qlpack.yml")
        git(self.repo, "commit", "-q", "-m", "the pack is not on the base")
        gaps = migrate.unit_gaps(self.spec([(SSRF, False)]), self.repo, "HEAD")
        self.assertEqual(self.kinds(gaps), [("config-queries-pack", "after-release")] * 2)

    def test_model_rows_need_the_ext_pack_in_the_synthetics_config_only(self):
        self.put("rust/ext/manual/iron.model.yml", "extensions: []\n")
        gaps = migrate.unit_gaps(self.spec(models=["rust/ext/manual/iron.model.yml"]), self.repo, "HEAD")
        self.assertEqual([(g["kind"], g["file"]) for g in gaps], [("config-ext-pack", "configs/synthetics.yml")])

    def test_a_unit_that_adds_its_own_lines_has_no_gap(self):
        for name in ("default.yml", "synthetics.yml"):
            self.put(f"configs/{name}", "packs:\n  - githubsecuritylab/codeql-go-queries\n  - githubsecuritylab/codeql-rust-queries\n")
        self.assertEqual(migrate.unit_gaps(self.spec([(SSRF, False)]), self.repo, "HEAD"), [])


if __name__ == "__main__":
    unittest.main()
