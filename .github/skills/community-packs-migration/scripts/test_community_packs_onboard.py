"""Offline tests for community_packs_onboard.py. Run: python -m unittest test_community_packs_onboard"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True
import community_packs_onboard as onboard  # noqa: E402

DEFAULT = """name: "Default"

packs:
  # GitHub Actions
  - githubsecuritylab/codeql-actions-queries
  # C/C++
  - githubsecuritylab/codeql-cpp-queries
  # Go
  - githubsecuritylab/codeql-go-queries
  # Ruby
  - githubsecuritylab/codeql-ruby-queries

  # Data extensions
  - githubsecuritylab/codeql-java-extensions
"""

SYNTHETICS = """name: "Synthetics"

packs:
    # All queries from the CodeQL Built in packs
    - codeql/cpp-queries:.
    - codeql/rust-queries:.

    ### GitHub Security Lab###
    - githubsecuritylab/codeql-cpp-queries
    - githubsecuritylab/codeql-go-queries
    - githubsecuritylab/codeql-ruby-queries

    # Data extensions via Community Packs
    - githubsecuritylab/codeql-go-extensions
    - githubsecuritylab/codeql-java-extensions

query-filters:
    - exclude:
          id:
              - cpp/untrusted-data-to-external-api
    - exclude:
          tags contain:
              - audit
"""

AUDIT = """name: "Audit"

packs:
  # C#
  - githubsecuritylab/codeql-csharp-queries:suites/csharp-audit.qls
  - githubsecuritylab/codeql-csharp-extensions
  # Java
  - githubsecuritylab/codeql-java-queries:suites/java-audit.qls
  # Ruby
  # - githubsecuritylab/codeql-ruby-queries:suites/ruby-audit.qls
"""

RUST_QUERIES = "githubsecuritylab/codeql-rust-queries"
RUST_EXT = "githubsecuritylab/codeql-rust-extensions"
# the same configs once the Rust lines are in them (the packs block of the synthetics config is not the last block)
DEFAULT_WITH_RUST = DEFAULT + f"  - {RUST_QUERIES}\n"
SYNTHETICS_WITH_RUST = SYNTHETICS.replace("\nquery-filters:", f"    - {RUST_QUERIES}\n    - {RUST_EXT}\n\nquery-filters:", 1)
AUDIT_WITH_RUST = AUDIT + f"  - {RUST_QUERIES}:suites/rust-audit.qls\n"


def write(path: Path, text: str, crlf: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))


def query(kind: str, tags: str) -> str:
    return f"/**\n * @name Q\n * @kind {kind}\n * @id githubsecuritylab/rust/q\n * @tags {tags}\n */\n\nimport rust\n"


def state(**overrides) -> dict:
    base = {"language": "rust", "queries_pack": RUST_QUERIES, "ext_pack": RUST_EXT, "suites": ["rust.qls"],
            "queries": {"security": 4, "audit": 1, "explore": 0, "other": 0}, "ext_models": 2}
    base.update(overrides)
    return base


class ConfigPacks(unittest.TestCase):
    def test_a_flat_list_reads_pack_and_path_and_nothing_from_the_other_blocks(self):
        entries = onboard.config_packs(SYNTHETICS)
        self.assertIn(("codeql/rust-queries", "."), entries)
        self.assertIn(("githubsecuritylab/codeql-go-queries", ""), entries)
        self.assertEqual(len(entries), 7)
        self.assertNotIn("cpp/untrusted-data-to-external-api", [name for name, _ in entries])

    def test_a_commented_out_line_is_not_an_entry(self):
        self.assertEqual(onboard.config_packs(AUDIT), [
            ("githubsecuritylab/codeql-csharp-queries", "suites/csharp-audit.qls"),
            ("githubsecuritylab/codeql-csharp-extensions", ""),
            ("githubsecuritylab/codeql-java-queries", "suites/java-audit.qls"),
        ])

    def test_a_mapping_of_languages_and_a_quoted_path_with_spaces(self):
        text = ("packs:\n  csharp:\n    - \"codeql/csharp-queries:Security Features/CWE-798/Hardcoded.ql\"\n"
                "  rust:\n    - githubsecuritylab/codeql-rust-queries:security/CWE-321/Key.ql  # a note\n")
        self.assertEqual(onboard.config_packs(text), [
            ("codeql/csharp-queries", "Security Features/CWE-798/Hardcoded.ql"),
            ("githubsecuritylab/codeql-rust-queries", "security/CWE-321/Key.ql"),
        ])

    def test_the_block_ends_at_the_next_top_level_key(self):
        text = "packs:\n  - a/b\npaths-ignore:\n  - examples/site\n"
        self.assertEqual(onboard.config_packs(text), [("a/b", "")])

    def test_crlf_reads_the_same(self):
        self.assertEqual(onboard.config_packs(DEFAULT.replace("\n", "\r\n")), onboard.config_packs(DEFAULT))


class QueryMeta(unittest.TestCase):
    def test_kind_and_tags_over_several_lines(self):
        text = "/**\n * @name Q\n * @kind path-problem\n * @tags security\n *       experimental\n *       external/cwe/cwe-079\n * @id x\n */\n"
        self.assertEqual(onboard.query_meta(text), ("path-problem", ["security", "experimental", "external/cwe/cwe-079"]))

    def test_a_file_without_a_header(self):
        self.assertEqual(onboard.query_meta("import rust\n"), (None, []))

    def test_tags_after_the_last_tag_line_belong_to_the_next_tag_only(self):
        text = "/**\n * @tags audit\n * @id githubsecuritylab/x\n */\n"
        self.assertEqual(onboard.query_meta(text), (None, ["audit"]))


class LanguageState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ccp = Path(self.tmp.name)
        write(self.ccp / "rust/src/qlpack.yml", f"name: {RUST_QUERIES}\nversion: 0.9.2\n")
        write(self.ccp / "rust/src/security/CWE-918/Ssrf.ql", query("path-problem", "security\n *       external/cwe/cwe-918"))
        write(self.ccp / "rust/src/audit/CWE-942/Cors.ql", query("path-problem", "security audit"))
        write(self.ccp / "rust/src/audit/explore/Files.ql", query("table", "audit"))
        write(self.ccp / "rust/src/debugging/Dbg.ql", query("problem", "debugging"))
        write(self.ccp / "rust/src/.codeql/lib/Ignored.ql", query("problem", "security"))
        write(self.ccp / "rust/src/suites/rust.qls", "- queries: '.'\n")
        write(self.ccp / "rust/ext/qlpack.yml", f"name: {RUST_EXT}\nlibrary: true\n")
        write(self.ccp / "rust/ext/manual/iron.model.yml", "extensions: []\n")
        write(self.ccp / "rust/ext/generated/.gitkeep", "")

    def tearDown(self):
        self.tmp.cleanup()

    def test_queries_are_counted_by_what_the_suites_can_select(self):
        found = onboard.language_state(self.ccp, "rust")
        self.assertEqual(found["queries"], {"security": 1, "audit": 1, "explore": 1, "other": 1})
        self.assertEqual((found["queries_pack"], found["ext_pack"], found["suites"]), (RUST_QUERIES, RUST_EXT, ["rust.qls"]))

    def test_an_extension_pack_has_models_when_it_has_a_yml_other_than_its_pack_files(self):
        self.assertEqual(onboard.language_state(self.ccp, "rust")["ext_models"], 1)
        (self.ccp / "rust/ext/manual/iron.model.yml").unlink()
        self.assertEqual(onboard.language_state(self.ccp, "rust")["ext_models"], 0)

    def test_a_language_without_a_directory_has_nothing(self):
        found = onboard.language_state(self.ccp, "swift")
        self.assertEqual((found["queries_pack"], sum(found["queries"].values()), found["suites"]), (None, 0, []))


class Gaps(unittest.TestCase):
    CONFIGS = {"default.yml": DEFAULT, "synthetics.yml": SYNTHETICS, "audit.yml": AUDIT}

    def kinds(self, gaps):
        return sorted((g["kind"], g["when"]) for g in gaps)

    def test_a_language_the_configs_never_heard_of_misses_every_line(self):
        gaps = onboard.onboard_gaps(state(), self.CONFIGS)
        self.assertEqual(self.kinds(gaps), [
            ("audit-config", "after-release"), ("audit-suite", "now"),
            ("config-ext-pack", "now"), ("config-queries-pack", "now"), ("config-queries-pack", "now"),
        ])
        self.assertEqual(sorted(g["file"] for g in gaps if g["kind"] == "config-queries-pack"),
                         ["configs/default.yml", "configs/synthetics.yml"])

    def test_nothing_is_missing_once_the_lines_and_the_suite_are_there(self):
        configs = {"default.yml": DEFAULT_WITH_RUST, "synthetics.yml": SYNTHETICS_WITH_RUST, "audit.yml": AUDIT_WITH_RUST}
        self.assertEqual(onboard.onboard_gaps(state(suites=["rust.qls", "rust-audit.qls"]), configs), [])

    def test_a_pack_with_no_security_query_needs_no_default_lines_and_one_without_models_needs_no_ext_line(self):
        found = state(queries={"security": 0, "audit": 0, "explore": 3, "other": 2}, ext_models=0)
        self.assertEqual(onboard.onboard_gaps(found, self.CONFIGS), [])

    def test_an_exploration_query_of_kind_table_does_not_need_an_audit_suite(self):
        found = state(queries={"security": 0, "audit": 0, "explore": 2, "other": 0}, ext_models=0)
        self.assertEqual([g["kind"] for g in onboard.onboard_gaps(found, self.CONFIGS)], [])

    def test_security_queries_need_the_default_suite(self):
        gaps = onboard.onboard_gaps(state(suites=[]), self.CONFIGS)
        self.assertIn("security-suite", [g["kind"] for g in gaps])

    def test_the_audit_line_waits_for_the_release_unless_the_published_pack_has_the_suite(self):
        configs = {**self.CONFIGS, "default.yml": DEFAULT_WITH_RUST, "synthetics.yml": SYNTHETICS_WITH_RUST}
        found = state(suites=["rust.qls", "rust-audit.qls"])
        for answer, when in ((None, "after-release"), (False, "after-release"), (True, "now")):
            gaps = onboard.onboard_gaps(found, configs, lambda pack, path, answer=answer: answer)
            self.assertEqual(self.kinds(gaps), [("audit-config", when)])

    def test_a_pack_that_was_never_published_waits_for_its_first_release(self):
        gaps = onboard.onboard_gaps(state(queries={"security": 1, "audit": 0, "explore": 0, "other": 0}, ext_models=0),
                                    self.CONFIGS, lambda pack, path: False if path == "" else None)
        self.assertEqual(self.kinds(gaps), [("config-queries-pack", "after-release")] * 2)


class InsertPackLine(unittest.TestCase):
    def test_a_commented_block_gets_a_comment_and_goes_after_the_language_before_it(self):
        out = onboard.insert_pack_line(DEFAULT, "config-queries-pack", "rust", RUST_QUERIES)
        self.assertIn(f"  # Ruby\n  - githubsecuritylab/codeql-ruby-queries\n  # Rust\n  - {RUST_QUERIES}\n\n  # Data extensions", out)

    def test_a_language_in_the_middle_goes_between_its_neighbours(self):
        out = onboard.insert_pack_line(DEFAULT, "config-queries-pack", "java", "githubsecuritylab/codeql-java-queries")
        self.assertIn("codeql-go-queries\n  # Java\n  - githubsecuritylab/codeql-java-queries\n  # Ruby\n", out)

    def test_a_language_before_the_first_goes_above_its_comment(self):
        out = onboard.insert_pack_line(DEFAULT.replace("  # GitHub Actions\n  - githubsecuritylab/codeql-actions-queries\n", ""),
                                       "config-queries-pack", "actions", "githubsecuritylab/codeql-actions-queries")
        self.assertIn("packs:\n  # GitHub Actions\n  - githubsecuritylab/codeql-actions-queries\n  # C/C++\n", out)

    def test_an_uncommented_block_gets_the_line_with_its_own_indent_and_no_comment(self):
        out = onboard.insert_pack_line(SYNTHETICS, "config-queries-pack", "rust", RUST_QUERIES)
        self.assertIn(f"    - githubsecuritylab/codeql-ruby-queries\n    - {RUST_QUERIES}\n\n", out)
        self.assertEqual(out.count("# Rust"), 0)
        self.assertEqual(out[out.index("query-filters:"):], SYNTHETICS[SYNTHETICS.index("query-filters:"):])

    def test_an_extension_line_goes_with_the_extension_lines(self):
        out = onboard.insert_pack_line(SYNTHETICS, "config-ext-pack", "rust", RUST_EXT)
        self.assertIn(f"    - githubsecuritylab/codeql-java-extensions\n    - {RUST_EXT}\n\nquery-filters:", out)

    def test_an_audit_line_goes_after_the_whole_group_of_the_language_before_it(self):
        out = onboard.insert_pack_line(AUDIT, "audit-config", "go", "githubsecuritylab/codeql-go-queries:suites/go-audit.qls")
        self.assertIn("codeql-csharp-extensions\n  # Go\n  - githubsecuritylab/codeql-go-queries:suites/go-audit.qls\n  # Java\n", out)

    def test_a_commented_out_line_for_the_same_entry_is_switched_on(self):
        out = onboard.insert_pack_line(AUDIT, "audit-config", "ruby", "githubsecuritylab/codeql-ruby-queries:suites/ruby-audit.qls")
        self.assertIn("  # Ruby\n  - githubsecuritylab/codeql-ruby-queries:suites/ruby-audit.qls\n", out)
        self.assertEqual(out.count("\n"), AUDIT.count("\n"))

    def test_line_endings_are_kept(self):
        out = onboard.insert_pack_line(DEFAULT.replace("\n", "\r\n"), "config-queries-pack", "rust", RUST_QUERIES)
        self.assertEqual(out, onboard.insert_pack_line(DEFAULT, "config-queries-pack", "rust", RUST_QUERIES).replace("\n", "\r\n"))

    def test_a_config_without_a_packs_block_is_an_error(self):
        with self.assertRaises(ValueError):
            onboard.insert_pack_line("name: x\n", "config-queries-pack", "rust", RUST_QUERIES)


class Onboard(unittest.TestCase):
    """The state of the Rust pack before the audit suite and the configs were added, end to end."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ccp = Path(self.tmp.name)
        write(self.ccp / "rust/src/qlpack.yml", f"name: {RUST_QUERIES}\nversion: 0.9.2\n")
        write(self.ccp / "rust/src/security/CWE-918/Ssrf.ql", query("path-problem", "security"))
        write(self.ccp / "rust/src/audit/CWE-942/Cors.ql", query("path-problem", "security audit"))
        write(self.ccp / "rust/src/suites/rust.qls", "- queries: '.'\n")
        write(self.ccp / "rust/ext/qlpack.yml", f"name: {RUST_EXT}\nlibrary: true\n")
        write(self.ccp / "rust/ext/manual/iron.model.yml", "extensions: []\n")
        for name, text in (("default.yml", DEFAULT), ("synthetics.yml", SYNTHETICS), ("audit.yml", AUDIT)):
            write(self.ccp / "configs" / name, text, crlf=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_report_names_what_is_missing_and_what_waits_for_the_release(self):
        report = onboard.onboard(self.ccp, ["rust"])
        self.assertFalse(report["ok"])
        self.assertEqual(len(report["languages"]["rust"]["gaps"]), 5)
        self.assertEqual(len(report["after_release"]), 1)
        self.assertEqual(report["applied"], [])

    def test_apply_fixes_what_is_safe_now_and_keeps_the_release_line_for_later(self):
        report = onboard.onboard(self.ccp, ["rust"], apply=True)
        self.assertTrue(report["ok"])
        self.assertEqual(len(report["applied"]), 4)
        self.assertEqual((self.ccp / "rust/src/suites/rust-audit.qls").read_text(), onboard.audit_suite_text("rust"))
        self.assertIn(RUST_QUERIES.encode() + b"\r\n", (self.ccp / "configs/default.yml").read_bytes())
        self.assertNotIn(b"rust", (self.ccp / "configs/audit.yml").read_bytes())
        self.assertEqual(len(report["after_release"]), 1)

    def test_apply_after_the_release_adds_the_audit_line_and_leaves_nothing(self):
        onboard.onboard(self.ccp, ["rust"], apply=True)
        report = onboard.onboard(self.ccp, ["rust"], apply=True, after_release=True)
        self.assertTrue(report["ok"])
        self.assertEqual(report["after_release"], [])
        self.assertIn(b"suites/rust-audit.qls", (self.ccp / "configs/audit.yml").read_bytes())
        self.assertEqual(onboard.onboard(self.ccp, ["rust"])["languages"]["rust"]["gaps"], [])

    def test_every_line_ending_of_an_edited_crlf_config_is_still_crlf(self):
        onboard.onboard(self.ccp, ["rust"], apply=True)
        for name in ("default.yml", "synthetics.yml"):
            data = (self.ccp / "configs" / name).read_bytes()
            self.assertEqual(data.replace(b"\r\n", b"").count(b"\n"), 0, name)

    def test_an_existing_audit_suite_is_not_overwritten(self):
        write(self.ccp / "rust/src/suites/rust-audit.qls", "- description: mine\n")
        onboard.onboard(self.ccp, ["rust"], apply=True)
        self.assertEqual((self.ccp / "rust/src/suites/rust-audit.qls").read_text(), "- description: mine\n")


class Published(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.published = Path(self.tmp.name) / "0.9.2"
        write(self.published / "suites/rust.qls", "- queries: '.'\n")

    def tearDown(self):
        self.tmp.cleanup()

    def root(self, name):
        return self.published if name == RUST_QUERIES else None

    def test_a_suite_that_only_main_has_is_a_problem_for_every_scan_that_names_it(self):
        configs = {"audit.yml": f"packs:\n  - {RUST_QUERIES}:suites/rust-audit.qls\n  - {RUST_QUERIES}:suites/rust.qls\n"}
        problems = onboard.published_problems(self.root, configs)
        self.assertEqual(len(problems), 1)
        self.assertIn("suites/rust-audit.qls", problems[0])
        self.assertIn("0.9.2", problems[0])

    def test_a_pack_that_is_not_published_is_a_problem_and_a_stock_pack_is_not_checked(self):
        configs = {"default.yml": f"packs:\n  - {RUST_QUERIES}\n  - githubsecuritylab/codeql-new-queries\n  - codeql/rust-queries:.\n"}
        problems = onboard.published_problems(self.root, configs)
        self.assertEqual(problems, ["configs/default.yml names githubsecuritylab/codeql-new-queries, which is not published"])

    def test_has_published(self):
        self.assertTrue(onboard.has_published(self.root, RUST_QUERIES, ""))
        self.assertTrue(onboard.has_published(self.root, RUST_QUERIES, "suites/rust.qls"))
        self.assertFalse(onboard.has_published(self.root, RUST_QUERIES, "suites/rust-audit.qls"))
        self.assertFalse(onboard.has_published(self.root, "githubsecuritylab/codeql-new-queries", ""))


class PublishedDownloads(unittest.TestCase):
    def fake(self, published):
        """A stand-in for `codeql pack download <name> --dir <dir>`; `published` maps a pack name to its version."""
        calls = []

        def run(cmd, **kwargs):
            name, target = cmd[3], Path(cmd[5])
            calls.append(name)
            if name in published:
                (target / name / published[name]).mkdir(parents=True)
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 1, "", f"no such pack {name}\n")

        return run, calls

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        onboard.remove_tree(self.dir)

    def test_a_pack_is_downloaded_once_and_an_unpublished_one_says_why(self):
        run, calls = self.fake({RUST_QUERIES: "0.9.2"})
        packs = onboard.PublishedPacks(Path("codeql"), self.dir)
        with mock.patch.object(onboard.subprocess, "run", run):
            self.assertEqual(packs(RUST_QUERIES).name, "0.9.2")
            self.assertEqual(packs(RUST_QUERIES).name, "0.9.2")
            self.assertIsNone(packs("githubsecuritylab/codeql-new-queries"))
        self.assertEqual(calls, [RUST_QUERIES, "githubsecuritylab/codeql-new-queries"])
        self.assertIn("no such pack", packs.errors["githubsecuritylab/codeql-new-queries"])

    def test_prefetch_downloads_every_name_once_and_in_parallel_slots(self):
        names = {RUST_QUERIES, RUST_EXT, "githubsecuritylab/codeql-new-queries"}
        run, calls = self.fake({RUST_QUERIES: "0.9.2", RUST_EXT: "0.9.2"})
        packs = onboard.PublishedPacks(Path("codeql"), self.dir, workers=3)
        with mock.patch.object(onboard.subprocess, "run", run):
            packs.prefetch(names)
            packs.prefetch(names)
            self.assertEqual(sorted(calls), sorted(names))
            self.assertIsNone(packs("githubsecuritylab/codeql-new-queries"))
            self.assertEqual(packs(RUST_EXT).name, "0.9.2")
        self.assertEqual(len(calls), 3)

    def test_the_reason_a_pack_could_not_be_downloaded_is_in_the_problem(self):
        run, _ = self.fake({})
        packs = onboard.PublishedPacks(Path("codeql"), self.dir)
        with mock.patch.object(onboard.subprocess, "run", run):
            problems = onboard.published_problems(packs, {"default.yml": f"packs:\n  - {RUST_QUERIES}\n"})
        self.assertEqual(len(problems), 1)
        self.assertIn("which is not published (no such pack", problems[0])

    def test_remove_tree_deletes_a_path_over_260_characters(self):
        root = self.dir / "download"
        deep = root.joinpath(*["a-long-directory-name-of-a-nested-pack-dependency"] * 7)
        self.assertGreater(len(str(deep)), 300)
        os.makedirs(("\\\\?\\" + str(deep)) if sys.platform == "win32" else deep)
        onboard.remove_tree(root)
        self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
