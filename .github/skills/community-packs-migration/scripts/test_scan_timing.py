"""Offline tests for scan_timing.py: the log parser, the comparison and the attribution, with no network."""

import contextlib
import io
import itertools
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
import scan_timing as st  # noqa: E402

CUT = "2026-11-24T12:00:00Z"
CCP = "githubsecuritylab/codeql-python-queries"


def stamped(lines):
    """A job log from (seconds from the start, text) pairs, each line stamped like the Actions log."""
    out = []
    for offset, text in lines:
        minutes, seconds = divmod(offset, 60)
        out.append(f"2026-11-24T10:{int(minutes):02d}:{seconds:010.7f}Z {text}")
    return "\n".join(out)


LOG = [
    (0.0, "Current runner version: '2.338.2'"),
    (1.0, "##[group]Run actions/checkout@v6"),
    (2.0, "##[group]Run github/codeql-action/init@v4"),
    (3.0, "Using configuration file input from repository property: GitHubSecurityLab/CodeQL-Community-Packs/configs/synthetics.yml@main"),
    (3.5, "[command]/opt/hostedtoolcache/CodeQL/2.27.5/x64/codeql/codeql database init --language=python"),
    (10.0, f"Installed fresh {CCP}@0.9.1"),
    (10.0, "Installed fresh githubsecuritylab/codeql-java-library-sources@0.9.1 (library)"),
    (10.0, "Installed fresh trailofbits/go-queries@0.3.0"),
    (20.0, "##[group]Run github/codeql-action/analyze@v4"),
    (21.0, "##[group]Extracting python"),
    (23.0, "##[group]Finalizing python"),
    (26.0, "##[group]Running queries for python"),
    (27.0, "Recording pack reference codeql/python-queries at /opt/hostedtoolcache/CodeQL/2.27.5/x64/codeql/qlpacks/codeql/python-queries/1.9.1."),
    (27.0, f"Recording pack reference {CCP} at /home/runner/.codeql/packages/{CCP}/0.9.1."),
    (30.0, "[1/4 eval 163ms] Evaluation done; writing results to codeql/python-queries/Diagnostics/ExtractionWarnings.bqrs."),
    (31.0, f"[2/4 eval 1.4s] Evaluation done; writing results to {CCP}/security/CWE-089/SqlInjectionLocal.bqrs."),
    (32.0, "[3/4 eval 2.5s] Evaluation done; writing results to codeql/python-queries/experimental/Security/CWE-022/ZipSlip.bqrs."),
    (95.0, "[4/4 eval 1m8s] Evaluation done; writing results to codeql/python-queries/Security/CWE-079/Jinja2WithoutEscaping.bqrs."),
    (96.0, 'Interpreted pathproblem query "SQL query built from user-controlled sources" (githubsecuritylab/sql-injection) at path '
           f"/home/runner/work/_temp/codeql_databases/python/results/{CCP}/security/CWE-089/SqlInjectionLocal.bqrs."),
    (96.0, 'Interpreted problem query "Arbitrary file access during archive extraction ("Zip Slip")" (py/zipslip) at path '
           "/home/runner/work/_temp/codeql_databases/python/results/codeql/python-queries/experimental/Security/CWE-022/ZipSlip.bqrs."),
    (97.0, "CodeQL scanned 22 out of 22 Python files in this invocation. Check the status page for overall coverage information"),
    (98.0, "##[group]Uploading code scanning results"),
    (99.0, "##[group]Cleaning up databases"),
    (101.0, "##[group]Waiting for processing to finish"),
    (106.0, "Post job cleanup."),
    (108.0, "Post job cleanup."),
]


class Parsers(unittest.TestCase):
    def test_cli_duration_text(self):
        for text, want in (("163ms", 0.163), ("1.4s", 1.4), ("5ms", 0.005), ("1m8s", 68.0), ("2m 5s", 125.0),
                           ("1h2m3s", 3723.0), ("3.5m", 210.0)):
            self.assertEqual(st.parse_duration(text), want, text)
        self.assertIsNone(st.parse_duration("soon"))

    def test_times_with_seven_digit_fractions_and_dates_alone(self):
        self.assertEqual(st.stamp(st.parse_time("2026-11-20T20:44:08.3592955Z")), "2026-11-20T20:44:08Z")
        self.assertEqual(st.normalize_time("2026-11-24"), "2026-11-24T00:00:00Z")
        self.assertEqual(st.normalize_time("2026-11-24T15:00:00Z"), "2026-11-24T15:00:00Z")
        with self.assertRaises(ValueError):
            st.normalize_time("tomorrow")

    def test_an_analyze_job_keeps_its_times_and_main_steps_and_other_jobs_are_dropped(self):
        run = {"id": 7, "name": "Push on main", "event": "dynamic", "created_at": "2026-11-20T20:44:00Z", "head_sha": "abc",
               "tree_id": "t1"}
        step = lambda name, a, b: {"name": name, "started_at": a, "completed_at": b}  # noqa: E731
        job = {"id": 9, "name": "Analyze (python)", "conclusion": "success", "created_at": "2026-11-20T20:44:02Z",
               "started_at": "2026-11-20T20:44:07Z", "completed_at": "2026-11-20T20:45:07Z",
               "steps": [step("Set up job", "2026-11-20T20:44:07Z", "2026-11-20T20:44:08Z"),
                         step("Initialize CodeQL", "2026-11-20T20:44:10Z", "2026-11-20T20:44:35Z"),
                         step("Post Initialize CodeQL", "2026-11-20T20:45:01Z", "2026-11-20T20:45:02Z"),
                         step("Perform CodeQL Analysis", "2026-11-20T20:44:35Z", "2026-11-20T20:45:03Z"),
                         step("Skipped step", None, None)]}
        record = st.job_record("repo", run, job)
        self.assertEqual((record["language"], record["duration_s"], record["queued_s"]), ("python", 60.0, 5.0))
        self.assertEqual(record["steps"], {"Initialize CodeQL": 25.0, "Perform CodeQL Analysis": 28.0})
        self.assertEqual((record["head_sha"], record["tree_id"]), ("abc", "t1"))
        self.assertIsNone(st.job_record("repo", run, {**job, "name": "Code Quality"}))


class LogSummary(unittest.TestCase):
    def setUp(self):
        self.summary = st.summarize_log(stamped(LOG))

    def test_a_phase_lasts_until_the_next_marker(self):
        self.assertEqual(self.summary["phases"], {
            "setup": 2.0, "init": 18.0, "analyze": 1.0, "extract": 2.0, "finalize": 3.0, "queries": 72.0,
            "upload": 1.0, "cleanup": 2.0, "processing": 5.0, "post": 2.0})
        self.assertEqual(self.summary["total_s"], 108.0)

    def test_packs_config_bundle_and_files(self):
        s = self.summary
        self.assertEqual(s["config"], "GitHubSecurityLab/CodeQL-Community-Packs/configs/synthetics.yml@main")
        # the only lines with the bundle start with "[command]" or "Recording pack reference"
        self.assertEqual(s["bundle"], "2.27.5")
        self.assertEqual(s["installed"], {CCP: "0.9.1", "githubsecuritylab/codeql-java-library-sources": "0.9.1",
                                          "trailofbits/go-queries": "0.3.0"})
        self.assertEqual(s["used"], {"codeql/python-queries": "1.9.1", CCP: "0.9.1"})
        self.assertEqual(st.ccp_version(s), "0.9.1")
        self.assertEqual(s["files"], [22, 22])
        self.assertFalse(s["config_ignored"])

    def test_every_query_has_its_evaluation_time_and_rule_id(self):
        queries = {q["path"]: q for q in self.summary["queries"]}
        self.assertEqual(len(queries), 4)
        self.assertEqual(queries["codeql/python-queries/Diagnostics/ExtractionWarnings"]["eval_s"], 0.163)
        sql = queries[f"{CCP}/security/CWE-089/SqlInjectionLocal"]
        self.assertEqual((sql["eval_s"], sql["rule"]), (1.4, "githubsecuritylab/sql-injection"))
        self.assertEqual(queries["codeql/python-queries/Security/CWE-079/Jinja2WithoutEscaping"]["eval_s"], 68.0)
        # the query name has quotes and parentheses, and the rule id is the last parenthesis before "at path"
        self.assertEqual(queries["codeql/python-queries/experimental/Security/CWE-022/ZipSlip"]["rule"], "py/zipslip")

    def test_a_byte_order_mark_and_windows_line_endings_change_nothing(self):
        text = "\ufeff" + stamped(LOG).replace("\n", "\r\n")
        self.assertEqual(st.summarize_log(text), self.summary)

    def test_the_bundle_version_is_read_from_a_command_line(self):
        text = stamped([(0.0, "start"), (1.0, "[command]/opt/hostedtoolcache/CodeQL/2.27.5/x64/codeql/codeql database init")])
        self.assertEqual(st.summarize_log(text)["bundle"], "2.27.5")

    def test_the_bundle_version_and_kind_come_from_the_setup_lines_not_from_a_deleted_old_version(self):
        text = stamped([
            (0.0, "start"),
            (1.0, "Selected the per-language CodeQL bundle for 'python'."),
            (2.0, "Using CodeQL CLI version 2.27.4 sourced from https://github.com/github/codeql-action/releases/download/"
                  "codeql-bundle-v2.27.4/codeql-bundle-python-linux64.tar.zst ."),
            (3.0, "Deleted the CodeQL tools at '/opt/hostedtoolcache/CodeQL/2.27.3' from the toolcache to free up disk space."),
            (4.0, "[command]/home/runner/work/_temp/abc/codeql/codeql database init")])
        summary = st.summarize_log(text)
        self.assertEqual((summary["bundle"], summary["bundle_kind"]), ("2.27.4", "per-language"))
        deleted = [(0.0, "start"), (1.0, "Deleted the CodeQL tools at '/opt/hostedtoolcache/CodeQL/2.27.3' from the toolcache")]
        self.assertIsNone(st.summarize_log(stamped(deleted))["bundle"])
        self.assertEqual(self.summary["bundle_kind"], "full")

    def test_an_ignored_configuration_file_is_reported(self):
        text = stamped([(0.0, "start"), (1.0, "##[warning]Ignoring configuration file input from repository property: x@main")])
        self.assertTrue(st.summarize_log(text)["config_ignored"])
        text = stamped([(0.0, "start"), (1.0, "##[warning]Both a config file and config input were provided. Ignoring config file.")])
        self.assertTrue(st.summarize_log(text)["config_ignored"])


_ids = itertools.count(1)


def job(repo, language, created, duration, version=None, conclusion="success", steps=None, sha="aaa1111"):
    record = {"repo": repo, "language": language, "run_created_at": created, "duration_s": duration, "conclusion": conclusion,
              "job_id": next(_ids), "head_sha": sha, "steps": steps or {}}
    if version:
        record["log"] = {"used": {CCP: version}, "installed": {}, "queries": [], "phases": {}, "config": "cfg",
                         "config_ignored": False, "bundle": None, "files": None}
    return record


class Compare(unittest.TestCase):
    def test_a_pair_is_flagged_only_when_the_ratio_and_the_difference_are_both_large(self):
        jobs = [job("big", "java-kotlin", "2026-11-23T10:00:00Z", 100.0), job("big", "java-kotlin", "2026-11-25T10:00:00Z", 200.0),
                job("small", "python", "2026-11-23T10:00:00Z", 40.0), job("small", "python", "2026-11-25T10:00:00Z", 80.0),
                job("mild", "go", "2026-11-23T10:00:00Z", 200.0), job("mild", "go", "2026-11-25T10:00:00Z", 250.0)]
        result = st.compare_jobs(jobs, CUT, None)
        self.assertEqual({p["repo"]: p["flagged"] for p in result["pairs"]}, {"big": True, "small": False, "mild": False})
        big = next(p for p in result["pairs"] if p["repo"] == "big")
        self.assertEqual((big["before_s"], big["after_s"], big["delta_s"], big["ratio"]), (100.0, 200.0, 100.0, 2.0))

    def test_the_median_covers_the_newest_jobs_before_and_the_first_jobs_after(self):
        before = [job("r", "python", f"2026-11-{d:02d}T10:00:00Z", s) for d, s in ((1, 900.0), (20, 50.0), (21, 100.0), (22, 60.0))]
        after = [job("r", "python", f"2026-11-{d:02d}T10:00:00Z", s) for d, s in ((25, 90.0), (26, 100.0), (27, 80.0), (28, 5000.0))]
        pair = st.compare_jobs(before + after, CUT, None, keep=3)["pairs"][0]
        self.assertEqual((pair["before_s"], pair["after_s"]), (60.0, 90.0))

    def test_after_jobs_on_an_older_pack_are_left_out_and_counted(self):
        jobs = [job("r", "python", "2026-11-23T10:00:00Z", 100.0, version="0.9.1"),
                job("r", "python", "2026-11-25T10:00:00Z", 100.0, version="0.9.1"),
                job("r", "python", "2026-11-26T10:00:00Z", 300.0, version="0.9.2"),
                job("r", "python", "2026-11-27T10:00:00Z", 310.0)]
        result = st.compare_jobs(jobs, CUT, "0.9.2", keep=3)
        self.assertEqual(result["pairs"][0]["after_s"], 305.0)
        self.assertEqual(result["not_compared"], {"after job still on an older pack": 1,
                                                  "after job without a log summary (pack not verified)": 1})

    def test_a_pair_that_never_used_the_new_pack_is_not_compared(self):
        jobs = [job("r", "python", "2026-11-23T10:00:00Z", 100.0), job("r", "python", "2026-11-25T10:00:00Z", 100.0, version="0.9.1")]
        result = st.compare_jobs(jobs, CUT, "0.9.2")
        self.assertEqual(result["pairs"], [])
        self.assertEqual(result["not_compared"], {"after job still on an older pack": 1,
                                                  "pair without a job on each side of the cutoff": 1})

    def test_failed_jobs_and_jobs_before_since_are_ignored(self):
        jobs = [job("r", "python", "2026-11-01T10:00:00Z", 10.0), job("r", "python", "2026-11-22T10:00:00Z", 100.0),
                job("r", "python", "2026-11-23T10:00:00Z", 1.0, conclusion="failure"), job("r", "python", "2026-11-25T10:00:00Z", 100.0)]
        pair = st.compare_jobs(jobs, CUT, None, since="2026-11-20T00:00:00Z")["pairs"][0]
        self.assertEqual(pair["before_s"], 100.0)

    def test_the_step_that_got_longer_is_named(self):
        jobs = [job("r", "python", "2026-11-23T10:00:00Z", 60.0, steps={"Initialize CodeQL": 10.0, "Perform CodeQL Analysis": 40.0}),
                job("r", "python", "2026-11-25T10:00:00Z", 80.0, steps={"Initialize CodeQL": 30.0, "Perform CodeQL Analysis": 45.0})]
        steps = st.compare_jobs(jobs, CUT, None)["pairs"][0]["steps"]
        self.assertEqual(steps, {"Initialize CodeQL": 20.0, "Autobuild": None, "Perform CodeQL Analysis": 5.0})


BASE = {"setup": 2.0, "init": 20.0, "analyze": 1.0, "extract": 2.0, "finalize": 3.0, "queries": 20.0,
        "upload": 1.0, "cleanup": 2.0, "processing": 5.0, "post": 2.0}
STOCK = [("codeql/python-queries/Security/A", 1.0, "py/a"), ("codeql/python-queries/Security/B", 2.0, "py/b")]
OURS = (f"{CCP}/security/CWE-001/Ours", "githubsecuritylab/ours")
OTHER = (f"{CCP}/security/CWE-002/Other", "githubsecuritylab/other")


def attribution(after_phases=None, before_q=STOCK, after_q=STOCK, bundle=("2.27.5", "2.27.5"), tree=("t", "t"),
                files=((22, 22), (22, 22)), ours=(), packs=(0, 0), kind=("full", "full")):
    phases = {**BASE, **(after_phases or {})}

    def log(p, queries, bundle_version, scanned, bundle_kind, installed):
        return {"queries": [{"path": path, "eval_s": seconds, "rule": rule} for path, seconds, rule in queries], "phases": p,
                "bundle": bundle_version, "bundle_kind": bundle_kind, "files": list(scanned), "used": {CCP: "0.9.1"},
                "installed": {f"p{i}/q": "1" for i in range(installed)}, "config": "cfg"}

    # every scan starts with an empty commit, so the commits always differ and only the tree says whether the code did
    before_job = {"repo": "r", "language": "python", "job_id": 1, "head_sha": "c1", "tree_id": tree[0], "duration_s": sum(BASE.values())}
    after_job = {"repo": "r", "language": "python", "job_id": 2, "head_sha": "c2", "tree_id": tree[1], "duration_s": sum(phases.values())}
    return st.attribute(before_job, after_job, log(BASE, before_q, bundle[0], files[0], kind[0], packs[0]),
                        log(phases, after_q, bundle[1], files[1], kind[1], packs[1]), list(ours), 5)


class Explain(unittest.TestCase):
    def test_new_queries_of_yours_are_named_as_the_cause(self):
        new = [(OURS[0], 70.0, OURS[1]), (OTHER[0], 20.0, OTHER[1]), ("codeql/python-queries/Security/New", 3.0, "py/new")]
        e = attribution({"queries": 120.0}, after_q=STOCK + new, ours=[OURS[1]])
        q = e["queries"]
        self.assertEqual((e["delta_s"], e["verdict"]["code"]), (100.0, "new_queries"))
        self.assertEqual((q["new_ours_s"], q["new_ccp_s"], q["new_other_s"]), (70.0, 20.0, 3.0))
        self.assertTrue(q["new"][0]["ours"])
        self.assertIn("mostly the new query you are verifying", e["verdict"]["text"])
        self.assertIn("are 100% of the extra evaluation time", e["verdict"]["text"])
        self.assertNotIn("Caution", e["verdict"]["text"])
        # the Community Packs queries before and after, whoever they belong to
        self.assertEqual((q["ccp_before_count"], q["ccp_after_count"], q["ccp_before_s"], q["ccp_after_s"]), (0, 2, 0.0, 90.0))

    def test_summed_evaluation_times_that_dwarf_the_phase_come_with_a_caution(self):
        waiting = [(f"{CCP}/security/CWE-00{i}/Q{i}", 500.0, f"githubsecuritylab/q{i}") for i in range(4)]
        e = attribution({"queries": 120.0}, after_q=STOCK + waiting)
        self.assertEqual(e["verdict"]["code"], "new_queries")
        self.assertEqual(e["queries"]["overlap"], round(2003.0 / 120.0, 1))
        self.assertIn("Caution: the summed evaluation time is 17 times the query phase", e["verdict"]["text"])

    def test_other_new_community_packs_queries_are_not_blamed_on_yours(self):
        new = [(OURS[0], 5.0, OURS[1]), (OTHER[0], 80.0, OTHER[1])]
        e = attribution({"queries": 120.0}, after_q=STOCK + new, ours=[OURS[1]])
        self.assertEqual(e["verdict"]["code"], "new_queries")
        self.assertIn("mostly other new Community Packs queries, not yours", e["verdict"]["text"])

    def test_queries_that_got_slower_are_told_apart_from_new_ones(self):
        slower = [("codeql/python-queries/Security/A", 31.0, "py/a"), ("codeql/python-queries/Security/B", 32.0, "py/b"),
                  ("codeql/python-queries/Security/New", 1.0, "py/new")]
        e = attribution({"queries": 120.0}, after_q=slower)
        self.assertEqual(e["verdict"]["code"], "slower_queries")
        self.assertEqual(e["queries"]["grown_s"], 60.0)
        self.assertIn("same bundle", e["verdict"]["text"])
        self.assertIn("are 98% of the extra evaluation time", e["verdict"]["text"])
        e = attribution({"queries": 120.0}, after_q=slower, bundle=("2.27.5", "2.28.0"))
        self.assertIn("CodeQL bundle changed from 2.27.5 to 2.28.0", e["verdict"]["text"])

    def test_a_longer_database_build_is_the_repository_only_when_the_repository_changed(self):
        self.assertEqual(attribution({"extract": 52.0}, tree=("t1", "t2"))["verdict"]["code"], "repository")
        self.assertEqual(attribution({"extract": 52.0}, files=((22, 22), (40, 40)))["verdict"]["code"], "repository")
        # a new commit with the same tree (the empty commit that starts a scan) is not a change of the code
        same_tree = attribution({"extract": 52.0})
        self.assertNotEqual(same_tree["commit"][0], same_tree["commit"][1])
        self.assertEqual(same_tree["verdict"]["code"], "database_variance")

    def test_setup_and_result_processing_are_their_own_causes(self):
        e = attribution({"init": 60.0}, bundle=("2.27.4", "2.27.5"), kind=("per-language", "full"), packs=(0, 16))
        self.assertEqual(e["verdict"]["code"], "setup")
        self.assertIn("bundle 2.27.4 -> 2.27.5, per-language -> full bundle, 0 -> 16 packs installed", e["verdict"]["text"])
        self.assertEqual(attribution({"processing": 45.0})["verdict"]["code"], "results")

    def test_an_increase_without_a_dominant_phase_lists_what_moved(self):
        e = attribution({"init": 40.0, "extract": 22.0, "queries": 40.0, "processing": 25.0})
        self.assertEqual(e["verdict"]["code"], "spread")
        self.assertIn("setup +20 s", e["verdict"]["text"])
        self.assertIn("queries +20 s", e["verdict"]["text"])

    def test_a_job_that_is_not_slower_has_nothing_to_explain(self):
        self.assertEqual(attribution({"queries": 10.0})["verdict"]["code"], "not_slower")

    def test_a_log_without_query_lines_says_so(self):
        e = attribution({"queries": 120.0}, before_q=(), after_q=())
        self.assertEqual(e["verdict"]["code"], "queries")
        self.assertIn("no per-query evaluation lines", e["verdict"]["text"])

    def test_removed_and_new_queries_are_listed_by_evaluation_time(self):
        changes = st.query_changes([{"path": "p/x/A", "eval_s": 4.0}, {"path": "p/x/Gone", "eval_s": 9.0}],
                                   [{"path": "p/x/A", "eval_s": 7.0}, {"path": "p/x/New", "eval_s": 2.0}], [], 5)
        self.assertEqual([e["path"] for e in changes["new"]], ["p/x/New"])
        self.assertEqual([e["path"] for e in changes["removed"]], ["p/x/Gone"])
        self.assertEqual(changes["grown"], [{"path": "p/x/A", "before_s": 4.0, "after_s": 7.0, "delta_s": 3.0}])

    def test_ours_matches_a_rule_a_path_a_file_name_or_the_end_of_a_path(self):
        query = {"path": f"{CCP}/security/CWE-001/Ours", "rule": "githubsecuritylab/ours"}
        for token in ("githubsecuritylab/ours", f"{CCP}/security/CWE-001/Ours", "Ours", "CWE-001/Ours"):
            self.assertTrue(st.is_ours(query, [token]), token)
        self.assertFalse(st.is_ours(query, ["Other", "ours"]))

    def test_the_closest_pair_is_the_newest_job_before_and_the_first_one_after_on_the_version(self):
        group = [job("r", "python", "2026-11-20T10:00:00Z", 50.0), job("r", "python", "2026-11-23T10:00:00Z", 60.0),
                 job("r", "python", "2026-11-25T10:00:00Z", 70.0, version="0.9.1"), job("r", "python", "2026-11-26T10:00:00Z", 80.0, version="0.9.2")]
        before, after = st.closest_pair(group, CUT, "0.9.2")
        self.assertEqual((before["duration_s"], after["duration_s"]), (60.0, 80.0))
        self.assertIsNone(st.closest_pair(group[:2], CUT, None))


class Packs(unittest.TestCase):
    def test_the_state_of_a_pair_says_why_it_is_not_on_the_version(self):
        newest = {"run_created_at": "2026-11-25T10:00:00Z", "conclusion": "failure"}
        self.assertEqual(st.pack_state(None, newest, "0.9.2")[0], "no_success")
        self.assertEqual(st.pack_state({"job_id": 1}, newest, "0.9.2")[0], "no_log")
        self.assertEqual(st.pack_state(job("r", "python", "2026-11-25T10:00:00Z", 1.0, version="0.9.2"), newest, "0.9.2"), ("ok", ""))
        self.assertEqual(st.pack_state(job("r", "python", "2026-11-25T10:00:00Z", 1.0, version="0.9.1"), newest, "0.9.2"),
                         ("old_pack", "uses 0.9.1, wanted 0.9.2"))
        bare = job("r", "python", "2026-11-25T10:00:00Z", 1.0, version="0.9.2")
        bare["log"]["used"] = {}
        self.assertEqual(st.pack_state(bare, newest, "0.9.2")[0], "no_pack")
        bare["log"]["used"], bare["log"]["config_ignored"] = {CCP: "0.9.2"}, True
        self.assertEqual(st.pack_state(bare, newest, "0.9.2")[0], "config_ignored")


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = st.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CommandLine(unittest.TestCase):
    def write(self, jobs, name="jobs.json"):
        path = Path(self.tmp.name) / name
        path.write_text(json.dumps({"org": "o", "jobs": jobs}), encoding="utf-8")
        return str(path)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # packs asks GitHub which languages a repository still has; here it cannot tell
        patcher = mock.patch.object(st, "configured_languages", return_value=None)
        self.configured = patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def test_compare_exits_1_for_a_flagged_pair_and_0_when_nothing_changed(self):
        slow = self.write([job("r", "java-kotlin", "2026-11-23T10:00:00Z", 100.0), job("r", "java-kotlin", "2026-11-25T10:00:00Z", 300.0)])
        code, out, _ = run_main("compare", "--jobs", slow, "--cutoff", CUT)
        self.assertEqual(code, 1)
        self.assertIn("flagged (at least 1.5 times as long and 60 s longer): 1", out)
        steady = self.write([job("r", "java-kotlin", "2026-11-23T10:00:00Z", 100.0), job("r", "java-kotlin", "2026-11-25T10:00:00Z", 110.0)], "b.json")
        code, out, _ = run_main("compare", "--jobs", steady, "--cutoff", CUT)
        self.assertEqual(code, 0)
        self.assertIn("no massive change", out)

    def test_two_collect_files_are_merged_and_the_job_with_a_log_summary_wins(self):
        a = job("r", "python", "2026-11-25T10:00:00Z", 100.0)
        b = dict(job("r", "python", "2026-11-25T10:00:00Z", 100.0, version="0.9.2"), job_id=a["job_id"])
        _, jobs = st.load_jobs([self.write([a], "a.json"), self.write([b], "b.json")])
        self.assertEqual(len(jobs), 1)
        self.assertIn("log", jobs[0])

    def test_packs_exits_1_while_a_pair_is_on_the_old_version(self):
        path = self.write([job("r", "python", "2026-11-25T10:00:00Z", 100.0, version="0.9.1"),
                           job("s", "python", "2026-11-25T10:00:00Z", 100.0, version="0.9.2")])
        code, out, _ = run_main("packs", "--jobs", path, "--version", "0.9.2")
        self.assertEqual(code, 1)
        self.assertIn("not on 0.9.2: r python", out)
        self.assertNotIn("not on 0.9.2: s python", out)
        self.assertEqual(run_main("packs", "--jobs", path, "--version", "0.9.1")[0], 1)

    def test_a_pair_that_has_not_scanned_since_the_release_is_not_using_the_pack(self):
        path = self.write([job("r", "python", "2026-11-23T10:00:00Z", 100.0, version="0.9.1"),
                           job("s", "python", "2026-11-25T10:00:00Z", 100.0, version="0.9.2")])
        code, out, _ = run_main("packs", "--jobs", path, "--version", "0.9.2", "--since", CUT)
        self.assertEqual(code, 1)
        self.assertIn("not on 0.9.2: r python: no scan since 2026-11-24T12:00:00Z", out)
        self.assertNotIn("not on 0.9.2: s python", out)
        only_new = self.write([job("s", "python", "2026-11-25T10:00:00Z", 100.0, version="0.9.2")], "c.json")
        self.assertEqual(run_main("packs", "--jobs", only_new, "--version", "0.9.2", "--since", CUT)[0], 0)

    def test_a_language_that_default_setup_no_longer_has_is_ignored_not_a_failure(self):
        path = self.write([job("r", "python", "2026-11-23T10:00:00Z", 100.0, version="0.9.1"),
                           job("s", "python", "2026-11-25T10:00:00Z", 100.0, version="0.9.2")])
        self.configured.return_value = set()
        code, out, _ = run_main("packs", "--jobs", path, "--version", "0.9.2", "--since", CUT)
        self.assertEqual(code, 0)
        self.assertIn("ignored, no longer in default setup: r python", out)
        self.configured.return_value = {"python"}
        self.assertEqual(run_main("packs", "--jobs", path, "--version", "0.9.2", "--since", CUT)[0], 1)

    def test_a_bad_cutoff_is_an_error_not_a_traceback(self):
        path = self.write([job("r", "python", "2026-11-25T10:00:00Z", 100.0)])
        code, _, err = run_main("compare", "--jobs", path, "--cutoff", "tomorrow")
        self.assertEqual(code, 2)
        self.assertIn("not a UTC ISO 8601 time", err)


if __name__ == "__main__":
    unittest.main()
