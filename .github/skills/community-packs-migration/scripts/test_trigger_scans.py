"""Offline tests for trigger_scans.py: the plan and the calls it would make, with a fake gh."""

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
import trigger_scans as ts  # noqa: E402

REPOS = {
    "alpha": {"setup": {"state": "configured", "languages": ["rust"]}, "branch": "main", "head": "h1", "tree": "t1"},
    "beta": {"setup": {"state": "configured", "languages": ["actions", "c-cpp"]}, "branch": "master", "head": "h2", "tree": "t2"},
    "gamma": {"setup": {"state": "not-configured", "languages": []}, "branch": "main", "head": "h3", "tree": "t3"},
    "delta": {"setup": {"state": "configured", "languages": ["rust"]}, "branch": "main", "head": "h4", "tree": "t4", "archived": True},
    "epsilon": {"setup": {"state": "configured", "languages": ["rust", "actions"]}, "branch": "trunk", "head": "h5", "tree": "t5"},
}


class FakeGh:
    """A gh that answers from REPOS and records every write."""

    def __init__(self, not_fast_forward=()):
        self.writes = []
        self.not_fast_forward = set(not_fast_forward)

    def __call__(self, *args, payload=None):
        if args[1] == "--paginate":
            rows = [{"repository_name": name, "properties": [{"property_name": "Synthetic", "value": "true"}]} for name in REPOS]
            return "\n".join(json.dumps(row) for row in rows)
        if args[1] == "-X":
            method, path = args[2], args[3]
            self.writes.append((method, path, payload))
            name = path.split("/")[2]
            if method == "POST":
                return json.dumps({"sha": f"new-{name}", "committer": {"date": "2026-11-23T23:09:32Z"}})
            if name in self.not_fast_forward:
                raise RuntimeError("gh api failed: HTTP 422 Update is not a fast forward")
            return "{}"
        parts = args[1].split("/")
        repo, tail = REPOS[parts[2]], "/".join(parts[3:])
        if tail == "code-scanning/default-setup":
            return json.dumps(repo["setup"])
        if tail == "":
            return json.dumps({"default_branch": repo["branch"], "archived": repo.get("archived", False)})
        if tail.startswith("git/ref/heads/"):
            return json.dumps({"object": {"sha": repo["head"]}})
        if tail.startswith("git/commits/"):
            return json.dumps({"tree": {"sha": repo["tree"]}})
        raise AssertionError(f"unexpected call {args}")


def run_main(fake, *argv):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(ts, "gh", fake), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ts.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Plan(unittest.TestCase):
    def test_the_plan_lists_the_repositories_with_the_language_and_says_why_it_skips_the_others(self):
        fake = FakeGh()
        code, out, _ = run_main(fake, "--language", "rust", "--verbose")
        self.assertEqual(code, 0)
        self.assertIn("would push alpha (main, head h1;", out)
        self.assertIn("would push epsilon (trunk, head h5;", out)
        self.assertIn("skip beta: default setup does not list rust (it lists actions, c-cpp)", out)
        self.assertIn("skip gamma: default setup is not-configured", out)
        self.assertIn("skip delta: the repository is archived", out)
        self.assertIn("dry run: 2 repositories would get an empty commit", out)
        self.assertEqual(fake.writes, [])

    def test_the_skips_are_summarized_by_reason_unless_verbose(self):
        _, out, _ = run_main(FakeGh(), "--language", "rust")
        self.assertIn("skipped 3: default setup does not list rust (1); default setup is not-configured (1); "
                      "the repository is archived (1) (--verbose lists them)", out)
        self.assertNotIn("skip beta", out)

    def test_without_a_language_every_configured_repository_is_planned(self):
        _, out, _ = run_main(FakeGh())
        self.assertEqual([line.split()[2] for line in out.splitlines() if line.startswith("would push")], ["alpha", "beta", "epsilon"])


class Apply(unittest.TestCase):
    def test_the_commit_keeps_the_tree_has_the_head_as_parent_and_the_branch_is_never_forced(self):
        fake = FakeGh()
        code, out, _ = run_main(fake, "--repo", "alpha", "--apply", "--trailer", "Co-authored-by: A <a@example.com>")
        self.assertEqual(code, 0)
        (post, patch) = fake.writes
        self.assertEqual(post[:2], ("POST", "repos/codeql-forks-felickz/alpha/git/commits"))
        self.assertEqual((post[2]["tree"], post[2]["parents"]), ("t1", ["h1"]))
        self.assertTrue(post[2]["message"].startswith("Trigger a default setup scan\n\n"))
        self.assertTrue(post[2]["message"].endswith("\n\nCo-authored-by: A <a@example.com>\n"))
        self.assertEqual(patch, ("PATCH", "repos/codeql-forks-felickz/alpha/git/refs/heads/main", {"sha": "new-alpha", "force": False}))
        self.assertIn("started 1 of 1 scans, the first commit at 2026-11-23T23:09:32Z", out)

    def test_a_branch_that_moved_fails_that_repository_and_the_others_still_start(self):
        fake = FakeGh(not_fast_forward={"alpha"})
        code, out, _ = run_main(fake, "--language", "rust", "--apply")
        self.assertEqual(code, 1)
        self.assertIn("push alpha (main, head h1; rust) FAILED: gh api failed: HTTP 422", out)
        self.assertIn("push epsilon (trunk, head h5; rust, actions) -> new-eps at 2026-11-23T23:09:32Z", out)
        self.assertIn("started 1 of 2 scans", out)


class Message(unittest.TestCase):
    def test_the_message_is_neutral_ascii_and_trailers_are_checked(self):
        text = ts.commit_message([])
        self.assertTrue(text.isascii())
        self.assertEqual(text.count("\n\n"), 1)
        with self.assertRaises(ValueError):
            ts.commit_message(["nonsense"])
        code, _, err = run_main(FakeGh(), "--repo", "alpha", "--trailer", "nonsense")
        self.assertEqual(code, 2)
        self.assertIn("not a trailer", err)


if __name__ == "__main__":
    unittest.main()
