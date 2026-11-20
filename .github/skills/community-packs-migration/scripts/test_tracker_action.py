"""Offline tests for tracker_action.py: only the Action cell may change, and nothing else."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tracker_action as ta  # noqa: E402

HEADER = ["<!-- tracker-language: actions -->", "### Create", "",
          "| Issue | PR | Labels | Notes | Destination | Action |", "|---|---|---|---|---|---|"]
ROW_230 = "| #230 | #234 | precision:medium | note one<!--g:aaaaaaaa--> | Community Packs<!--g:bbbbbbbb--> |  |"
ROW_231 = ("| #231 | #235 | precision:high | a \\| b | github/codeql | "
           "[o/r#1](https://github.com/o/r/pull/1) draft<!--prs--> |")
ROW_232 = "| [#232](https://github.com/o/t/issues/232) | #236 | x | y | z | free text with a | pipe |"


def body(eol: str = "\n") -> str:
    return eol.join(HEADER + [ROW_230, ROW_231, ROW_232, "", "trailing text"]) + eol


class EditRows(unittest.TestCase):
    def test_set_changes_one_cell_and_nothing_else(self):
        link = "[o/r#2](https://github.com/o/r/pull/2)"
        new, changed = ta.edit_rows(body(), lambda issue, action: link if issue == 230 else None)
        self.assertEqual(changed, [230])
        old_lines, new_lines = body().split("\n"), new.split("\n")
        self.assertEqual(len(old_lines), len(new_lines))
        differing = [i for i, (a, b) in enumerate(zip(old_lines, new_lines)) if a != b]
        self.assertEqual(differing, [HEADER.__len__()])
        self.assertEqual(new_lines[len(HEADER)],
                         "| #230 | #234 | precision:medium | note one<!--g:aaaaaaaa--> | Community Packs<!--g:bbbbbbbb--> | " + link + " |")

    def test_crlf_line_endings_are_kept(self):
        new, changed = ta.edit_rows(body("\r\n"), lambda issue, action: "done" if issue == 231 else None)
        self.assertEqual(changed, [231])
        self.assertNotIn("\n", new.replace("\r\n", ""))
        self.assertEqual(new.count("\r\n"), body("\r\n").count("\r\n"))

    def test_stray_pipes_are_escaped_and_existing_escapes_survive(self):
        new, _ = ta.edit_rows(body(), lambda issue, action: "a|b" if issue == 230 else None)
        self.assertIn("| a\\|b |", new)
        self.assertIn("a \\| b", new)  # the Notes cell of #231 was not touched

    def test_an_action_with_an_unescaped_pipe_is_read_whole(self):
        self.assertEqual(ta.actions(body())[232], "free text with a | pipe")

    def test_a_missing_issue_changes_nothing(self):
        new, changed = ta.edit_rows(body(), lambda issue, action: "x" if issue == 999 else None)
        self.assertEqual((new, changed), (body(), []))

    def test_clearing_an_action(self):
        new, changed = ta.edit_rows(body(), lambda issue, action: "" if issue == 231 else None)
        self.assertEqual(changed, [231])
        self.assertIn("| github/codeql |  |", new)


class Refresh(unittest.TestCase):
    LINK = "[o/r#1](https://github.com/o/r/pull/1)"

    def test_state_replaces_the_marked_state(self):
        text = self.LINK + " draft<!--prs-->"
        self.assertEqual(ta.refresh_action(text, lambda *_: "merged 2026-11-19"),
                         self.LINK + " merged 2026-11-19<!--prs-->")

    def test_state_is_added_after_a_bare_link_and_is_idempotent(self):
        once = ta.refresh_action(self.LINK, lambda *_: "open")
        self.assertEqual(once, self.LINK + " open<!--prs-->")
        self.assertEqual(ta.refresh_action(once, lambda *_: "open"), once)

    def test_unreadable_state_leaves_the_cell_alone(self):
        text = self.LINK + " draft<!--prs--> and more"
        self.assertEqual(ta.refresh_action(text, lambda *_: None), text)

    def test_several_links_are_each_resolved(self):
        text = self.LINK + " and [a/b#2](https://github.com/a/b/pull/2)"
        states = {("o", "r", "1"): "merged 2026-11-18", ("a", "b", "2"): "open"}
        out = ta.refresh_action(text, lambda owner, repo, number: states[(owner, repo, number)])
        self.assertEqual(out, self.LINK + " merged 2026-11-18<!--prs--> and [a/b#2](https://github.com/a/b/pull/2) open<!--prs-->")

    def test_refresh_through_edit_rows_touches_only_rows_with_links(self):
        new, changed = ta.edit_rows(body(), lambda issue, action: ta.refresh_action(action, lambda *_: "merged 2026-11-19") if action else None)
        self.assertEqual(changed, [231])
        self.assertIn("merged 2026-11-19<!--prs-->", new)


if __name__ == "__main__":
    unittest.main()
