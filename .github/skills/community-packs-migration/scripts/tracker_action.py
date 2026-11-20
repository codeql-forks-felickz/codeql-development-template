#!/usr/bin/env python3
"""Update the Action column of the tracker issue, and nothing else.

The tracker is an issue whose per-language comments hold tables with the columns
Issue | PR | Labels | Notes | Destination | Action. Each such comment starts with a marker,
``<!-- tracker-language: <language> -->``. The Action column belongs to the maintainer, so this
script changes that one cell, in the rows you name, and leaves every other character of the
comment as it is.

    tracker_action.py show                      the rows that have an Action
    tracker_action.py set 230 "<markdown>"      replace the Action of issue 230
    tracker_action.py refresh                   add the state of every pull request in an Action:
                                                draft, open, merged DATE or closed DATE

``set`` and ``refresh`` print what would change and write nothing unless you add ``--apply``.
The tracker is issue 64 of codeql-forks-felickz/codeql-development-template unless ``--repo``
and ``--issue`` say otherwise. It needs the gh CLI, signed in with access to that repository.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import subprocess
import sys
from typing import Callable

REPO = "codeql-forks-felickz/codeql-development-template"
ISSUE = 64
COLUMNS = 6  # Issue | PR | Labels | Notes | Destination | Action
MARKER = re.compile(r"<!-- tracker-language: ([\w-]+) -->")
PIPE = re.compile(r"(?<!\\)\|")
ISSUE_CELL = re.compile(r"^\[?#(\d+)\b")
# A pull request link in an Action cell, and the state this script wrote after it (marked, so that the
# next refresh replaces it instead of adding another).
PR_LINK = re.compile(
    r"\[([^\]]+)\]\((https://github\.com/([^/\s)]+)/([^/\s)]+)/pull/(\d+))\)"
    r"(?: (?:draft|open|merged \d{4}-\d{2}-\d{2}|closed \d{4}-\d{2}-\d{2})<!--prs-->)?"
)


def gh(*args: str, payload: dict | None = None) -> str:
    cmd = ["gh", *args] + (["--input", "-"] if payload is not None else [])
    proc = subprocess.run(cmd, input=json.dumps(payload) if payload is not None else None,
                          capture_output=True, text=True, encoding="utf-8")
    if proc.returncode:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout


def language_comments(repo: str, issue: int) -> list[dict]:
    out = gh("api", "--paginate", f"repos/{repo}/issues/{issue}/comments", "--jq", ".[] | {id, body}")
    comments = []
    for line in out.splitlines():
        if not line.strip():
            continue
        comment = json.loads(line)
        found = MARKER.search(comment.get("body") or "")
        if found:
            comments.append({"id": comment["id"], "language": found.group(1), "body": comment["body"]})
    return comments


def locate_action(line: str) -> tuple[int, int, int] | None:
    """For a tracker table row: the issue number and the span ``line[start:end]`` of its Action cell.

    The Action is everything after the fifth separator up to the closing pipe, so an unescaped pipe
    inside it does not hide it. Anything that is not a row of that table gives None.
    """
    core = line.rstrip()
    if not (core.startswith("|") and core.endswith("|")):
        return None
    pipes = [m.start() for m in PIPE.finditer(core)]
    if len(pipes) < COLUMNS + 1 or pipes[-1] != len(core) - 1:
        return None
    found = ISSUE_CELL.match(core[pipes[0] + 1:pipes[1]].strip())
    if not found:
        return None
    return int(found.group(1)), pipes[COLUMNS - 1] + 1, pipes[-1]


def escape(text: str) -> str:
    return PIPE.sub(r"\\|", text.strip())


def edit_rows(body: str, change: Callable[[int, str], str | None]) -> tuple[str, list[int]]:
    """Apply ``change(issue, action)`` to every table row of an issue. Returns the new body and the issues changed.

    Only the text of the Action cell is replaced, and only when ``change`` returns something
    different. Every other character, including line endings, is kept.
    """
    out: list[str] = []
    changed: list[int] = []
    for raw in body.splitlines(keepends=True):
        line = raw.rstrip("\r\n")
        ending = raw[len(line):]
        located = locate_action(line)
        if located:
            issue, start, end = located
            action = line[start:end].strip()
            new = change(issue, action)
            if new is not None and new != action:
                line = line[:start] + " " + escape(new) + " " + line[end:]
                changed.append(issue)
        out.append(line + ending)
    return "".join(out), changed


def actions(body: str) -> dict[int, str]:
    found: dict[int, str] = {}
    edit_rows(body, lambda issue, action: found.__setitem__(issue, action))
    return found


def refresh_action(text: str, status_of: Callable[[str, str, str], str | None]) -> str:
    """The Action cell with the current state after each pull request link.

    A link whose state cannot be read is left as it is.
    """
    def repl(match: re.Match) -> str:
        status = status_of(match.group(3), match.group(4), match.group(5))
        link = f"[{match.group(1)}]({match.group(2)})"
        return link + (f" {status}<!--prs-->" if status else match.group(0)[len(link):])
    return PR_LINK.sub(repl, text)


def pr_status(owner: str, repo: str, number: str) -> str | None:
    """'draft', 'open', 'merged YYYY-MM-DD' or 'closed YYYY-MM-DD'. None when GitHub cannot say."""
    try:
        out = gh("api", f"repos/{owner}/{repo}/pulls/{number}", "--jq",
                 '[.state, (.draft | tostring), (.merged_at // ""), (.closed_at // "")] | @tsv')
    except RuntimeError:
        return None
    state, draft, merged, closed = (out.rstrip("\n").split("\t") + ["", "", "", ""])[:4]
    if merged:
        return "merged " + merged[:10]
    if state == "closed":
        return "closed " + closed[:10]
    return "draft" if draft == "true" else "open"


def show_diff(language: str, old: str, new: str) -> None:
    for line in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0):
        if line.startswith(("+++", "---", "@@")):
            continue
        print(f"[{language}] {line}")


def run(args: argparse.Namespace) -> int:
    comments = language_comments(args.repo, args.issue)
    if not comments:
        print(f"no tracker comment (marker '<!-- tracker-language: ... -->') on {args.repo}#{args.issue}", file=sys.stderr)
        return 2

    if args.command == "show":
        for comment in comments:
            for issue, action in sorted(actions(comment["body"]).items()):
                if action:
                    print(f"#{issue} [{comment['language']}] {action}")
        return 0

    cache: dict[tuple[str, str, str], str | None] = {}

    def status_of(owner: str, repo: str, number: str) -> str | None:
        key = (owner, repo, number)
        if key not in cache:
            cache[key] = pr_status(owner, repo, number)
        return cache[key]

    if args.command == "set":
        def change(issue: int, action: str) -> str | None:
            return args.text if issue == args.number else None
    else:
        def change(issue: int, action: str) -> str | None:
            return refresh_action(action, status_of) if action else None

    total = 0
    for comment in comments:
        new_body, changed = edit_rows(comment["body"], change)
        if not changed:
            continue
        total += len(changed)
        show_diff(comment["language"], comment["body"], new_body)
        if args.apply:
            gh("api", "-X", "PATCH", f"repos/{args.repo}/issues/comments/{comment['id']}", payload={"body": new_body})
            print(f"[{comment['language']}] updated comment {comment['id']}")
    if args.command == "set" and not any(args.number in actions(c["body"]) for c in comments):
        print(f"no row for #{args.number} in any language comment", file=sys.stderr)
        return 1
    if not total:
        print("nothing to change")
    elif not args.apply:
        print(f"{total} row(s) would change; add --apply to write them")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=REPO, help="repository that holds the tracker issue")
    parser.add_argument("--issue", type=int, default=ISSUE, help="tracker issue number")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("show", help="the rows that have an Action")
    set_p = sub.add_parser("set", help="replace the Action of one issue")
    set_p.add_argument("number", type=int, help="the gap issue number of the row")
    set_p.add_argument("text", help="the new Action, in Markdown (an empty string clears it)")
    set_p.add_argument("--apply", action="store_true", help="write the change")
    refresh_p = sub.add_parser("refresh", help="add the state of every pull request in an Action")
    refresh_p.add_argument("--apply", action="store_true", help="write the change")
    try:
        return run(parser.parse_args(argv))
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
