#!/usr/bin/env python3
"""Start a code scanning run in repositories by pushing an empty commit to their default branch.

A dynamic default setup run cannot be re-run, and it starts on a push to the default branch (verify-detection.md,
sections 5 and 7). An empty commit does it without a clone: it has the tree of the head commit and the head as its
parent, so the code does not change. The branch is fast-forwarded and never forced, so a branch that moved after the
plan makes that repository fail and leaves it alone.

    trigger_scans.py --property Synthetic=true --language rust            # the plan, nothing is written
    trigger_scans.py --property Synthetic=true --language rust --apply    # starts the scans
    trigger_scans.py --repo NAME [--repo NAME] --apply --trailer "Co-authored-by: Name <mail>"

A repository is planned when its default setup is configured and, with --language, lists that language. The
repository is skipped otherwise, with the reason. With --apply it prints the time of the first commit, which is what
`scan_timing.py compare --cutoff` and `packs --since` take. Without --apply it writes nothing. It needs the gh CLI
with write access to the contents of the repositories. The defaults name codeql-forks-felickz.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import re
import subprocess
import sys

ORG = "codeql-forks-felickz"
DEFAULT_PROPERTY = "Synthetic=true"
SUBJECT = "Trigger a default setup scan"
BODY = "Empty commit that starts a CodeQL default setup run with the configuration of the github-codeql-config-file repository property."
TRAILER_RE = re.compile(r"^[A-Za-z][\w-]*: \S.*$")


def gh(*args: str, payload: dict | None = None) -> str:
    cmd = ["gh", *args] + (["--input", "-"] if payload is not None else [])
    proc = subprocess.run(cmd, input=json.dumps(payload) if payload is not None else None, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    if proc.returncode:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {(proc.stderr or proc.stdout).strip()[:300]}")
    return proc.stdout


def gh_json(path: str):
    return json.loads(gh("api", path))


def commit_message(trailers: list[str]) -> str:
    """The message of the empty commit: a neutral subject and body, then the trailers you give."""
    for trailer in trailers:
        if not TRAILER_RE.match(trailer):
            raise ValueError(f"not a trailer (Key: value): {trailer!r}")
    return f"{SUBJECT}\n\n{BODY}\n" + ("\n" + "\n".join(trailers) + "\n" if trailers else "")


def repositories(args: argparse.Namespace) -> list[str]:
    if args.repo:
        return sorted(set(args.repo))
    name, _, value = args.property.partition("=")
    out = gh("api", "--paginate", f"orgs/{args.org}/properties/values?per_page=100", "--jq", ".[]")
    rows = [json.loads(line) for line in out.splitlines() if line.strip()]
    return sorted(r["repository_name"] for r in rows
                  if any(p["property_name"] == name and p["value"] == value for p in r.get("properties") or []))


def plan_repository(org: str, repo: str, language: str | None) -> dict:
    """What to push to one repository, or why it is skipped."""
    item = {"repo": repo, "skip": None}
    try:
        setup = gh_json(f"repos/{org}/{repo}/code-scanning/default-setup")
        languages = setup.get("languages") or []
        info = gh_json(f"repos/{org}/{repo}")
        item.update({"languages": languages, "branch": info["default_branch"]})
        if info.get("archived"):
            item["skip"] = "the repository is archived"
        elif setup.get("state") != "configured":
            item["skip"] = f"default setup is {setup.get('state')}"
        elif language and language not in languages:
            item["skip"] = f"default setup does not list {language} (it lists {', '.join(languages) or 'nothing'})"
        else:
            head = gh_json(f"repos/{org}/{repo}/git/ref/heads/{info['default_branch']}")["object"]["sha"]
            item.update({"head": head, "tree": gh_json(f"repos/{org}/{repo}/git/commits/{head}")["tree"]["sha"]})
    except RuntimeError as exc:
        item["skip"] = str(exc)
    return item


def start_scan(org: str, item: dict, message: str) -> dict:
    """Make the empty commit and fast-forward the default branch to it."""
    created = json.loads(gh("api", "-X", "POST", f"repos/{org}/{item['repo']}/git/commits",
                            payload={"message": message, "tree": item["tree"], "parents": [item["head"]]}))
    gh("api", "-X", "PATCH", f"repos/{org}/{item['repo']}/git/refs/heads/{item['branch']}",
       payload={"sha": created["sha"], "force": False})
    return {"commit": created["sha"], "at": created["committer"]["date"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--org", default=ORG)
    parser.add_argument("--property", default=DEFAULT_PROPERTY, help="NAME=VALUE: the repositories with this custom property value")
    parser.add_argument("--repo", action="append", default=[], help="a repository name; repeatable, instead of --property")
    parser.add_argument("--language", help="only repositories whose default setup lists this language, for example rust")
    parser.add_argument("--trailer", action="append", default=[], help="a commit message trailer, `Key: value`; repeatable")
    parser.add_argument("--apply", action="store_true", help="push the commits (default: print the plan)")
    parser.add_argument("--verbose", action="store_true", help="list every skipped repository, not a summary of the reasons")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        message = commit_message(args.trailer)
        repos = repositories(args)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            plan = list(pool.map(lambda r: plan_repository(args.org, r, args.language), repos))
        todo = [p for p in plan if not p["skip"]]
        results: dict[str, dict] = {}
        if args.apply:
            def run(item: dict) -> tuple[str, dict]:
                try:
                    return item["repo"], start_scan(args.org, item, message)
                except RuntimeError as exc:
                    return item["repo"], {"error": str(exc)}
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
                results = dict(pool.map(run, todo))
    except (RuntimeError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 2
    failed = [r for r, v in results.items() if "error" in v]
    if args.json:
        print(json.dumps({"applied": args.apply, "plan": plan, "results": results}, indent=1))
        return 1 if failed else 0
    for item in plan:
        if item["skip"]:
            if args.verbose:
                print(f"skip {item['repo']}: {item['skip']}")
        else:
            outcome = results.get(item["repo"])
            tail = ("" if outcome is None else f" -> {outcome['commit'][:7]} at {outcome['at']}" if "commit" in outcome
                    else f" FAILED: {outcome['error']}")
            print(f"{'push' if args.apply else 'would push'} {item['repo']} ({item['branch']}, head {item['head'][:7]}; "
                  f"{', '.join(item['languages'])}){tail}")
    skipped = [p for p in plan if p["skip"]]
    if skipped and not args.verbose:
        reasons = collections.Counter(p["skip"].split(" (it lists")[0] for p in skipped)
        print(f"skipped {len(skipped)}: " + "; ".join(f"{why} ({n})" for why, n in sorted(reasons.items())) + " (--verbose lists them)")
    if not args.apply:
        print(f"dry run: {len(todo)} repositories would get an empty commit; add --apply to start their scans")
    else:
        times = sorted(v["at"] for v in results.values() if "at" in v)
        print(f"started {len(times)} of {len(todo)} scans" + (f", the first commit at {times[0]}" if times else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
