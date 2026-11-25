#!/usr/bin/env python3
"""Did a released Community Packs query close its gap, and how much does it find?

It reads code scanning alerts with the gh CLI and writes nothing to GitHub.

    verify_alerts.py gap --issue 230 --rule githubsecuritylab/actions/encoded-secret-in-log
        For every AI scan alert that the gap issue links, is there now a CodeQL alert of that rule
        on the same lines of the same file (COVERED)? Is there none although the language is
        analyzed (NOT_COVERED)? Or is the rule's language not analyzed in that repository at all
        (NOT_ANALYZED), in which case no query can have found anything yet?

    verify_alerts.py count --rule githubsecuritylab/actions/encoded-secret-in-log --property Synthetic=true
        How many alerts of that rule exist in the organization's repositories that have the property
        value, by repository. ``--snapshot FILE`` appends the result to a JSON lines history, so the
        number can be tracked over time.

``gap`` exits 0 when every linked alert is COVERED, 1 when one is not, 2 on an error.
The defaults name codeql-forks-felickz and its template repository; ``--template`` and ``--org``
change them. It needs the gh CLI, signed in with access to the code scanning alerts.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys

TEMPLATE_REPO = "codeql-forks-felickz/codeql-development-template"
ORG = "codeql-forks-felickz"
CONFIG_PROPERTY = "github-codeql-config-file"
ALERT_URL = re.compile(r"https://github\.com/([^/\s]+)/([^/\s]+)/security/code-scanning/(\d+)")
RULE_RE = re.compile(r"^[\w./-]+$")
# The language segment of a Community Packs query id, and the name default setup gives the language.
SETUP_LANGUAGE = {
    "actions": "actions", "cpp": "c-cpp", "cs": "csharp", "go": "go", "java": "java-kotlin",
    "js": "javascript-typescript", "py": "python", "rb": "ruby", "rust": "rust", "swift": "swift",
}


def gh(*args: str) -> str:
    proc = subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8")
    if proc.returncode:
        raise RuntimeError(f"gh {' '.join(args[:2])} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout


def gh_json(path: str) -> dict | list:
    return json.loads(gh("api", path))


def gh_lines(path: str, jq: str = ".[]") -> list[dict]:
    """Every item of a paginated list endpoint, one JSON object per line from ``--jq``."""
    out = gh("api", "--paginate", path, "--jq", jq)
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def rule_language(rule: str) -> str | None:
    """The default setup language of a Community Packs rule id, or None for any other id."""
    parts = rule.split("/")
    if len(parts) < 3 or parts[0] != "githubsecuritylab":
        return None
    segment = parts[2] if parts[1] == "audit" else parts[1]
    return SETUP_LANGUAGE.get(segment)


def linked_alerts(issue_body: str) -> list[tuple[str, str, int]]:
    """The code scanning alerts (owner, repository, number) that a gap issue links."""
    return sorted({(o, r, int(n)) for o, r, n in ALERT_URL.findall(issue_body or "")})


def overlaps(a: dict, b: dict) -> bool:
    return (a["path"] == b["path"] and a["start"] <= b["end"] and b["start"] <= a["end"])


def classify(ai: dict, found: list[dict], language: str | None, analyzed: set[str] | None) -> dict:
    """The status of one AI scan alert. ``found`` are the CodeQL alerts of the rule in the same repository.

    ``analyzed`` is the set of analysis categories CodeQL has uploaded for the repository, or None when
    that could not be read.
    """
    covering = [f for f in found if overlaps(ai, f)]
    open_covering = [f for f in covering if f["state"] == "open"]
    if open_covering:
        top = open_covering[0]
        return {"status": "COVERED", "reason": f"alert {top['url']} on lines {top['start']}-{top['end']}",
                "alerts": [f["url"] for f in open_covering]}
    if language and analyzed is not None and f"/language:{language}" not in analyzed:
        return {"status": "NOT_ANALYZED", "alerts": [],
                "reason": f"no CodeQL analysis with category /language:{language} (seen: {', '.join(sorted(analyzed)) or 'none'})"}
    closed = [f"{f['url']} ({f['state']})" for f in covering]
    return {"status": "NOT_COVERED", "alerts": [],
            "reason": "no open alert of the rule covers the lines" + (f"; closed: {', '.join(closed)}" if closed else "")}


def location(alert: dict) -> dict:
    loc = alert["most_recent_instance"]["location"]
    return {"path": loc["path"], "start": loc["start_line"], "end": loc.get("end_line") or loc["start_line"]}


def repository_facts(owner: str, repo: str) -> dict:
    """Default setup languages, uploaded analysis categories and the config file property of one repository."""
    facts: dict = {"setup_languages": None, "analyzed": None, "config_file": None}
    try:
        facts["setup_languages"] = gh_json(f"repos/{owner}/{repo}/code-scanning/default-setup").get("languages")
    except (RuntimeError, json.JSONDecodeError):
        pass
    try:
        analyses = gh_lines(f"repos/{owner}/{repo}/code-scanning/analyses?tool_name=CodeQL&per_page=100")
        facts["analyzed"] = {a.get("category") or "" for a in analyses}
    except (RuntimeError, json.JSONDecodeError):
        pass
    try:
        values = gh_json(f"repos/{owner}/{repo}/properties/values")
        facts["config_file"] = next((p["value"] for p in values if p["property_name"] == CONFIG_PROPERTY), None)
    except (RuntimeError, json.JSONDecodeError, TypeError):
        pass
    return facts


def run_gap(args: argparse.Namespace) -> int:
    language = rule_language(args.rule)
    issue = gh_json(f"repos/{args.template}/issues/{args.issue}")
    links = linked_alerts(issue.get("body") or "")
    if not links:
        print(f"issue {args.issue} links no code scanning alert", file=sys.stderr)
        return 2
    report, per_repo = [], {}
    for owner, repo, number in links:
        key = (owner, repo)
        if key not in per_repo:
            facts = repository_facts(owner, repo)
            jq = f'.[] | select(.rule.id == "{args.rule}") | {{number, url: .html_url, state, most_recent_instance}}'
            alerts = []
            for state in ("open", "closed"):
                alerts += gh_lines(f"repos/{owner}/{repo}/code-scanning/alerts?tool_name=CodeQL&state={state}&per_page=100", jq)
            facts["found"] = [{"url": a["url"], "state": a["state"], **location(a)} for a in alerts]
            per_repo[key] = facts
        facts = per_repo[key]
        ai_alert = gh_json(f"repos/{owner}/{repo}/code-scanning/alerts/{number}")
        ai = location(ai_alert)
        result = classify(ai, facts["found"], language, facts["analyzed"])
        report.append({"repository": f"{owner}/{repo}", "ai_alert": f"https://github.com/{owner}/{repo}/security/code-scanning/{number}",
                       "location": f"{ai['path']}:{ai['start']}-{ai['end']}", "config_file_property": facts["config_file"],
                       "default_setup_languages": facts["setup_languages"], **result})
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for row in report:
            print(f"{row['status']:<13} {row['repository']}  {row['location']}\n    {row['reason']}\n"
                  f"    AI alert {row['ai_alert']}\n    {CONFIG_PROPERTY}: {row['config_file_property'] or '(not set)'}")
        covered = sum(1 for r in report if r["status"] == "COVERED")
        print(f"\n{covered} of {len(report)} linked alert(s) covered by {args.rule}")
    return 0 if all(r["status"] == "COVERED" for r in report) else 1


def run_count(args: argparse.Namespace) -> int:
    repos: set[str] | None = None
    if args.property:
        name, _, value = args.property.partition("=")
        rows = gh_lines(f"orgs/{args.org}/properties/values?per_page=100")
        repos = {r["repository_name"] for r in rows
                 if any(p["property_name"] == name and p["value"] == value for p in r.get("properties") or [])}
    jq = f'.[] | select(.rule.id == "{args.rule}") | [.repository.name, .state] | @tsv'
    by_repo: dict[str, int] = {}
    for state in args.states.split(","):
        out = gh("api", "--paginate", f"orgs/{args.org}/code-scanning/alerts?tool_name=CodeQL&state={state}&per_page=100", "--jq", jq)
        for line in out.splitlines():
            repo = line.split("\t")[0]
            if repo and (repos is None or repo in repos):
                by_repo[repo] = by_repo.get(repo, 0) + 1
    result = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "rule": args.rule,
              "states": args.states, "property": args.property, "repositories_checked": len(repos) if repos is not None else None,
              "alerts": sum(by_repo.values()), "repositories": len(by_repo), "by_repository": dict(sorted(by_repo.items()))}
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{result['alerts']} alert(s) of {args.rule} ({args.states}) in {result['repositories']} repository(ies)"
              + (f" of {result['repositories_checked']} with {args.property}" if repos is not None else ""))
        for repo, n in result["by_repository"].items():
            print(f"  {n:>4}  {repo}")
    if args.snapshot:
        with open(args.snapshot, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(result) + "\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    gap = sub.add_parser("gap", help="is every AI scan alert of a gap issue covered by the rule?")
    gap.add_argument("--issue", type=int, required=True, help="the gap issue in the template repository")
    gap.add_argument("--rule", required=True, help="the released query id, for example githubsecuritylab/actions/encoded-secret-in-log")
    gap.add_argument("--template", default=TEMPLATE_REPO)
    gap.add_argument("--json", action="store_true")
    count = sub.add_parser("count", help="how many alerts of the rule exist in the organization?")
    count.add_argument("--rule", required=True)
    count.add_argument("--org", default=ORG)
    count.add_argument("--property", help="NAME=VALUE: only repositories with this custom property value, for example Synthetic=true")
    count.add_argument("--states", default="open", help="comma separated alert states (default: open)")
    count.add_argument("--snapshot", help="append the result to this JSON lines file")
    count.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if not RULE_RE.match(args.rule):
        print("the rule id may only contain letters, digits, '_', '.', '/' and '-'", file=sys.stderr)
        return 2
    try:
        return run_gap(args) if args.command == "gap" else run_count(args)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
