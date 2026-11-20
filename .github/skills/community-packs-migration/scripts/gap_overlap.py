#!/usr/bin/env python3
"""Which findings with a planned query do the new CodeQL alerts now cover?

    gap_overlap.py report --org ORG --since 2026-11-20T20:00:00Z --planned planned.json [--out report.json]

``planned.json`` lists AI Scan alerts that were triaged: [{"repo", "alert", "issue", "group", "handling"}], where
``group`` is "planned" for a finding that got a gap issue (a query, a query update or a data extension was
planned) and anything else, for example "retained", for a finding that stays with AI Scan. The script reads those
AI alerts and the CodeQL alerts created at or after ``--since``, and matches them by file, lines and CWE, with the
rules of the first AI-versus-CodeQL comparison:

  exact-duplicate      the lines overlap and the CWE is the same
  near-duplicate       the same file, 5 lines or less apart, the same CWE or the same CWE family
  possible-same-flow   the same file, 40 lines or less apart, the same CWE or the same CWE family
  same-spot-other-cwe  the lines overlap or are 5 lines apart, and the weakness is another one

The first two count as covered. Read-only. Needs `gh`, signed in with access to the code scanning alerts.
"""

import argparse
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rule_value as rv  # noqa: E402

COVERED = ("exact-duplicate", "near-duplicate")
CWE_FAMILIES = {
    "path-traversal": {22, 23, 36, 73}, "xss": {79, 80, 83, 87, 116}, "sql-injection": {89, 564, 943},
    "command-injection": {77, 78, 88}, "code-injection": {94, 95, 96}, "ldap-injection": {90},
    "xpath-injection": {643}, "expression-injection": {917}, "log-injection": {117}, "header-injection": {113},
    "ssrf": {918}, "open-redirect": {601}, "csrf": {352}, "xxe": {611, 827}, "deserialization": {502},
    "sensitive-data": {200, 201, 203, 204, 209, 256, 312, 315, 319, 359, 497, 524, 530, 532, 548, 598},
    "hardcoded-secret": {257, 259, 321, 798}, "weak-crypto": {295, 311, 326, 327, 328, 329, 330, 338, 345, 346, 347},
    "authentication": {287, 306, 307, 384, 521, 522, 523, 613, 640, 916}, "authorization": {269, 284, 285, 639, 862, 863, 926},
    "cookie": {565, 614, 1004}, "resource-exhaustion": {400, 401, 409, 772, 775, 776, 789, 835, 1333, 1336},
    "file-upload": {434}, "memory-safety": {119, 120, 121, 122, 124, 125, 126, 127, 415, 416, 476, 590, 787, 788},
    "integer": {190, 191, 192, 369, 681, 682}, "prototype-pollution": {1321, 915}, "untrusted-code": {494, 829}, "debug": {489},
}
CWE_TO_FAMILY = {cwe: family for family, cwes in CWE_FAMILIES.items() for cwe in cwes}


def cwes_from_tags(tags: list[str]) -> list[int]:
    """The CWE numbers of a rule, from its tags (`external/cwe/cwe-079`)."""
    return sorted({int(m.group(1)) for tag in tags or [] for m in [re.fullmatch(r"external/cwe/cwe-(\d+)", tag)] if m})


def cwe_relation(left: list[int], right: list[int]) -> str | None:
    """"exact" when the two lists share a CWE, "family" when they share a family, else None."""
    if set(left or []) & set(right or []):
        return "exact"
    families = lambda cwes: {CWE_TO_FAMILY.get(c) for c in cwes or []} - {None}  # noqa: E731
    return "family" if families(left) & families(right) else None


def classify(ai: dict, codeql: dict) -> tuple[str, int, int] | None:
    """(class, score, line distance) of the match of a CodeQL alert to an AI alert, or None."""
    if (ai.get("path") or "").lower() != (codeql.get("path") or "").lower():
        return None
    a0, a1 = ai["start_line"], ai.get("end_line") or ai["start_line"]
    c0, c1 = codeql["line"], codeql.get("end_line") or codeql["line"]
    overlapping = a0 <= c1 and c0 <= a1
    distance = 0 if overlapping else min(abs(a0 - c1), abs(c0 - a1))
    relation = cwe_relation(ai.get("cwes"), codeql.get("cwes"))
    if relation == "exact" and overlapping:
        return "exact-duplicate", 100, distance
    if relation and distance <= 5:
        return "near-duplicate", 90 if relation == "exact" else 80, distance
    if relation and distance <= 40:
        return "possible-same-flow", 70 if relation == "exact" else 60, distance
    if distance <= 5:
        return "same-spot-other-cwe", 40, distance
    return None


def ai_alerts(org: str) -> dict[tuple[str, int], dict]:
    """Every AI Scan alert of the organization, in any state, by (repository, number)."""
    out: dict[tuple[str, int], dict] = {}
    for state in ("open", "fixed", "dismissed"):
        page = 1
        while True:
            data = rv.gh_json(f"orgs/{org}/code-scanning/alerts?tool_name=AI%20Scan&state={state}&per_page=100&page={page}")
            for alert in data:
                location = alert["most_recent_instance"].get("location", {})
                out[(alert["repository"]["name"], alert["number"])] = {
                    "path": location.get("path"), "start_line": location.get("start_line") or 0,
                    "end_line": location.get("end_line") or location.get("start_line") or 0,
                    "cwes": cwes_from_tags(alert["rule"].get("tags", [])), "state": alert["state"],
                    "severity": alert["rule"].get("security_severity_level") or alert["rule"].get("severity")}
            if len(data) < 100:
                break
            page += 1
    return out


def match_all(planned: list[dict], ai: dict, new: list[dict]) -> list[dict]:
    """One row per planned finding, with its best match among the new alerts of the same repository."""
    by_repo: dict[str, list[dict]] = collections.defaultdict(list)
    for alert in new:
        by_repo[alert["repo"]].append({**alert, "cwes": cwes_from_tags(alert.get("tags", []))})
    rows = []
    for item in planned:
        found = ai.get((item["repo"], item["alert"]))
        row = {**item, "found": bool(found), "ai": found, "class": None, "match": None}
        if found:
            best = None
            for alert in by_repo.get(item["repo"], []):
                result = classify(found, alert)
                if result and (best is None or (result[1], -result[2]) > (best[0][1], -best[0][2])):
                    best = (result, alert)
            if best:
                (row["class"], _, distance), alert = best
                row["match"] = {"rule": alert["rule"], "url": alert.get("url"), "path": alert["path"], "line": alert["line"],
                                "end_line": alert.get("end_line"), "distance": distance}
        rows.append(row)
    return rows


def by_issue(rows: list[dict]) -> list[dict]:
    """Per gap issue: how many of its findings the new alerts cover."""
    issues: dict[str, dict] = {}
    for row in rows:
        entry = issues.setdefault(str(row.get("issue")), {"issue": row.get("issue"), "findings": 0, "covered": 0, "possible": 0, "rules": collections.Counter()})
        entry["findings"] += 1
        if row["class"] in COVERED:
            entry["covered"] += 1
            entry["rules"][row["match"]["rule"]] += 1
        elif row["class"] == "possible-same-flow":
            entry["possible"] += 1
    return sorted(issues.values(), key=lambda e: (-e["covered"] / max(e["findings"], 1), -e["covered"], str(e["issue"])))


def print_report(rows: list[dict], since: str, top: int) -> None:
    for group in sorted({r.get("group") for r in rows}, key=str):
        part = [r for r in rows if r.get("group") == group]
        classes = collections.Counter(r["class"] or ("no match" if r["found"] else "AI alert not found") for r in part)
        print(f"\n== {group}: {len(part)} findings, against the CodeQL alerts created since {since}")
        for name in ("exact-duplicate", "near-duplicate", "possible-same-flow", "same-spot-other-cwe", "no match", "AI alert not found"):
            if classes.get(name):
                print(f"  {classes[name]:>5}  {name}")
        covered = [r for r in part if r["class"] in COVERED]
        print(f"  covered (exact or near duplicate): {len(covered)} findings in {len({r['issue'] for r in covered})} issues")
        rules = collections.Counter(r["match"]["rule"] for r in covered)
        for rule, count in rules.most_common(top):
            print(f"      {count:>4}  {rule}")
    planned = [r for r in rows if r.get("group") == "planned"]
    print("\nGap issues whose findings are now covered, most covered first:")
    for entry in [e for e in by_issue(planned) if e["covered"]][:top]:
        print(f"  issue {entry['issue']}: {entry['covered']} of {entry['findings']} covered ({entry['possible']} possible)  {dict(entry['rules'].most_common(2))}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    rep = sub.add_parser("report", help="match the triaged AI findings to the new CodeQL alerts")
    rep.add_argument("--org", required=True)
    rep.add_argument("--since", required=True)
    rep.add_argument("--planned", required=True, help="JSON list of {repo, alert, issue, group, handling}")
    rep.add_argument("--out")
    rep.add_argument("--top", type=int, default=12)
    args = parser.parse_args(argv)
    planned = json.load(open(args.planned, encoding="utf-8"))
    rows = match_all(planned, ai_alerts(args.org), rv.new_alerts(args.org, args.since, {p["repo"] for p in planned}))
    print_report(rows, args.since, args.top)
    if args.out:
        json.dump(rows, open(args.out, "w", encoding="utf-8"), indent=1)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
