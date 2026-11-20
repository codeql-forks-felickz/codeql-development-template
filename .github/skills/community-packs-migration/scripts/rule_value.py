#!/usr/bin/env python3
"""Which queries found things: the new code scanning alerts of one rollout, by rule, precision and pack.

Use it after a configuration change and the scans that followed it, for example setting the
github-codeql-config-file property, to see which of the queries that the change added produce alerts, and
how precise those queries are.

    rule_value.py report --org ORG --since 2026-11-20T20:42:00Z [--property Synthetic=true] [--out report.json]

An alert is new when it was created at or after --since. The alerts API does not return the precision of a
rule, so it is read from the SARIF of one analysis that holds the rule (the smallest one). A rule that
declares no precision is reported as "none". Read-only. Needs `gh`, signed in with access to the code scanning
alerts of the organization.
"""

import argparse
import collections
import json
import os
import subprocess
import sys

PRECISIONS = ("very-high", "high", "medium", "low", "none", "unknown")


def gh(*args: str, capture_to: str | None = None) -> str:
    cmd = ["gh", *args]
    if capture_to:
        with open(capture_to, "wb") as handle:
            proc = subprocess.run(cmd, stdout=handle, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip()[:300])
        return ""
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip()[:300])
    return proc.stdout


def gh_json(path: str):
    return json.loads(gh("api", path))


def namespace(rule_id: str) -> str:
    """The pack family of a rule, from its id."""
    if rule_id.startswith("githubsecuritylab/"):
        return "community-packs"
    if rule_id.startswith("tob/"):
        return "trail-of-bits"
    return "codeql"


def rule_meta_from_sarif(sarif: dict) -> dict[str, dict]:
    """The metadata that the alerts API leaves out, by rule id, from the rules of every run of a SARIF file."""
    out: dict[str, dict] = {}
    for run in sarif.get("runs", []):
        tool = run.get("tool", {})
        rules = list(tool.get("driver", {}).get("rules", []))
        for extension in tool.get("extensions", []):
            rules += extension.get("rules", [])
        for rule in rules:
            props = rule.get("properties", {})
            out[rule["id"]] = {
                "precision": props.get("precision", "none"),
                "kind": props.get("kind"),
                "severity": props.get("problem.severity"),
                "security_severity": props.get("security-severity"),
                "tags": props.get("tags", []),
            }
    return out


def new_alerts(org: str, since: str, repos: set[str] | None) -> list[dict]:
    """Open CodeQL alerts created at or after `since`, newest first, in the repositories `repos` (all when None)."""
    found: list[dict] = []
    page = 1
    while True:
        data = gh_json(f"orgs/{org}/code-scanning/alerts?tool_name=CodeQL&state=open&sort=created&direction=desc&per_page=100&page={page}")
        if not data:
            return found
        for alert in data:
            if alert["created_at"] < since:
                return found
            name = alert["repository"]["name"]
            if repos is not None and name not in repos:
                continue
            instance = alert["most_recent_instance"]
            location = instance.get("location", {})
            found.append({"repo": name, "number": alert["number"], "rule": alert["rule"]["id"], "name": alert["rule"].get("name"),
                          "severity": alert["rule"].get("severity"), "tags": alert["rule"].get("tags", []),
                          "category": instance.get("category"), "path": location.get("path"), "line": location.get("start_line"),
                          "end_line": location.get("end_line") or location.get("start_line"), "url": alert.get("html_url"),
                          "created_at": alert["created_at"]})
        page += 1


def property_repos(org: str, prop: str) -> set[str]:
    name, _, value = prop.partition("=")
    out = gh("api", "--paginate", f"orgs/{org}/properties/values?per_page=100", "--jq",
             f'.[] | select(.properties[] | select(.property_name=="{name}" and .value=="{value}")) | .repository_name')
    return {line.strip() for line in out.splitlines() if line.strip()}


def latest_analyses(org: str, repo: str, since: str) -> dict[str, dict]:
    """The newest analysis of each category that was created at or after `since`."""
    rows = gh_json(f"repos/{org}/{repo}/code-scanning/analyses?tool_name=CodeQL&per_page=100")
    out: dict[str, dict] = {}
    for row in rows:
        if row["created_at"] >= since and row["category"] not in out:
            out[row["category"]] = row
    return out


def collect_rule_meta(org: str, alerts: list[dict], since: str, cache_dir: str) -> dict[str, dict]:
    """Rule metadata for every rule of `alerts`, one smallest-analysis SARIF at a time."""
    os.makedirs(cache_dir, exist_ok=True)
    meta: dict[str, dict] = {}
    cache_file = os.path.join(cache_dir, "rule-meta.json")
    if os.path.exists(cache_file):
        meta = json.load(open(cache_file, encoding="utf-8"))
    where: dict[str, set[tuple[str, str]]] = collections.defaultdict(set)
    for alert in alerts:
        where[alert["rule"]].add((alert["repo"], alert["category"]))
    analyses: dict[str, dict[str, dict]] = {}
    for rule in sorted(where, key=lambda r: len(where[r])):
        if rule in meta:
            continue
        candidates = []
        for repo, category in where[rule]:
            if repo not in analyses:
                analyses[repo] = latest_analyses(org, repo, since)
            analysis = analyses[repo].get(category)
            if analysis:
                candidates.append((analysis["results_count"], repo, analysis["id"]))
        for _, repo, analysis_id in sorted(candidates)[:3]:
            path = os.path.join(cache_dir, f"{repo}-{analysis_id}.sarif")
            try:
                gh("api", f"repos/{org}/{repo}/code-scanning/analyses/{analysis_id}", "-H", "Accept: application/sarif+json", capture_to=path)
                meta.update(rule_meta_from_sarif(json.load(open(path, encoding="utf-8"))))
            except (RuntimeError, ValueError) as exc:
                print(f"  could not read the SARIF of analysis {analysis_id} in {repo}: {exc}", file=sys.stderr)
            finally:
                if os.path.exists(path):
                    os.remove(path)
            if rule in meta:
                break
    json.dump(meta, open(cache_file, "w", encoding="utf-8"))
    return meta


def summarize(alerts: list[dict], meta: dict[str, dict]) -> list[dict]:
    """One row per rule, the busiest first."""
    rules: dict[str, dict] = {}
    for alert in alerts:
        row = rules.setdefault(alert["rule"], {"rule": alert["rule"], "alerts": 0, "repos": set(), "examples": []})
        row["alerts"] += 1
        row["repos"].add(alert["repo"])
        if len(row["examples"]) < 2:
            row["examples"].append(f'{alert["repo"]}:{alert["path"]}:{alert["line"]}')
    rows = []
    for rule_id, row in rules.items():
        info = meta.get(rule_id, {})
        rows.append({"rule": rule_id, "namespace": namespace(rule_id), "precision": info.get("precision", "unknown"),
                     "kind": info.get("kind"), "alerts": row["alerts"], "repos": len(row["repos"]), "examples": row["examples"]})
    return sorted(rows, key=lambda r: (-r["alerts"], r["rule"]))


def by_precision(rows: list[dict]) -> dict[str, dict[str, dict]]:
    """Alerts and rules per pack family and precision."""
    out: dict[str, dict[str, dict]] = {}
    for row in rows:
        cell = out.setdefault(row["namespace"], {}).setdefault(row["precision"], {"alerts": 0, "rules": 0})
        cell["alerts"] += row["alerts"]
        cell["rules"] += 1
    return out


def language_of(alert: dict) -> str:
    """The language of an alert, from the category of its analysis (`/language:python`)."""
    return (alert.get("category") or "").removeprefix("/language:") or "unknown"


def by_language(alerts: list[dict], meta: dict[str, dict]) -> dict[str, collections.Counter]:
    """Alerts per language: stock CodeQL rules by precision, the other pack families as one column each."""
    out: dict[str, collections.Counter] = {}
    for alert in alerts:
        family = namespace(alert["rule"])
        column = meta.get(alert["rule"], {}).get("precision", "unknown") if family == "codeql" else family
        out.setdefault(language_of(alert), collections.Counter())[column] += 1
    return out


def print_report(since: str, alerts: list[dict], rows: list[dict], meta: dict[str, dict], top: int) -> None:
    repos = {a["repo"] for a in alerts}
    print(f"New alerts since {since}: {len(alerts)} in {len(repos)} repositories, from {len(rows)} rules\n")
    table = by_precision(rows)
    print(f"{'pack family':<18}{'precision':<11}{'rules':>6}{'alerts':>8}")
    for family in sorted(table):
        for precision in PRECISIONS:
            if precision in table[family]:
                cell = table[family][precision]
                print(f"{family:<18}{precision:<11}{cell['rules']:>6}{cell['alerts']:>8}")
    columns = ("very-high", "high", "medium", "low", "none", "community-packs", "trail-of-bits")
    print(f"\nalerts per language: CodeQL rules by precision, then the other pack families")
    print(f"{'language':<24}" + "".join(f"{c[:9]:>11}" for c in columns))
    for language, counts in sorted(by_language(alerts, meta).items()):
        print(f"{language:<24}" + "".join(f"{counts.get(c, 0):>11}" for c in columns))
    low = [r for r in rows if r["namespace"] == "codeql" and r["precision"] in ("low", "none")]
    print(f"\nCodeQL rules of low or no precision that found things: {len(low)} rules, {sum(r['alerts'] for r in low)} alerts")
    for row in low[:top]:
        print(f"  {row['alerts']:>5} alerts in {row['repos']:>2} repos  {row['precision']:<5} {row['rule']}  e.g. {row['examples'][0]}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    rep = sub.add_parser("report", help="group the new alerts by rule, precision and pack")
    rep.add_argument("--org", required=True)
    rep.add_argument("--since", required=True, help="ISO time such as 2026-11-20T20:42:00Z; alerts created from then on are new")
    rep.add_argument("--property", help="NAME=VALUE: only repositories that have the property value")
    rep.add_argument("--out", help="write the rows and alerts as JSON")
    rep.add_argument("--cache", default=os.path.join(os.path.expanduser("~"), ".rule_value_cache"))
    rep.add_argument("--top", type=int, default=15)
    args = parser.parse_args(argv)
    repos = property_repos(args.org, args.property) if args.property else None
    alerts = new_alerts(args.org, args.since, repos)
    meta = collect_rule_meta(args.org, alerts, args.since, args.cache)
    rows = summarize(alerts, meta)
    print_report(args.since, alerts, rows, meta, args.top)
    if args.out:
        json.dump({"since": args.since, "rows": rows, "alerts": alerts}, open(args.out, "w", encoding="utf-8"), indent=1)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
