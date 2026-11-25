#!/usr/bin/env python3
"""Add a language to the code scanning default setup of the repositories that contain files of it.

A query cannot alert on a language that is not analyzed. Default setup picks its languages when it is
configured, so repositories configured before a language was supported never analyze it.

    default_setup_languages.py plan   [--org ORG] [--language actions] --out plan.json
    default_setup_languages.py apply  --plan plan.json [--property Synthetic=true] [--only REPO ...] [--apply]
    default_setup_languages.py revert --plan plan.json [--only REPO ...] [--apply]
    default_setup_languages.py disable-workflows --only REPO ... [--apply]
    default_setup_languages.py remove-language --language python --only REPO ... [--apply]

``plan`` only reads. It lists every repository of the organization with its default setup and whether it has
files of the language, and writes the plan. ``apply`` sends ``PATCH /repos/{owner}/{repo}/code-scanning/default-setup``
for the repositories whose plan says ``enable``, keeps the languages they had, and records what it did in the plan
file. ``revert`` puts the earlier languages back. ``apply`` and ``revert`` write nothing to GitHub unless you add
``--apply``. A repository that is archived, has no default setup, already has the language or has no files of it
is skipped. The calls need administration rights on the repositories and the gh CLI, signed in.

Only ``actions`` is detected so far: a repository has it when ``.github/workflows`` holds a YAML file. The API
also refuses ``actions`` (422, languages not present) for a repository where GitHub Actions has registered no
workflow of its own, which is how every fork starts. ``plan`` shows those as skipped: enable the workflows in the
Actions tab of the fork, then plan again.

``remove-language`` takes a language out of the default setup of the named repositories. Use it when a language
job fails with "CodeQL detected code written in X but could not process any of it", which happens when the
configuration ignores every path that holds the code (a ``paths-ignore`` of ``tests/**``, say) and nothing
worth analyzing is left. A removal needs no validation run: the call answers at once, with run_id 0.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import subprocess
import sys
import time

ORG = "codeql-forks-felickz"
# The names the API accepts in a PATCH. A GET also lists aliases (javascript, typescript, java, kotlin, c, cpp).
ALIASES = {"javascript": "javascript-typescript", "typescript": "javascript-typescript",
           "java": "java-kotlin", "kotlin": "java-kotlin", "c": "c-cpp", "cpp": "c-cpp"}
WORKFLOW_SUFFIXES = (".yml", ".yaml")


def gh(*args: str, payload: dict | None = None, retries: int = 3) -> str:
    cmd = ["gh", *args] + (["--input", "-"] if payload is not None else [])
    for attempt in range(retries):
        proc = subprocess.run(cmd, input=json.dumps(payload) if payload is not None else None,
                              capture_output=True, text=True, encoding="utf-8")
        if proc.returncode == 0:
            return proc.stdout
        message = (proc.stderr or proc.stdout).strip()
        if "rate limit" in message.lower() and attempt < retries - 1:
            time.sleep(30 * (attempt + 1))
            continue
        raise RuntimeError(message[:300])
    raise RuntimeError("unreachable")


def gh_json(path: str) -> dict | list | None:
    """The JSON of a GET, or None when the resource does not exist."""
    try:
        return json.loads(gh("api", path))
    except RuntimeError as exc:
        if "404" in str(exc) or "Not Found" in str(exc):
            return None
        raise


def canonical(languages: list[str]) -> list[str]:
    """The languages by the names a PATCH accepts, without duplicates, in their original order."""
    out: list[str] = []
    for language in languages:
        name = ALIASES.get(language, language)
        if name not in out:
            out.append(name)
    return out


def workflow_files(listing: list | dict | None) -> int:
    """How many YAML files a ``.github/workflows`` directory listing holds."""
    if not isinstance(listing, list):
        return 0
    return sum(1 for item in listing if item.get("type") == "file" and item.get("name", "").lower().endswith(WORKFLOW_SUFFIXES))


def registered_workflows(listing: dict | None) -> int:
    """How many workflows of the repository itself GitHub Actions has registered, in any state.

    A fork starts with the workflows it inherited disabled and not registered, so the API lists only the
    dynamic ones (dynamic/...) until someone enables them in the Actions tab.
    """
    if not isinstance(listing, dict):
        return 0
    return sum(1 for item in listing.get("workflows") or [] if str(item.get("path", "")).startswith(".github/workflows/"))


def active_own_workflows(listing: dict | None) -> list[dict]:
    """The repository's own workflows that can still run, that is, the ones that are not disabled in any way."""
    if not isinstance(listing, dict):
        return []
    return [w for w in listing.get("workflows") or []
            if str(w.get("path", "")).startswith(".github/workflows/") and w.get("state") == "active"]


def decide(row: dict, language: str) -> str:
    """'enable', or 'skip: <reason>'."""
    if row["archived"]:
        return "skip: archived"
    if row["state"] != "configured":
        return "skip: default setup is not configured"
    if language in row["languages"]:
        return "skip: already analyzed"
    if row["files"] == 0:
        return "skip: no files of the language"
    if language == "actions" and row.get("registered", 0) == 0:
        return "skip: workflows are not enabled (the API would refuse)"
    if "rust" in row["languages"]:
        return "skip: the API does not accept rust (use the settings form)"
    return "enable"


def payload(row: dict, languages: list[str]) -> dict:
    """The PATCH body: the languages, and the settings the repository already has, so none is reset."""
    body: dict = {"state": "configured", "languages": languages}
    for key in ("query_suite", "threat_model"):
        if row.get(key):
            body[key] = row[key]
    if row.get("runner_type") == "labeled":
        body["runner_type"] = "labeled"
        body["runner_label"] = row.get("runner_label")
    return body


def inspect(org: str, repo: dict, language: str) -> dict:
    name = repo["name"]
    row = {"repository": f"{org}/{name}", "archived": bool(repo.get("archived")), "state": "unknown", "languages": [],
           "raw_languages": [], "query_suite": None, "threat_model": None, "runner_type": None, "runner_label": None,
           "files": 0, "registered": 0, "error": None}
    try:
        setup = gh_json(f"repos/{org}/{name}/code-scanning/default-setup")
        if setup:
            row.update(state=setup.get("state") or "unknown", raw_languages=setup.get("languages") or [],
                       languages=canonical(setup.get("languages") or []), query_suite=setup.get("query_suite"),
                       threat_model=setup.get("threat_model"), runner_type=setup.get("runner_type"),
                       runner_label=setup.get("runner_label") or None)
        if language == "actions":
            row["files"] = workflow_files(gh_json(f"repos/{org}/{name}/contents/.github/workflows"))
            row["registered"] = registered_workflows(gh_json(f"repos/{org}/{name}/actions/workflows"))
    except RuntimeError as exc:
        row["error"] = str(exc)
    row["action"] = decide(row, language) if not row["error"] else "skip: could not be read"
    return row


def property_values(org: str) -> dict[str, dict[str, str]]:
    out = gh("api", "--paginate", f"orgs/{org}/properties/values?per_page=100", "--jq", ".[]")
    values: dict[str, dict[str, str]] = {}
    for line in out.splitlines():
        if line.strip():
            item = json.loads(line)
            values[item["repository_name"]] = {p["property_name"]: p["value"] for p in item.get("properties") or []
                                               if isinstance(p.get("value"), str)}
    return values


def run_plan(args: argparse.Namespace) -> int:
    if args.language != "actions":
        print("only the actions language can be detected so far", file=sys.stderr)
        return 2
    out = gh("api", "--paginate", f"orgs/{args.org}/repos?per_page=100&type=all", "--jq", ".[] | {name, archived}")
    repos = [json.loads(line) for line in out.splitlines() if line.strip()]
    properties = property_values(args.org)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows = list(pool.map(lambda repo: inspect(args.org, repo, args.language), repos))
    for row in rows:
        row["properties"] = properties.get(row["repository"].split("/", 1)[1], {})
    plan = {"org": args.org, "language": args.language, "rows": rows}
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(plan, handle, indent=1)
    summarize(plan, args.property)
    print(f"plan written to {args.out}")
    return 0


def matches(row: dict, prop: str | None) -> bool:
    if not prop:
        return True
    name, _, value = prop.partition("=")
    return row.get("properties", {}).get(name) == value


def summarize(plan: dict, prop: str | None = None) -> None:
    rows = plan["rows"]
    counts: dict[str, int] = {}
    for row in rows:
        key = row["action"] if row["action"] == "enable" else row["action"]
        counts[key] = counts.get(key, 0) + 1
    print(f"{len(rows)} repositories in {plan['org']}, language {plan['language']}")
    for key, n in sorted(counts.items(), key=lambda kv: (kv[0] != "enable", -kv[1])):
        print(f"  {n:>4}  {key}")
    enable = [r for r in rows if r["action"] == "enable"]
    if prop:
        inside = [r for r in enable if matches(r, prop)]
        print(f"  of the {len(enable)} to enable: {len(inside)} have {prop}, {len(enable) - len(inside)} do not")


def selected(plan: dict, args: argparse.Namespace, key: str) -> list[dict]:
    only = {name.lower() for name in args.only}
    chosen = []
    for row in plan["rows"]:
        short = row["repository"].split("/", 1)[1].lower()
        if only and short not in only and row["repository"].lower() not in only:
            continue
        if key == "apply" and (row["action"] != "enable" or not matches(row, args.property)):
            continue
        if key == "revert" and not (row.get("result") or {}).get("applied"):
            continue
        chosen.append(row)
    return chosen


def patch(row: dict, body: dict) -> dict:
    out = gh("api", "-X", "PATCH", f"repos/{row['repository']}/code-scanning/default-setup", payload=body)
    return json.loads(out) if out.strip() else {}


def languages_now(row: dict) -> list[str]:
    setup = gh_json(f"repos/{row['repository']}/code-scanning/default-setup") or {}
    return canonical(setup.get("languages") or [])


def run_apply(args: argparse.Namespace) -> int:
    with open(args.plan, encoding="utf-8") as handle:
        plan = json.load(handle)
    language = plan["language"]
    rows = selected(plan, args, "apply")
    print(f"{len(rows)} repositor{'y' if len(rows) == 1 else 'ies'} to update" + ("" if args.apply else " (dry run, add --apply to write)"))
    failures = 0
    for row in rows:
        body = payload(row, canonical(row["raw_languages"]) + [language])
        body["languages"] = canonical(body["languages"])
        if not args.apply:
            print(f"  would PATCH {row['repository']}: {json.dumps(body)}")
            continue
        try:
            response = patch(row, body)
            after = languages_now(row)
            row["result"] = {"applied": True, "run_url": response.get("run_url"), "languages_after": after,
                             "confirmed": language in after, "at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
            print(f"  {row['repository']}: {'ok' if language in after else 'sent, language not listed yet'} {response.get('run_url') or ''}")
        except RuntimeError as exc:
            failures += 1
            row["result"] = {"applied": False, "error": str(exc)}
            print(f"  {row['repository']}: FAILED {exc}")
        time.sleep(args.pause)
        with open(args.plan, "w", encoding="utf-8") as handle:
            json.dump(plan, handle, indent=1)
    return 1 if failures else 0


def run_revert(args: argparse.Namespace) -> int:
    with open(args.plan, encoding="utf-8") as handle:
        plan = json.load(handle)
    rows = selected(plan, args, "revert")
    print(f"{len(rows)} repositor{'y' if len(rows) == 1 else 'ies'} to put back" + ("" if args.apply else " (dry run, add --apply to write)"))
    for row in rows:
        body = payload(row, canonical(row["raw_languages"]))
        if not args.apply:
            print(f"  would PATCH {row['repository']}: {json.dumps(body)}")
            continue
        try:
            patch(row, body)
            row["result"] = {"applied": False, "reverted": True}
            print(f"  {row['repository']}: reverted")
        except RuntimeError as exc:
            print(f"  {row['repository']}: FAILED {exc}")
        time.sleep(args.pause)
    if args.apply:
        with open(args.plan, "w", encoding="utf-8") as handle:
            json.dump(plan, handle, indent=1)
    return 0


def repos_from(args: argparse.Namespace) -> list[str]:
    """The repositories named with --only and --repos-file, as OWNER/REPO."""
    names = [name.strip() for name in args.only if name.strip()]
    if args.repos_file:
        with open(args.repos_file, encoding="utf-8") as handle:
            names += [line.strip() for line in handle if line.strip()]
    return [name if "/" in name else f"{args.org}/{name}" for name in names]


def without_language(languages: list[str], language: str) -> list[str]:
    """The canonical languages of a default setup without `language`, which may be given as an alias."""
    return [name for name in canonical(languages) if name != ALIASES.get(language, language)]


def run_remove(args: argparse.Namespace) -> int:
    """Take a language out of the default setup of the named repositories."""
    repos = repos_from(args)
    if not repos:
        print("name the repositories with --only or --repos-file", file=sys.stderr)
        return 2
    failures = 0
    for repo in repos:
        current = json.loads(gh("api", f"repos/{repo}/code-scanning/default-setup"))
        before = canonical(current.get("languages") or [])
        after = without_language(before, args.language)
        if after == before:
            print(f"  {repo}: does not analyze {args.language}")
            continue
        if not after:
            print(f"  {repo}: skipped, {args.language} is its only language")
            continue
        row = {"query_suite": current.get("query_suite"), "threat_model": current.get("threat_model"),
               "runner_type": current.get("runner_type"), "runner_label": current.get("runner_label") or None}
        if not args.apply:
            print(f"  would PATCH {repo}: {before} -> {after}")
            continue
        try:
            answer = gh("api", "-X", "PATCH", f"repos/{repo}/code-scanning/default-setup", payload=payload(row, after))
            print(f"  {repo}: {before} -> {after} {answer.strip()}")
        except RuntimeError as exc:
            failures += 1
            print(f"  {repo}: FAILED {exc}")
        time.sleep(args.pause)
    if not args.apply:
        print("dry run, add --apply to write")
    return 1 if failures else 0


def run_disable(args: argparse.Namespace) -> int:
    """Disable every workflow of the repositories' own that can still run, so that enabling them runs nothing."""
    repos = repos_from(args)
    if not repos:
        print("name the repositories with --only or --repos-file", file=sys.stderr)
        return 2

    def work(repo: str) -> tuple[str, list[tuple[int, str, str]]]:
        out = gh("api", "--paginate", f"repos/{repo}/actions/workflows?per_page=100", "--jq", ".workflows[]")
        listing = {"workflows": [json.loads(line) for line in out.splitlines() if line.strip()]}
        results = []
        for workflow in active_own_workflows(listing):
            if not args.apply:
                results.append((workflow["id"], workflow["path"], "would disable"))
                continue
            try:
                gh("api", "-X", "PUT", f"repos/{repo}/actions/workflows/{workflow['id']}/disable")
                results.append((workflow["id"], workflow["path"], "disabled"))
            except RuntimeError as exc:
                results.append((workflow["id"], workflow["path"], f"FAILED {exc}"))
        return repo, results

    failures = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for repo, results in pool.map(work, repos):
            failed = [r for r in results if r[2].startswith("FAILED")]
            failures += len(failed)
            print(f"  {repo}: {len(results)} active workflow(s) " + ("to disable" if not args.apply else "handled")
                  + (f", {len(failed)} failed: {failed[0][2]}" if failed else ""))
    if not args.apply:
        print("dry run, add --apply to write")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    plan_p = sub.add_parser("plan", help="read every repository and write the plan")
    plan_p.add_argument("--org", default=ORG)
    plan_p.add_argument("--language", default="actions")
    plan_p.add_argument("--out", required=True)
    plan_p.add_argument("--property", help="NAME=VALUE: also report how many of the repositories to enable have it")
    plan_p.add_argument("--workers", type=int, default=8)
    disable_p = sub.add_parser("disable-workflows", help="disable the repositories' own workflows that can still run")
    disable_p.add_argument("--org", default=ORG)
    disable_p.add_argument("--only", action="append", default=[], metavar="REPO", help="repository to handle; repeatable")
    disable_p.add_argument("--repos-file", help="a file with one repository per line")
    disable_p.add_argument("--workers", type=int, default=4)
    disable_p.add_argument("--apply", action="store_true", help="write to GitHub")
    remove_p = sub.add_parser("remove-language", help="take a language out of the default setup of the named repositories")
    remove_p.add_argument("--org", default=ORG)
    remove_p.add_argument("--language", required=True)
    remove_p.add_argument("--only", action="append", default=[], metavar="REPO", help="repository to handle; repeatable")
    remove_p.add_argument("--repos-file", help="a file with one repository per line")
    remove_p.add_argument("--pause", type=float, default=1.0, help="seconds between writes")
    remove_p.add_argument("--apply", action="store_true", help="write to GitHub")
    for name, text in (("apply", "add the language to the default setup of the planned repositories"),
                       ("revert", "put the earlier languages back")):
        p = sub.add_parser(name, help=text)
        p.add_argument("--plan", required=True)
        p.add_argument("--only", action="append", default=[], metavar="REPO", help="limit to these repositories; repeatable")
        p.add_argument("--property", help="NAME=VALUE: limit to repositories with this custom property value")
        p.add_argument("--pause", type=float, default=1.0, help="seconds between writes")
        p.add_argument("--apply", action="store_true", help="write to GitHub")
    args = parser.parse_args(argv)
    try:
        return {"plan": run_plan, "apply": run_apply, "revert": run_revert, "disable-workflows": run_disable,
                "remove-language": run_remove}[args.command](args)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
