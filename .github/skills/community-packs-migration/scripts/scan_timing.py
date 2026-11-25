#!/usr/bin/env python3
"""How long do the code scanning jobs of an organization take, and did a release make them slower?

Use it as the last step after a Community Packs release is live and the repositories have scanned with it. It
reads the default setup runs with the gh CLI and writes nothing to GitHub.

    scan_timing.py collect --org ORG [--property Synthetic=true] --out before.json
        Save the "Analyze (language)" jobs of the repositories (duration and steps) and, for the newest job of
        every repository and language, a summary of its log: the pack versions it used, the time of each phase
        and the evaluation time of every query. Run it before the release as well. Actions keeps runs for 90
        days by default, and the jobs before the release are the baseline.

    scan_timing.py packs --jobs after.json --version 0.9.2 [--since TIME] [--ours githubsecuritylab/rust/some-rule]
        Does the newest scan of every repository use the new pack version, did the configuration apply, and was
        the new query evaluated? A pair that has no scan since --since is not using it yet, and a language that
        default setup no longer has is ignored. Exit 1 when a pair is not on the version.

    scan_timing.py compare --jobs before.json --jobs after.json --cutoff 2026-11-24T15:00:00Z [--version 0.9.2]
        For every repository and language: the median job time before and after the cutoff (the time the
        release was published), the ratio and the difference. A pair is flagged when it takes at least --ratio
        times as long and at least --min-delta seconds longer. Exit 1 when one is flagged.

    scan_timing.py explain --jobs before.json --jobs after.json --cutoff ... [--repo R] [--language L] [--ours RULE]
        For the flagged pairs, or the pair you name: read both logs and split the increase into phases (setup,
        database, queries, results), then into new queries (yours, the other new Community Packs queries, stock
        queries), queries that got slower, and the repository itself (a different tree, more files).

The numbers come from the job log of the CodeQL Action. A query's evaluation time (`[3/99 eval 1.4s]`) overlaps
with the others (the CLI runs queries on several threads), so it ranks queries and does not add up to the wall
time of the phase. A job time varies by 20 to 30 percent from run to run on a hosted runner, which is why a pair
is flagged only for a ratio and an absolute difference together. The defaults name codeql-forks-felickz.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import datetime
import json
import re
import statistics
import subprocess
import sys
import time
import urllib.parse

ORG = "codeql-forks-felickz"
WORKFLOW_PATH = "dynamic/github-code-scanning/codeql"
DEFAULT_PROPERTY = "Synthetic=true"
CCP_SCOPE = "githubsecuritylab"
JOB_RE = re.compile(r"^Analyze \((?P<language>[^)]+)\)$")
DEFAULT_RATIO = 1.5
DEFAULT_MIN_DELTA = 60.0
# A cause that explains at least this share of an increase is called the cause.
SHARE = 0.5
# Queries run on several threads and many of them wait for the same shared computation, so the summed evaluation time
# of a job can be a multiple of its query phase. A runner has 4 threads: beyond this the sum says little about cost.
OVERLAP_WARN = 5.0
# How many jobs on each side of the cutoff the median is taken over.
KEEP = 3
SKIP_STEPS = ("Set up job", "Complete job")
# The phases of a job log, in order, found by the line that starts them. The time of a phase is the time up to the
# next one that the log has. Extraction happens inside `init` for build mode none, and in `extract` otherwise.
PHASES = (
    ("init", re.compile(r"^##\[group\]Run github/codeql-action/init@")),
    ("autobuild", re.compile(r"^##\[group\]Run github/codeql-action/autobuild@")),
    ("analyze", re.compile(r"^##\[group\]Run github/codeql-action/analyze@")),
    ("extract", re.compile(r"^##\[group\]Extracting ")),
    ("finalize", re.compile(r"^##\[group\]Finalizing ")),
    ("queries", re.compile(r"^##\[group\]Running queries for ")),
    ("upload", re.compile(r"^##\[group\]Uploading code scanning results")),
    ("cleanup", re.compile(r"^##\[group\]Cleaning up databases")),
    ("processing", re.compile(r"^##\[group\]Waiting for processing to finish")),
    ("post", re.compile(r"^Post job cleanup\.")),
)
# What the phases mean for a decision.
PHASE_GROUPS = {
    "setup": ("setup", "init", "analyze"),
    "database": ("autobuild", "extract", "finalize"),
    "queries": ("queries",),
    "results": ("upload", "cleanup", "processing", "post"),
}

LINE_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z) (.*)$")
EVAL_RE = re.compile(r"^\[(\d+)/(\d+) eval ([^\]]+)\] Evaluation done; writing results to (.+)\.bqrs\.?$")
INTERPRETED_RE = re.compile(r'^Interpreted \w+ query ".*" \(([^()]*)\) at path (.+)\.bqrs\.?$')
INSTALLED_RE = re.compile(r"^Installed (?:[a-z]+ )*?(\S+/\S+?)@(\S+?)(?: \((\w+)\))?$")
RECORDING_RE = re.compile(r"^Recording pack reference (\S+) at (\S+?)\.?$")
CONFIG_RE = re.compile(r"^Using configuration file input from repository property: (\S+)")
CONFIG_IGNORED_RE = re.compile(
    r"Ignoring configuration file input from repository property|"
    r"Both a config file and config input were provided\. Ignoring config file\.")
BUNDLE_RE = re.compile(r"/hostedtoolcache/CodeQL/([\d.]+)/")
USING_BUNDLE_RE = re.compile(r"^Using CodeQL CLI version (\S+)")
SCANNED_RE = re.compile(r"^CodeQL scanned ([\d,]+) out of ([\d,]+) .*?files? in this invocation")
TIME_RE = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?Z?$")
DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(ms|h|m|s)")
UNIT_SECONDS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}


# ------------------------------------------------------------------------ gh


class Unavailable(RuntimeError):
    """The run or its log no longer exists (HTTP 404 or 410)."""


def gh(*args: str, retries: int = 3) -> str:
    error = ""
    for attempt in range(retries):
        proc = subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
        if proc.returncode == 0:
            return proc.stdout
        error = (proc.stderr or proc.stdout).strip()
        if re.search(r"HTTP (404|410)", error):
            raise Unavailable(error[:300])
        if "unknown flag" in error:
            break
        time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"gh {' '.join(args[:2])} failed: {error[:300]}")


def gh_lines(path: str, jq: str) -> list[dict]:
    """Every item of a paginated list endpoint, one JSON object per line from ``--jq``."""
    out = gh("api", "--paginate", path, "--jq", jq)
    return [json.loads(line) for line in out.splitlines() if line.strip()]


# ------------------------------------------------------------------ small parsers


def parse_time(value: str) -> datetime.datetime:
    m = TIME_RE.match(value.strip())
    if not m:
        raise ValueError(f"not a UTC ISO 8601 time: {value!r}")
    year, month, day, hour, minute, second = (int(x) for x in m.groups()[:6])
    micro = int((m.group(7) or "0")[:6].ljust(6, "0"))
    return datetime.datetime(year, month, day, hour, minute, second, micro, tzinfo=datetime.timezone.utc)


def stamp(value: datetime.datetime) -> str:
    return value.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_time(value: str) -> str:
    """A time argument as `YYYY-MM-DDTHH:MM:SSZ`; a date alone means midnight UTC."""
    value = value.strip()
    if re.fullmatch(r"\d{4}-\d\d-\d\d", value):
        value += "T00:00:00Z"
    return stamp(parse_time(value))


def seconds_between(start: str, end: str) -> float:
    return (parse_time(end) - parse_time(start)).total_seconds()


def parse_duration(text: str) -> float | None:
    """Seconds from the CLI's duration text: `163ms`, `1.4s`, `1m8s`, `2m 5s`, `1h2m3s`."""
    tokens = DURATION_RE.findall(text)
    if not tokens:
        return None
    return round(sum(float(number) * UNIT_SECONDS[unit] for number, unit in tokens), 3)


def fmt_s(seconds: float | None) -> str:
    if seconds is None:
        return "?"
    return f"{seconds:.1f} s" if abs(seconds) < 10 else f"{seconds:.0f} s"


def fmt_delta(seconds: float) -> str:
    return ("+" if seconds >= 0 else "-") + fmt_s(abs(seconds))


# ------------------------------------------------------------------------ log


def summarize_log(text: str) -> dict:
    """What the log of one `Analyze (language)` job says about the packs, the phases and the queries."""
    markers: dict[str, datetime.datetime] = {}
    first = last = None
    config = bundle = files = None
    config_ignored = per_language = False
    installed: dict[str, str] = {}
    used: dict[str, str] = {}
    evals: list[tuple[str, float | None]] = []
    rules: dict[str, str] = {}
    for raw in text.splitlines():
        m = LINE_RE.match(raw.lstrip("\ufeff").rstrip("\r"))
        if not m:
            continue
        when, line = parse_time(m.group(1)), m.group(2)
        first = first or when
        last = when
        if bundle is None:
            # "Using CodeQL CLI version" names the bundle, and so does its toolcache path (but not the path of an old
            # version that the action deletes, and a per-language bundle is unpacked in the runner's temp directory)
            if line.startswith("Using CodeQL CLI version"):
                b = USING_BUNDLE_RE.match(line)
                bundle = b.group(1) if b else None
            elif "/hostedtoolcache/CodeQL/" in line and not line.startswith("Deleted the CodeQL tools"):
                b = BUNDLE_RE.search(line)
                bundle = b.group(1) if b else None
        if line.startswith("Selected the per-language CodeQL bundle"):
            per_language = True
        if line.startswith("##[group]") or line.startswith("Post job cleanup."):
            for name, pattern in PHASES:
                if name not in markers and pattern.match(line):
                    markers[name] = when
            continue
        if line.startswith("["):
            e = EVAL_RE.match(line)
            if e:
                evals.append((e.group(4), parse_duration(e.group(3))))
            continue
        if line.startswith("Interpreted "):
            i = INTERPRETED_RE.match(line)
            if i:
                rules[i.group(2).split("/results/", 1)[-1]] = i.group(1)
            continue
        if line.startswith("Installed "):
            i = INSTALLED_RE.match(line)
            if i:
                installed[i.group(1)] = i.group(2)
            continue
        if line.startswith("Recording pack reference"):
            r = RECORDING_RE.match(line)
            if r:
                used[r.group(1)] = r.group(2).rsplit("/", 1)[-1]
            continue
        if line.startswith("Using configuration file input"):
            c = CONFIG_RE.match(line)
            config = c.group(1) if c else config
        elif CONFIG_IGNORED_RE.search(line):
            config_ignored = True
        elif line.startswith("CodeQL scanned"):
            s = SCANNED_RE.match(line)
            if s:
                files = [int(s.group(1).replace(",", "")), int(s.group(2).replace(",", ""))]
    queries = [{"path": path, "eval_s": seconds, "rule": rules.get(path)} for path, seconds in evals]
    return {
        "config": config, "config_ignored": config_ignored, "bundle": bundle,
        "bundle_kind": None if bundle is None else "per-language" if per_language else "full",
        "installed": installed, "used": used,
        "files": files, "phases": phase_seconds(markers, first, last), "total_s": seconds_or_none(first, last),
        "queries": queries,
    }


def seconds_or_none(first: datetime.datetime | None, last: datetime.datetime | None) -> float | None:
    return round((last - first).total_seconds(), 1) if first and last else None


def phase_seconds(markers: dict[str, datetime.datetime], first: datetime.datetime | None,
                  last: datetime.datetime | None) -> dict[str, float]:
    """The time from each phase marker to the next one, and from the start of the log to the first marker as `setup`."""
    if not markers or first is None or last is None:
        return {}
    points = sorted(((when, name) for name, when in markers.items()), key=lambda p: (p[0], p[1]))
    if points[0][0] > first:
        points.insert(0, (first, "setup"))
    phases = {}
    for index, (when, name) in enumerate(points):
        end = points[index + 1][0] if index + 1 < len(points) else last
        phases[name] = round((end - when).total_seconds(), 1)
    return phases


def pack_scope(path: str) -> str:
    return path.split("/", 1)[0]


def pack_of(path: str) -> str:
    return "/".join(path.split("/")[:2])


def ccp_version(log: dict | None) -> str | None:
    """The Community Packs version that the job used: the queries pack it recorded, else any installed pack of the family."""
    if not log:
        return None
    for source in (log.get("used") or {}, log.get("installed") or {}):
        versions = sorted(v for pack, v in source.items() if pack_scope(pack) == CCP_SCOPE)
        if versions:
            return versions[-1]
    return None


# ----------------------------------------------------------------------- collect


def job_record(repo: str, run: dict, job: dict) -> dict | None:
    """The fields of one Analyze job that a comparison needs, or None for any other job."""
    match = JOB_RE.match(job.get("name") or "")
    if not match or not job.get("started_at"):
        return None
    done = job.get("completed_at")
    steps = {}
    for step in job.get("steps") or []:
        name = step.get("name", "")
        if step.get("started_at") and step.get("completed_at") and not name.startswith("Post ") and name not in SKIP_STEPS:
            steps[name] = round(seconds_between(step["started_at"], step["completed_at"]), 1)
    return {
        "repo": repo, "run_id": run["id"], "job_id": job["id"], "run": run.get("name"), "event": run.get("event"),
        "head_sha": run.get("head_sha"), "tree_id": run.get("tree_id"), "run_created_at": run["created_at"],
        "language": match.group("language"),
        "conclusion": job.get("conclusion"), "started_at": job["started_at"], "completed_at": done,
        "duration_s": round(seconds_between(job["started_at"], done), 1) if done else None,
        "queued_s": round(seconds_between(job["created_at"], job["started_at"]), 1) if job.get("created_at") else None,
        "steps": steps,
    }


def repositories(args: argparse.Namespace) -> list[str]:
    if args.repo:
        return sorted(set(args.repo))
    if args.repos_file:
        with open(args.repos_file, encoding="utf-8") as handle:
            return sorted({line.strip() for line in handle if line.strip() and not line.startswith("#")})
    name, _, value = args.property.partition("=")
    rows = gh_lines(f"orgs/{args.org}/properties/values?per_page=100", ".[]")
    return sorted(r["repository_name"] for r in rows
                  if any(p["property_name"] == name and p["value"] == value for p in r.get("properties") or []))


def collect_repository(org: str, repo: str, since: str | None, max_runs: int) -> tuple[list[dict], str | None]:
    """The Analyze jobs of the newest default setup runs of one repository, and an error text if it failed."""
    query = "per_page=100&event=dynamic&status=completed"
    if since:
        query += "&created=" + urllib.parse.quote(">=" + since[:10])
    jq = ('.workflow_runs[] | select(.path == "%s") | '
          "{id, name, event, conclusion, created_at, run_started_at, head_sha, tree_id: .head_commit.tree_id}") % WORKFLOW_PATH
    try:
        runs = gh_lines(f"repos/{org}/{repo}/actions/runs?{query}", jq)
        runs.sort(key=lambda r: r["created_at"], reverse=True)
        records = []
        for run in runs[:max_runs]:
            for job in gh_lines(f"repos/{org}/{repo}/actions/runs/{run['id']}/jobs?per_page=100", ".jobs[]"):
                record = job_record(repo, run, job)
                if record:
                    records.append(record)
        return records, None
    except (RuntimeError, ValueError) as exc:
        return [], f"{repo}: {exc}"


def fetch_log(org: str, job: dict) -> tuple[dict | None, str | None]:
    """The summary of a job log and no error, or no summary and the reason (GitHub keeps logs for 90 days by default).

    gh refuses a log that has terminal escape sequences (a build tool that colors its output) unless it is told to
    print it, and older versions of gh do not have that flag.
    """
    path = f"repos/{org}/{job['repo']}/actions/jobs/{job['job_id']}/logs"
    try:
        try:
            text = gh("api", "--allow-escape-sequences", path)
        except RuntimeError as exc:
            if "unknown flag" not in str(exc):
                raise
            text = gh("api", path)
        return summarize_log(text), None
    except Unavailable:
        return None, "the log is no longer available"
    except RuntimeError as exc:
        return None, str(exc)


def newest_successful(jobs: list[dict]) -> list[dict]:
    """The newest successful job of every repository and language."""
    return list(newest_by_pair([j for j in jobs if j.get("conclusion") == "success"]).values())


def run_collect(args: argparse.Namespace) -> int:
    repos = repositories(args)
    since = normalize_time(args.since) if args.since else None
    print(f"{len(repos)} repositories", file=sys.stderr)
    jobs: list[dict] = []
    errors: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for records, error in pool.map(lambda r: collect_repository(args.org, r, since, args.max_runs), repos):
            jobs += records
            if error:
                errors.append(error)
    wanted = {"none": [], "latest": newest_successful(jobs), "all": [j for j in jobs if j.get("conclusion") == "success"]}[args.logs]
    missing: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for job, (log, error) in zip(wanted, pool.map(lambda j: fetch_log(args.org, j), wanted)):
            if log is None:
                job["log_error"] = error
                missing.append(f"{job['repo']} {job['language']}: {error}")
            else:
                job["log"] = log
    data = {"org": args.org, "collected_at": stamp(datetime.datetime.now(datetime.timezone.utc)),
            "property": None if args.repo or args.repos_file else args.property, "workflow_path": WORKFLOW_PATH, "jobs": jobs}
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=1)
    pairs = {(j["repo"], j["language"]) for j in jobs}
    print(f"{len(jobs)} jobs of {len(pairs)} repository and language pairs, {len(wanted) - len(missing)} log summaries "
          f"({len(missing)} logs missing), written to {args.out}")
    for line in errors + missing:
        print(f"  failed: {line}", file=sys.stderr)
    return 0 if not errors else 1


def load_jobs(paths: list[str]) -> tuple[str, list[dict]]:
    """The jobs of several collect files, one record per job id (the one with a log summary wins), and the organization."""
    by_id: dict[int, dict] = {}
    org = ORG
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        org = data.get("org", org)
        for job in data["jobs"]:
            known = by_id.get(job["job_id"])
            if known is None or ("log" in job and "log" not in known):
                by_id[job["job_id"]] = job
    return org, list(by_id.values())


# ------------------------------------------------------------------------- packs


def newest_by_pair(jobs: list[dict]) -> dict[tuple[str, str], dict]:
    """The newest job of every repository and language, whatever its conclusion."""
    newest: dict[tuple[str, str], dict] = {}
    for job in jobs:
        key = (job["repo"], job["language"])
        if key not in newest or job["run_created_at"] > newest[key]["run_created_at"]:
            newest[key] = job
    return newest


def pack_state(job: dict | None, newest: dict, version: str) -> tuple[str, str]:
    """Whether the newest successful scan of a pair used the version, as a code and a reason."""
    if job is None:
        return "no_success", f"no successful scan (the newest, {newest['run_created_at']}, ended in {newest.get('conclusion')})"
    log = job.get("log")
    if not log:
        return "no_log", "no log summary (collect with --logs latest)"
    used = ccp_version(log)
    if log.get("config_ignored"):
        return "config_ignored", "the configuration file was ignored (the repository property did not apply)"
    if used is None:
        return "no_pack", ("no Community Packs pack in the log: the scan is older than the configuration, or the "
                           "configuration did not apply")
    if used != version:
        return "old_pack", f"uses {used}, wanted {version}"
    return "ok", ""


def configured_languages(org: str, repo: str) -> set[str] | None:
    """The languages in the default setup of a repository now, or None when they cannot be read."""
    try:
        out = gh("api", f"repos/{org}/{repo}/code-scanning/default-setup", "--jq", ".languages[]")
    except RuntimeError:
        return None
    return {line.strip() for line in out.splitlines() if line.strip()}


def run_packs(args: argparse.Namespace) -> int:
    org, jobs = load_jobs(args.jobs)
    since = normalize_time(args.since) if args.since else None
    recent = [j for j in jobs if not since or j["run_created_at"] >= since]
    newest = newest_by_pair(recent)
    successful = {(j["repo"], j["language"]): j for j in newest_successful(recent)}
    configured: dict[str, set[str] | None] = {}
    rows = []
    for key in sorted({(j["repo"], j["language"]) for j in jobs}):
        job = successful.get(key)
        if key not in newest:
            state, why = "not_scanned", f"no scan since {since} (not scanned yet)"
        else:
            state, why = pack_state(job, newest[key], args.version)
        if state != "ok":
            # a language that default setup no longer has is not scanned, so it cannot use any pack
            if key[0] not in configured:
                configured[key[0]] = configured_languages(org, key[0])
            if configured[key[0]] is not None and key[1] not in configured[key[0]]:
                state, why = "dropped", "the language is no longer in default setup"
        log = (job or {}).get("log")
        hits = [q for q in (log or {}).get("queries", []) if is_ours(q, args.ours)] if args.ours else []
        rows.append({
            "repo": key[0], "language": key[1], "run": job["run_created_at"] if job else None, "state": state, "why": why,
            "version": ccp_version(log), "config": (log or {}).get("config"),
            "later_failure": bool(job and key in newest and newest[key] is not job and newest[key].get("conclusion") != "success"),
            "ours_evaluated": bool(hits), "ours_s": round(sum(q["eval_s"] or 0 for q in hits), 2) if hits else None,
        })
    bad = [r for r in rows if r["state"] not in ("ok", "dropped")]
    if args.json:
        print(json.dumps({"version": args.version, "since": since, "ours": args.ours, "rows": rows}, indent=1))
        return 1 if bad else 0
    counts = collections.Counter(r["version"] if r["state"] == "ok" else r["state"] for r in rows)
    print(f"newest scan of {len(rows)} repository and language pairs, by Community Packs version used: "
          + ", ".join(f"{v}: {n}" for v, n in sorted(counts.items())))
    for r in bad:
        print(f"  not on {args.version}: {r['repo']} {r['language']}" + (f" (scan {r['run']})" if r["run"] else "") + f": {r['why']}")
    dropped = [r for r in rows if r["state"] == "dropped"]
    if dropped:
        print("  ignored, no longer in default setup: " + ", ".join(f"{r['repo']} {r['language']}" for r in dropped))
    for r in rows:
        if r["later_failure"]:
            print(f"  note: {r['repo']} {r['language']} has a newer scan that did not succeed")
    if args.ours:
        ran = [r for r in rows if r["ours_evaluated"]]
        print(f"evaluated {', '.join(args.ours)}: {len(ran)} of {len(rows) - len(dropped)} pairs"
              + (f" ({min(r['ours_s'] for r in ran):.1f} to {max(r['ours_s'] for r in ran):.1f} s)" if ran else ""))
    return 1 if bad else 0


def is_ours(query: dict, ours: list[str]) -> bool:
    """A query matches a rule id, a pack relative path, a file name without the extension, or the end of the path."""
    path = query["path"]
    return any(token in (query.get("rule"), path, path.rsplit("/", 1)[-1]) or path.endswith("/" + token) for token in ours)


# ----------------------------------------------------------------------- compare


def step_delta(before: list[dict], after: list[dict], step: str) -> float | None:
    b = [j["steps"][step] for j in before if step in j.get("steps", {})]
    a = [j["steps"][step] for j in after if step in j.get("steps", {})]
    return round(statistics.median(a) - statistics.median(b), 1) if a and b else None


def compare_jobs(jobs: list[dict], cutoff: str, version: str | None, keep: int = KEEP, ratio: float = DEFAULT_RATIO,
                 min_delta: float = DEFAULT_MIN_DELTA, since: str | None = None) -> dict:
    """The median job time before and after the cutoff for every repository and language."""
    groups: dict[tuple[str, str], list[dict]] = collections.defaultdict(list)
    for job in jobs:
        if job.get("conclusion") == "success" and job.get("duration_s") is not None and (not since or job["run_created_at"] >= since):
            groups[(job["repo"], job["language"])].append(job)
    pairs, skipped = [], collections.Counter()
    for (repo, language), group in sorted(groups.items()):
        before = sorted((j for j in group if j["run_created_at"] < cutoff), key=lambda j: j["run_created_at"], reverse=True)[:keep]
        after = []
        for job in sorted((j for j in group if j["run_created_at"] >= cutoff), key=lambda j: j["run_created_at"]):
            seen = ccp_version(job.get("log"))
            if version and seen and seen != version:
                skipped["after job still on an older pack"] += 1
                continue
            if version and not seen:
                skipped["after job without a log summary (pack not verified)"] += 1
            after.append(job)
            if len(after) == keep:
                break
        if not before or not after:
            skipped["pair without a job on each side of the cutoff"] += 1
            continue
        before_s = statistics.median(j["duration_s"] for j in before)
        after_s = statistics.median(j["duration_s"] for j in after)
        delta = round(after_s - before_s, 1)
        factor = round(after_s / max(before_s, 1.0), 2)
        pairs.append({
            "repo": repo, "language": language, "before_s": before_s, "after_s": after_s, "delta_s": delta, "ratio": factor,
            "flagged": factor >= ratio and delta >= min_delta,
            "before": [j["job_id"] for j in before], "after": [j["job_id"] for j in after],
            "steps": {step: step_delta(before, after, step) for step in ("Initialize CodeQL", "Autobuild", "Perform CodeQL Analysis")},
        })
    languages = {}
    for language in sorted({p["language"] for p in pairs}):
        rows = [p for p in pairs if p["language"] == language]
        languages[language] = {
            "pairs": len(rows), "flagged": sum(p["flagged"] for p in rows),
            "median_before_s": statistics.median(p["before_s"] for p in rows),
            "median_after_s": statistics.median(p["after_s"] for p in rows),
            "median_ratio": round(statistics.median(p["ratio"] for p in rows), 2),
        }
    return {"cutoff": cutoff, "version": version, "since": since, "keep": keep, "ratio": ratio, "min_delta_s": min_delta,
            "pairs": pairs, "flagged": [p for p in pairs if p["flagged"]], "languages": languages, "not_compared": dict(skipped)}


def run_compare(args: argparse.Namespace) -> int:
    _, jobs = load_jobs(args.jobs)
    result = compare_jobs(jobs, normalize_time(args.cutoff), args.version, args.keep, args.ratio, args.min_delta,
                          normalize_time(args.since) if args.since else None)
    if args.json:
        print(json.dumps(result, indent=1))
        return 1 if result["flagged"] else 0
    print(f"scan time before and after {result['cutoff']}" + (f" (release {args.version})" if args.version else "")
          + f": {len(result['pairs'])} repository and language pairs compared, median of up to {args.keep} jobs per side")
    print(f"{'language':<24}{'pairs':>6}{'before':>10}{'after':>10}{'ratio':>8}{'flagged':>9}")
    for language, row in result["languages"].items():
        print(f"{language:<24}{row['pairs']:>6}{fmt_s(row['median_before_s']):>10}{fmt_s(row['median_after_s']):>10}"
              f"{row['median_ratio']:>8.2f}{row['flagged']:>9}")
    flagged = sorted(result["flagged"], key=lambda p: -p["delta_s"])
    print(f"flagged (at least {args.ratio:g} times as long and {args.min_delta:g} s longer): {len(flagged)}")
    for p in flagged:
        steps = ", ".join(f"{name.split()[0].lower()} {fmt_delta(d)}" for name, d in p["steps"].items() if d is not None)
        print(f"  {p['repo']} {p['language']}: {fmt_s(p['before_s'])} -> {fmt_s(p['after_s'])} ({fmt_delta(p['delta_s'])}, "
              f"x{p['ratio']:.2f}); {steps}")
    for why, count in result["not_compared"].items():
        print(f"not compared: {count} x {why}")
    if flagged:
        print("next: scan_timing.py explain with the same --jobs and --cutoff reads the logs of the flagged pairs")
    else:
        print("no massive change: no pair crosses the thresholds")
    return 1 if flagged else 0


# ----------------------------------------------------------------------- explain


def query_changes(before: list[dict], after: list[dict], ours: list[str], top: int) -> dict:
    """The queries that are new, gone or slower between two logs, with the evaluation time of each."""
    old = {q["path"]: q for q in before}
    new = {q["path"]: q for q in after}

    def entry(q: dict) -> dict:
        return {"path": q["path"], "pack": pack_of(q["path"]), "rule": q.get("rule"), "eval_s": q["eval_s"] or 0.0,
                "ccp": pack_scope(q["path"]) == CCP_SCOPE, "ours": is_ours(q, ours)}

    added = sorted((entry(q) for p, q in new.items() if p not in old), key=lambda e: -e["eval_s"])
    removed = sorted((entry(q) for p, q in old.items() if p not in new), key=lambda e: -e["eval_s"])
    changed = []
    for path, q in new.items():
        if path in old:
            was, now = old[path]["eval_s"] or 0.0, q["eval_s"] or 0.0
            changed.append({"path": path, "before_s": was, "after_s": now, "delta_s": round(now - was, 3)})
    grown = sorted((c for c in changed if c["delta_s"] > 0), key=lambda c: -c["delta_s"])
    total = lambda queries: round(sum((q["eval_s"] or 0.0) for q in queries), 2)  # noqa: E731
    ccp = lambda queries: [q for q in queries if pack_scope(q["path"]) == CCP_SCOPE]  # noqa: E731
    return {
        "before_count": len(old), "after_count": len(new), "before_s": total(before), "after_s": total(after),
        "ccp_before_count": len(ccp(before)), "ccp_after_count": len(ccp(after)),
        "ccp_before_s": total(ccp(before)), "ccp_after_s": total(ccp(after)),
        "new_count": len(added), "new_s": round(sum(e["eval_s"] for e in added), 2),
        "new_ccp_s": round(sum(e["eval_s"] for e in added if e["ccp"] and not e["ours"]), 2),
        "new_ours_s": round(sum(e["eval_s"] for e in added if e["ours"]), 2),
        "new_other_s": round(sum(e["eval_s"] for e in added if not e["ccp"] and not e["ours"]), 2),
        "removed_count": len(removed), "removed_s": round(sum(e["eval_s"] for e in removed), 2),
        "grown_s": round(sum(c["delta_s"] for c in grown), 2),
        "new": added[:top], "removed": removed[:top], "grown": grown[:top],
    }


def group_deltas(before: dict[str, float], after: dict[str, float]) -> dict[str, dict]:
    out = {}
    for group, names in PHASE_GROUPS.items():
        b = round(sum(before.get(n, 0.0) for n in names), 1)
        a = round(sum(after.get(n, 0.0) for n in names), 1)
        out[group] = {"before": b, "after": a, "delta": round(a - b, 1)}
    return out


def shift(pair: tuple, missing: str = "?") -> str:
    """One value when both sides agree, else `before -> after`; a value that is not there is `missing`."""
    a, b = (missing if v is None else v for v in pair)
    return str(a) if a == b else f"{a} -> {b}"


def caution(q: dict) -> str:
    """A sentence for a job whose queries overlap so much that their summed evaluation time is not a cost."""
    if q.get("overlap") and q["overlap"] > OVERLAP_WARN:
        return (f". Caution: the summed evaluation time is {q['overlap']:.0f} times the query phase, so many queries wait for the "
                "same shared computation and a long time says that a query needed it, not that it is expensive. Judge the new "
                "queries by the phase time, and check whether stock queries show the same times")
    return ""


def decide(delta: float, groups: dict[str, dict], q: dict, context: dict) -> dict:
    """The largest cause of an increase, as a code and a sentence. A hint: the numbers above it are the evidence."""
    if delta < 1.0:
        return {"code": "not_slower", "text": "this job is not slower"}
    positive = {g: v["delta"] for g, v in groups.items() if v["delta"] > 0}
    top = max(positive, key=positive.get) if positive else None
    if top is None or positive[top] < SHARE * delta:
        moved = ", ".join(f"{g} {fmt_delta(d)}" for g, d in sorted(positive.items(), key=lambda p: -p[1]))
        return {"code": "spread", "text": f"no single phase explains it ({moved or 'no phase got longer'}): several small changes "
                                          "or runner variance, so read the phases and the new queries above"}
    share = f"{positive[top]:.0f} of the {delta:.0f} s"
    bundle = context["bundle"]
    if top == "queries":
        if q["before_count"] == 0 and q["after_count"] == 0:
            return {"code": "queries", "text": f"the query phase is {share} longer, but the logs have no per-query evaluation lines "
                                               "(another CodeQL Action version?)"}
        added = q["new_s"]
        total = added + q["grown_s"]
        if total <= 0:
            return {"code": "queries", "text": f"the query phase is {share} longer, but no query's own evaluation time grew"}
        new_share = added / total
        if new_share >= SHARE:
            if q["new_ours_s"] >= SHARE * added:
                who = "mostly the new query you are verifying"
            elif q["new_ccp_s"] >= SHARE * added:
                who = "mostly other new Community Packs queries, not yours"
            else:
                who = "mostly new queries that are not from Community Packs"
            return {"code": "new_queries", "text": f"the query phase is {share} longer: {q['new_count']} new queries are {new_share:.0%} of "
                                                    f"the extra evaluation time, {who} (their evaluation times, which overlap: yours "
                                                    f"{q['new_ours_s']:.1f} s, other Community Packs {q['new_ccp_s']:.1f} s, other "
                                                    f"{q['new_other_s']:.1f} s)" + caution(q)}
        why = (f"the CodeQL bundle changed from {bundle[0]} to {bundle[1]}, so the stock queries changed too"
               if bundle[0] != bundle[1] else "same bundle")
        extra = "; the repository changed too" if context["repo_changed"] or context["files_changed"] else ""
        return {"code": "slower_queries", "text": f"the query phase is {share} longer: queries that were already there are "
                                                    f"{1 - new_share:.0%} of the extra evaluation time ({why}){extra}" + caution(q)}
    if top == "database":
        if context["repo_changed"] or context["files_changed"]:
            return {"code": "repository", "text": f"building the database took {share} longer and the repository changed "
                                                  "(a different tree or number of files): the code is bigger, not the queries"}
        return {"code": "database_variance", "text": f"building the database took {share} longer with the same content and "
                                                     "files: runner variance, scan again to confirm"}
    if top == "setup":
        return {"code": "setup", "text": f"CodeQL tools, packs and the checkout took {share} longer (bundle {shift(bundle)}, "
                                         f"{shift(context['bundle_kind'])} bundle, {shift(context['packs'])} packs installed); "
                                         "downloads vary with the runner and the network"}
    return {"code": "results", "text": f"uploading and processing the results took {share} longer, which happens on GitHub's side"}


def attribute(before: dict, after: dict, before_log: dict, after_log: dict, ours: list[str], top: int) -> dict:
    delta = round(after["duration_s"] - before["duration_s"], 1)
    groups = group_deltas(before_log.get("phases") or {}, after_log.get("phases") or {})
    q = query_changes(before_log.get("queries") or [], after_log.get("queries") or [], ours, top)
    wall = groups["queries"]["after"]
    q["overlap"] = round(q["after_s"] / wall, 1) if wall else None
    bundle = (before_log.get("bundle"), after_log.get("bundle"))
    # an empty commit, which is how a scan is started, changes the commit and not the tree
    tree = (before.get("tree_id"), after.get("tree_id"))
    context = {
        "bundle": bundle, "bundle_kind": (before_log.get("bundle_kind"), after_log.get("bundle_kind")),
        "packs": (len(before_log.get("installed") or {}), len(after_log.get("installed") or {})),
        "repo_changed": bool(tree[0] and tree[1] and tree[0] != tree[1]),
        "files_changed": bool(before_log.get("files") and after_log.get("files") and before_log["files"] != after_log["files"]),
    }
    return {
        "repo": after["repo"], "language": after["language"], "before_s": before["duration_s"], "after_s": after["duration_s"],
        "delta_s": delta, "before_job": before["job_id"], "after_job": after["job_id"],
        "version": (ccp_version(before_log), ccp_version(after_log)), "bundle": bundle,
        "bundle_kind": context["bundle_kind"], "packs": context["packs"],
        "config": (before_log.get("config"), after_log.get("config")),
        "commit": (before.get("head_sha"), after.get("head_sha")), "tree": tree,
        "files": (before_log.get("files"), after_log.get("files")),
        "phases": groups, "queries": q, "verdict": decide(delta, groups, q, context),
    }


def closest_pair(group: list[dict], cutoff: str, version: str | None) -> tuple[dict, dict] | None:
    """The newest successful job before the cutoff and the first one after it that uses the version."""
    ok = [j for j in group if j.get("conclusion") == "success" and j.get("duration_s") is not None]
    before = sorted((j for j in ok if j["run_created_at"] < cutoff), key=lambda j: j["run_created_at"])
    after = sorted((j for j in ok if j["run_created_at"] >= cutoff), key=lambda j: j["run_created_at"])
    if version:
        after = [j for j in after if ccp_version(j.get("log")) in (None, version)]
    return (before[-1], after[0]) if before and after else None


def print_explanation(e: dict, top: int) -> None:
    q, p = e["queries"], e["phases"]
    print(f"== {e['repo']} {e['language']}: {fmt_s(e['before_s'])} -> {fmt_s(e['after_s'])} ({fmt_delta(e['delta_s'])})")
    commit = tuple((c or "")[:7] or None for c in e["commit"])
    files = tuple(None if f is None else f"{f[0]}/{f[1]}" for f in e["files"])
    content = "unknown" if not all(e["tree"]) else "same" if e["tree"][0] == e["tree"][1] else "changed"
    print(f"   Community Packs {shift(e['version'], 'none')}, bundle {shift(e['bundle'])} ({shift(e['bundle_kind'])}), "
          f"{shift(e['packs'])} packs installed, config "
          f"{'unchanged' if e['config'][0] == e['config'][1] else shift(e['config'], 'none')}")
    print(f"   repository: commit {shift(commit)}, content {content}, files scanned {shift(files)}")
    print("   phases: " + " | ".join(f"{g} {fmt_s(v['before'])} -> {fmt_s(v['after'])} ({fmt_delta(v['delta'])})" for g, v in p.items()))
    print(f"   queries evaluated: {q['before_count']} -> {q['after_count']} ({q['new_count']} new, {q['removed_count']} gone); "
          f"summed evaluation time {fmt_s(q['before_s'])} -> {fmt_s(q['after_s'])} (queries overlap, so this is not the phase time)")
    part = lambda a, b: f"{a / b:.1%}" if b else "0%"  # noqa: E731
    print(f"   Community Packs queries: {q['ccp_before_count']} -> {q['ccp_after_count']} evaluated, summed evaluation time "
          f"{fmt_s(q['ccp_before_s'])} ({part(q['ccp_before_s'], q['before_s'])} of all) -> "
          f"{fmt_s(q['ccp_after_s'])} ({part(q['ccp_after_s'], q['after_s'])})")
    for item in q["new"][:top]:
        tag = " [yours]" if item["ours"] else " [Community Packs]" if item["ccp"] else ""
        print(f"   new {fmt_s(item['eval_s']):>8}  {item['path']}" + (f" ({item['rule']})" if item["rule"] else "") + tag)
    for item in q["grown"][:top]:
        print(f"   slower {fmt_delta(item['delta_s']):>8}  {item['path']} ({fmt_s(item['before_s'])} -> {fmt_s(item['after_s'])})")
    print(f"   verdict ({e['verdict']['code']}): {e['verdict']['text']}")


def explain_targets(result: dict) -> list[tuple[str, str]]:
    """The flagged pairs, the largest increase first."""
    return [(p["repo"], p["language"]) for p in sorted(result["flagged"], key=lambda p: -p["delta_s"])]


def run_explain(args: argparse.Namespace) -> int:
    org, jobs = load_jobs(args.jobs)
    cutoff = normalize_time(args.cutoff)
    since = normalize_time(args.since) if args.since else None
    if args.repo or args.language:
        targets = sorted({(j["repo"], j["language"]) for j in jobs
                          if (not args.repo or j["repo"] == args.repo) and (not args.language or j["language"] == args.language)})
    else:
        targets = explain_targets(compare_jobs(jobs, cutoff, args.version, KEEP, args.ratio, args.min_delta, since))
    groups: dict[tuple[str, str], list[dict]] = collections.defaultdict(list)
    for job in jobs:
        if not since or job["run_created_at"] >= since:
            groups[(job["repo"], job["language"])].append(job)
    explained = []
    for repo, language in targets[:args.limit]:
        pair = closest_pair(groups[(repo, language)], cutoff, args.version)
        if not pair:
            print(f"== {repo} {language}: no job on each side of the cutoff")
            continue
        logs = []
        for job in pair:
            log = job.get("log")
            if log is None:
                log, error = fetch_log(org, job)
                if error:
                    print(f"== {repo} {language}: {error}", file=sys.stderr)
            logs.append(log)
        if not all(logs):
            print(f"== {repo} {language}: a log is missing (collect with --logs latest before the release, and keep the file)")
            continue
        explained.append(attribute(pair[0], pair[1], logs[0], logs[1], args.ours or [], args.top))
    if args.json:
        print(json.dumps(explained, indent=1))
    else:
        for item in explained:
            print_explanation(item, args.top)
        if len(targets) > args.limit:
            print(f"{len(targets) - args.limit} more flagged pairs, raise --limit to read them")
        if not targets:
            print("nothing flagged: no pair to explain (name one with --repo and --language)")
    return 0


# --------------------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="save the Analyze jobs of the repositories and the logs of the newest ones")
    collect.add_argument("--org", default=ORG)
    collect.add_argument("--property", default=DEFAULT_PROPERTY, help="NAME=VALUE: only repositories with this custom property value")
    collect.add_argument("--repo", action="append", default=[], help="a repository name; repeatable, instead of --property")
    collect.add_argument("--repos-file", help="one repository name per line, instead of --property")
    collect.add_argument("--since", help="only runs created on or after this date")
    collect.add_argument("--max-runs", type=int, default=8, help="the newest runs per repository (default 8)")
    collect.add_argument("--logs", choices=("none", "latest", "all"), default="latest",
                         help="which jobs get a log summary: the newest successful job of each pair (default), all, or none")
    collect.add_argument("--workers", type=int, default=6)
    collect.add_argument("--out", required=True)

    def add_jobs(p: argparse.ArgumentParser) -> None:
        p.add_argument("--jobs", action="append", required=True, help="a collect file; repeatable, they are merged")
        p.add_argument("--json", action="store_true")

    def add_thresholds(p: argparse.ArgumentParser) -> None:
        p.add_argument("--version", help="the release version (every Community Packs pack has the same one)")
        p.add_argument("--ratio", type=float, default=DEFAULT_RATIO, help=f"flag a pair that takes this many times as long (default {DEFAULT_RATIO:g})")
        p.add_argument("--min-delta", type=float, default=DEFAULT_MIN_DELTA, help=f"and this many seconds longer (default {DEFAULT_MIN_DELTA:g})")
        p.add_argument("--since", help="ignore jobs before this time, for example the time the configuration last changed")

    packs = sub.add_parser("packs", help="does the newest scan of every repository use the new pack version?")
    add_jobs(packs)
    packs.add_argument("--version", required=True)
    packs.add_argument("--since", help="only scans on or after this time count, for example when the release was published")
    packs.add_argument("--ours", action="append", default=[], help="a rule id, query file name or path whose evaluation to confirm; repeatable")

    compare = sub.add_parser("compare", help="the job time before and after the release, per repository and language")
    add_jobs(compare)
    add_thresholds(compare)
    compare.add_argument("--cutoff", required=True, help="when the release was published (UTC, or a date)")
    compare.add_argument("--keep", type=int, default=KEEP, help=f"jobs per side that the median is taken over (default {KEEP})")

    explain = sub.add_parser("explain", help="read the logs of the flagged pairs and say where the time went")
    add_jobs(explain)
    add_thresholds(explain)
    explain.add_argument("--cutoff", required=True)
    explain.add_argument("--repo")
    explain.add_argument("--language")
    explain.add_argument("--ours", action="append", default=[], help="a rule id, query file name or path that is yours; repeatable")
    explain.add_argument("--top", type=int, default=5, help="queries to list per kind (default 5)")
    explain.add_argument("--limit", type=int, default=10, help="pairs to explain (default 10)")

    args = parser.parse_args(argv)
    try:
        return {"collect": run_collect, "packs": run_packs, "compare": run_compare, "explain": run_explain}[args.command](args)
    except (RuntimeError, ValueError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
