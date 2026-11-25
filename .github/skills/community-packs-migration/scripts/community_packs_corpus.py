#!/usr/bin/env python3
"""Build and use databases of public repositories to measure a Community Packs query.

A query that passes its unit tests can still be unusable on real code, so every
migrated query is measured on a corpus (see references/migration-guide.md in the skill directory).
This script makes the corpus step deterministic instead of improvised:

* ``sample``    a seeded random sample of public repositories in one language.
* ``targeted``  explicit repositories (``owner/name`` or ``owner/name@ref``), or
                the repositories that a GitHub code search hit.
* ``links``     turns the rows that ``community_packs_migrate.py measure`` wrote
                into commit pinned permalinks plus repository metadata.

Both build modes clone shallowly over HTTPS, write ``manifest.json`` (repository,
commit, size), create the database, and finish by writing ``READY`` (or
``FAILED``) so that other sessions can wait for it. Corpora and results are local
files. Never commit them, and never paste them into a public place.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

# The CLI on PATH, unless the CODEQL environment variable or --codeql names another one. Pin it to the
# version in .codeqlversion of the Community Packs checkout.
DEFAULT_CODEQL = shutil.which("codeql") or "codeql"

# language -> GitHub search name, CodeQL language id, extra database create flags.
# CLI 2.27.4 has build mode ``none`` only for C#, Java, JavaScript/TypeScript, Python and Ruby.
# Go is built with a manual command (see ``create_database``). C/C++ and Swift need a toolchain
# that this script does not drive, so they are not listed.
LANGUAGES = {
    "python": ("Python", "python", []),
    "javascript": ("JavaScript", "javascript-typescript", []),
    "ruby": ("Ruby", "ruby", []),
    "java": ("Java", "java-kotlin", ["--build-mode=none"]),
    "csharp": ("C#", "csharp", ["--build-mode=none"]),
    "go": ("Go", "go", []),
    "rust": ("Rust", "rust", []),
}
DEFAULT_COUNT = {"go": 8}


def run(cmd: list[str], *, cwd: Path | None = None, timeout: int | None = None, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, env={**os.environ, **(env or {})})


def gh(*args: str) -> str:
    proc = run(["gh", *args], timeout=120)
    if proc.returncode:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout


def git_env(out: Path) -> dict:
    """Clone over HTTPS whatever the user's git config rewrites github.com URLs to."""
    config = out / ".gitconfig-https"
    config.write_text("[core]\n\tlongpaths = true\n\tautocrlf = false\n", encoding="utf-8")
    return {"GIT_CONFIG_GLOBAL": str(config), "GIT_TERMINAL_PROMPT": "0"}


def _rm_readonly(func, path, _exc) -> None:
    os.chmod(path, stat.S_IWRITE)
    func(path)


def clone(repo: str, ref: str | None, dest: Path, env: dict) -> str | None:
    """Shallow clone ``repo`` at ``ref`` into ``dest``. Returns the commit, or None when it failed."""
    if (dest / ".ccp-commit").exists():
        return (dest / ".ccp-commit").read_text().strip()
    if dest.exists():
        shutil.rmtree(dest, onerror=_rm_readonly)
    dest.mkdir(parents=True)
    url = f"https://github.com/{repo}.git"
    steps = [["git", "init", "-q"], ["git", "remote", "add", "origin", url],
             ["git", "fetch", "-q", "--depth", "1", "origin", ref or "HEAD"], ["git", "checkout", "-q", "FETCH_HEAD"]]
    for step in steps:
        try:
            proc = run(step, cwd=dest, timeout=300, env=env)
        except subprocess.TimeoutExpired:
            proc = subprocess.CompletedProcess(step, 1, "", "timeout")
        if proc.returncode:
            shutil.rmtree(dest, onerror=_rm_readonly)
            return None
    sha = run(["git", "rev-parse", "HEAD"], cwd=dest).stdout.strip()
    shutil.rmtree(dest / ".git", onerror=_rm_readonly)
    (dest / ".ccp-commit").write_text(sha)
    return sha


def search_sample(language: str, count: int, seed: int, min_kb: int, max_kb: int, min_stars: int, max_stars: int) -> list[dict]:
    q = (f"language:{LANGUAGES[language][0]} stars:{min_stars}..{max_stars} size:{min_kb}..{max_kb} "
         "fork:false archived:false pushed:>2024-01-01")
    found: list[dict] = []
    for page in (1, 2, 3):
        items = json.loads(gh("api", "-X", "GET", "search/repositories", "-f", f"q={q}", "-f", "sort=updated",
                              "-f", "per_page=100", "-f", f"page={page}")).get("items", [])
        found += items
        if len(items) < 100:
            break
    random.Random(seed).shuffle(found)
    return found[:count]


def search_code(language: str, query: str, limit: int) -> list[dict]:
    # gh treats one argument as an exact phrase, so split the terms like a shell would
    hits = json.loads(gh("search", "code", *shlex.split(query), "--language", language, "--limit", "100",
                         "--json", "repository,path,sha,url"))
    by_repo: dict[str, dict] = {}
    for hit in hits:
        repo = hit["repository"]
        if repo.get("isFork") or repo.get("isPrivate"):
            continue
        entry = by_repo.setdefault(repo["nameWithOwner"], {"full_name": repo["nameWithOwner"], "hits": 0})
        entry["hits"] += 1
    return sorted(by_repo.values(), key=lambda e: -e["hits"])[:limit]


def go_build_command(src: Path, out: Path, env: dict) -> list[str]:
    """A manual build command that builds every Go module of the corpus, for ``database create``.

    The modules are downloaded first, outside the traced command, so that the traced build is only
    compilation. A module that does not build is skipped.
    """
    modules = sorted(p.parent for p in src.rglob("go.mod") if len(p.relative_to(src).parts) <= 3)
    lines = ["@echo off"]
    for module in modules:
        run(["go", "mod", "download"], cwd=module, timeout=600, env=env)
        lines.append(f'pushd "{module}" && (go build ./... || ver >nul) & popd')
    script = out / "build-all.cmd"
    script.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
    return ["--command", str(script)]


def create_database(codeql: str, language: str, src: Path, db: Path, threads: int, ram: int,
                    out: Path | None = None) -> subprocess.CompletedProcess:
    _gh, ql_language, extra = LANGUAGES[language]
    env: dict = {}
    if language == "go" and out is not None:
        extra = go_build_command(src, out, {"GOFLAGS": "-mod=mod"})
        env = {"GOFLAGS": "-mod=mod"}  # the traced build resolves modules itself, vendor directories or not
    return run([codeql, "database", "create", str(db), f"--language={ql_language}", f"--source-root={src}",
                "--overwrite", f"--threads={threads}", f"--ram={ram}", *extra], env=env)


def build(args: argparse.Namespace, picked: list[tuple[str, str | None, dict]]) -> int:
    out: Path = args.out
    src = out / "src"
    src.mkdir(parents=True, exist_ok=True)
    for marker in ("READY", "FAILED"):
        (out / marker).unlink(missing_ok=True)
    env = git_env(out)
    started = time.monotonic()
    repos, skipped = [], []
    for repo, ref, meta in picked:
        directory = repo.replace("/", "__")
        sha = clone(repo, ref, src / directory, env)
        if sha is None:
            skipped.append({"repo": repo, "ref": ref, "reason": "clone failed"})
            continue
        files = sum(1 for _ in (src / directory).rglob("*") if _.is_file())
        repos.append({"repo": repo, "ref": ref, "commit": sha, "dir": directory, "files": files,
                      "stars": meta.get("stargazers_count"), "kb": meta.get("size")})
        print(f"cloned {repo} {sha[:10]} ({files} files)", flush=True)
    manifest = {"language": args.language, "created": time.strftime("%Y-%m-%dT%H:%M:%S"), "repos": repos,
                "skipped": skipped, "src": str(src), "db": str(out / "db")}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if not repos:
        (out / "FAILED").write_text("no repository could be cloned")
        return 1
    cloned = time.monotonic()
    proc = create_database(args.codeql, args.language, src, out / "db", args.threads, args.ram, out)
    if proc.returncode:
        (out / "FAILED").write_text(proc.stderr[-1500:])
        print(proc.stderr[-1500:], file=sys.stderr)
        return 1
    (out / "READY").write_text(json.dumps({
        "repos": len(repos), "files": sum(r["files"] for r in repos), "clone_s": round(cloned - started),
        "database_s": round(time.monotonic() - cloned)}, indent=2))
    print(f"READY {out / 'db'}", flush=True)
    return 0


def cmd_sample(args: argparse.Namespace) -> int:
    count = args.count or DEFAULT_COUNT.get(args.language, 30)
    chosen = search_sample(args.language, count, args.seed, args.min_kb, args.max_kb, args.min_stars, args.max_stars)
    return build(args, [(item["full_name"], None, item) for item in chosen])


def cmd_targeted(args: argparse.Namespace) -> int:
    picked: list[tuple[str, str | None, dict]] = []
    for spec in args.repo:
        repo, _, ref = spec.partition("@")
        picked.append((repo, ref or None, {}))
    if args.code_search:
        for entry in search_code(args.language, args.code_search, args.max_repos):
            picked.append((entry["full_name"], None, {}))
    return build(args, picked)


def cmd_links(args: argparse.Namespace) -> int:
    manifest = json.loads((args.corpus / "manifest.json").read_text(encoding="utf-8"))
    commits = {r["dir"]: r for r in manifest["repos"]}
    rows = json.loads(args.rows.read_text(encoding="utf-8"))
    metadata: dict[str, dict] = {}
    links = []
    for row in rows:
        path = (row.get("file") or "").replace("\\", "/")
        match = re.search(r"/src/([^/]+)/(.+)$", path)
        if not match or match.group(1) not in commits:
            links.append({"file": path, "line": row.get("line"), "permalink": None})
            continue
        entry = commits[match.group(1)]
        repo = entry["repo"]
        if repo not in metadata:
            try:
                info = json.loads(gh("api", f"repos/{repo}"))
                metadata[repo] = {"archived": info.get("archived"), "stars": info.get("stargazers_count"),
                                  "pushed_at": info.get("pushed_at"), "description": info.get("description")}
            except RuntimeError:
                metadata[repo] = {}
        line = f"#L{row['line']}" if row.get("line") else ""
        links.append({"repo": repo, "path": match.group(2), "line": row.get("line"), "commit": entry["commit"],
                      "permalink": f"https://github.com/{repo}/blob/{entry['commit']}/{match.group(2)}{line}",
                      "message": row.get("message"), **metadata[repo]})
    text = json.dumps(links, indent=2)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    print(text)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--language", required=True, choices=sorted(LANGUAGES))
        p.add_argument("--out", type=Path, required=True, help="corpus directory, for example <corpus-root>/python")
        p.add_argument("--codeql", default=os.environ.get("CODEQL", DEFAULT_CODEQL))
        p.add_argument("--threads", type=int, default=4)
        p.add_argument("--ram", type=int, default=6000, help="MB for the database build")

    sample = sub.add_parser("sample", help="seeded random sample of public repositories")
    common(sample)
    sample.add_argument("--count", type=int, default=None, help="repositories to sample (30, or 8 for Go)")
    sample.add_argument("--seed", type=int, default=2026)
    sample.add_argument("--min-kb", type=int, default=300, help="skip repositories smaller than this")
    sample.add_argument("--max-kb", type=int, default=10000, help="skip repositories larger than this")
    sample.add_argument("--min-stars", type=int, default=50)
    sample.add_argument("--max-stars", type=int, default=5000)
    sample.set_defaults(func=cmd_sample)

    targeted = sub.add_parser("targeted", help="explicit repositories, or those a code search found")
    common(targeted)
    targeted.add_argument("--repo", action="append", default=[], metavar="OWNER/NAME[@REF]")
    targeted.add_argument("--code-search", help="GitHub code search query; its repositories are added")
    targeted.add_argument("--max-repos", type=int, default=8)
    targeted.set_defaults(func=cmd_targeted)

    links = sub.add_parser("links", help="permalinks and repository metadata for measure rows")
    links.add_argument("--corpus", type=Path, required=True)
    links.add_argument("--rows", type=Path, required=True, help="rows.json written by community_packs_migrate.py measure")
    links.add_argument("--out", type=Path)
    links.set_defaults(func=cmd_links)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
