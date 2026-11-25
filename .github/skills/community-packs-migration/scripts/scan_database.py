#!/usr/bin/env python3
"""Download the CodeQL database of a code scanning analysis, and list the calls in it with their targets.

A query or a data extension row that matches a library call by its canonical path sees nothing when the
extraction cannot resolve the call. A code scanning default setup builds with ``buildMode: none``, and some
imports do not resolve there (a glob import of the ``iron`` prelude leaves every call into it without a
target), although the tests of the same code pass. This script shows what a database holds, so that a
missing alert can be told from a query that does not match:

* ``download`` fetches the database that the API returns for the language of a repository (the newest
  analysis) and unpacks it. It needs the gh CLI, signed in with access to the repository.
* ``calls`` lists the calls of the files that match a pattern, with the canonical path of the target or
  ``<unresolved>``. Pass a pattern: the default lists every file, including the libraries that the database
  holds. Rust only: the other languages name call targets differently.

    scan_database.py download --repo owner/name --language rust --out <dir>
    scan_database.py calls --db <dir>/db/rust --codeql <cli> --file "%handlers%" [--unresolved]

Nothing here writes to GitHub.
"""

from __future__ import annotations

import argparse
import csv
import io
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True
import community_packs_migrate as migrate  # noqa: E402  (run_codeql hides the user level CLI config)

UNRESOLVED = "<unresolved>"

CALLS_QL = """/**
 * @name Call targets
 * @kind table
 * @id scratch/call-targets
 */

import rust

from Call call, string target
where
  call.getLocation().getFile().getRelativePath().matches(%s) and
  (
    target = call.getStaticTarget().getCanonicalPath()
    or
    not exists(call.getStaticTarget()) and target = "<unresolved>"
  )
select call.getLocation().getFile().getRelativePath(), call.getLocation().getStartLine(), call.toString(), target
"""

QLPACK = """name: scratch/call-targets
version: 0.0.1
dependencies:
  codeql/rust-all: '*'
"""


def ql_string(text: str) -> str:
    """A QL string literal for `text`."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def calls_query(file_pattern: str) -> str:
    """The query that lists the calls of the files whose path matches `file_pattern` (the QL ``matches`` wildcards)."""
    return CALLS_QL % ql_string(file_pattern)


def parse_calls(csv_text: str) -> list[dict]:
    """The rows of ``bqrs decode --format=csv`` as dictionaries: file, line, call, target."""
    rows = list(csv.reader(io.StringIO(csv_text)))
    return [{"file": r[0], "line": int(r[1]), "call": r[2], "target": r[3]} for r in rows[1:] if len(r) >= 4]


def format_calls(rows: list[dict], unresolved_only: bool = False) -> str:
    """One line per call, in file and line order, and a count of the calls with no target at the end."""
    shown = [r for r in rows if not unresolved_only or r["target"] == UNRESOLVED]
    lines = [f"{r['file']}:{r['line']}  {r['call']}  ->  {r['target']}"
             for r in sorted(shown, key=lambda r: (r["file"], r["line"], r["call"]))]
    missing = sum(1 for r in rows if r["target"] == UNRESOLVED)
    lines.append(f"{len(rows)} call(s), {missing} without a target")
    return "\n".join(lines)


def database_info(db: Path) -> dict:
    """The few fields of ``codeql-database.yml`` that say how and when the database was built."""
    info: dict = {}
    text = (db / "codeql-database.yml").read_text(encoding="utf-8", errors="replace")
    for key in ("primaryLanguage", "buildMode", "sha", "cliVersion", "creationTime"):
        found = re.search(rf"^\s*{key}:\s*(\S+)", text, re.M)
        if found:
            info[key] = found.group(1)
    return info


def long_path(path: Path) -> str:
    """The path with the extended length prefix on Windows, where a database holds paths over 260 characters."""
    resolved = str(path.resolve())
    return "\\\\?\\" + resolved if sys.platform == "win32" and not resolved.startswith("\\\\?\\") else resolved


def extract(archive: Path, target: Path) -> None:
    """Unpack `archive` below `target`, keeping paths that are longer than Windows allows by default."""
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            name = member.filename
            if name.startswith("/") or ".." in Path(name).parts:
                raise SystemExit(f"refusing to unpack {name!r}: it leaves the target directory")
            destination = Path(long_path(target)) / name if sys.platform == "win32" else target / name
            if member.is_dir():
                Path(str(destination)).mkdir(parents=True, exist_ok=True)
                continue
            Path(str(destination)).parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as source, open(str(destination), "wb") as out:
                while chunk := source.read(1 << 20):
                    out.write(chunk)


def download(repo: str, language: str, out: Path) -> Path:
    """Fetch the database of `language` of `repo` and unpack it. Returns the database directory."""
    out.mkdir(parents=True, exist_ok=True)
    archive = out / f"{language}.zip"
    with open(archive, "wb") as handle:
        # gh follows the redirect to the storage and writes the body as it is; a shell redirection would corrupt it
        proc = subprocess.run(["gh", "api", "-H", "Accept: application/zip",
                               f"repos/{repo}/code-scanning/codeql/databases/{language}"],
                              stdout=handle, stderr=subprocess.PIPE)
    if proc.returncode:
        archive.unlink(missing_ok=True)
        raise SystemExit(f"gh api failed: {proc.stderr.decode(errors='replace').strip()[:300]}")
    target = out / "db"
    extract(archive, target)
    archive.unlink()
    return target / language


def run_calls(db: Path, codeql: Path, file_pattern: str) -> list[dict]:
    info = database_info(db)
    if info.get("primaryLanguage", "rust") != "rust":
        raise SystemExit(f"only Rust databases are supported, this one is {info.get('primaryLanguage')}")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "qlpack.yml").write_text(QLPACK, encoding="utf-8")
        (work / "Calls.ql").write_text(calls_query(file_pattern), encoding="utf-8")
        bqrs = work / "calls.bqrs"
        proc = migrate.run_codeql(codeql, work, "query", "run", f"--database={db}", f"--output={bqrs}", "--threads=4",
                                  str(work / "Calls.ql"))
        if proc.returncode:
            raise SystemExit("codeql query run failed:\n" + (proc.stdout + proc.stderr)[-1500:])
        decoded = migrate.run_codeql(codeql, work, "bqrs", "decode", "--format=csv", str(bqrs))
        if decoded.returncode:
            raise SystemExit("codeql bqrs decode failed:\n" + decoded.stderr[-800:])
        return parse_calls(decoded.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    down = sub.add_parser("download", help="fetch and unpack the database of an analysis")
    down.add_argument("--repo", required=True, help="owner/name")
    down.add_argument("--language", required=True, help="the database language, for example rust")
    down.add_argument("--out", type=Path, required=True, help="directory for the unpacked database (<out>/db/<language>)")
    calls = sub.add_parser("calls", help="list the calls with their targets")
    calls.add_argument("--db", type=Path, required=True, help="the database directory (holds codeql-database.yml)")
    calls.add_argument("--codeql", type=Path, required=True, help="the CodeQL CLI")
    calls.add_argument("--file", default="%", help="file path pattern with the QL wildcards %% and _ (default: every file)")
    calls.add_argument("--unresolved", action="store_true", help="only the calls that have no target")
    args = parser.parse_args()
    if args.command == "download":
        db = download(args.repo, args.language, args.out)
        print(db)
        print(" ".join(f"{k}={v}" for k, v in database_info(db).items()))
        return 0
    print(format_calls(run_calls(args.db, args.codeql, args.file), args.unresolved))
    return 0


if __name__ == "__main__":
    sys.exit(main())
