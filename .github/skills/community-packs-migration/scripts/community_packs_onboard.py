#!/usr/bin/env python3
"""Make a language pack's queries and models run in the checked-in Community Packs configs.

A query that is merged into a pack does not run because of that. It runs when all of these hold, and a
migration forgot the first two for Actions and again for Rust:

1. the pack is named in a config under ``configs/``: the queries pack in ``default.yml`` and
   ``synthetics.yml``, and in ``synthetics.yml`` the extensions pack when it has data extensions;
2. a suite selects the query: ``<language>.qls`` for a security query, ``<language>-audit.qls`` for an
   audit query (no other suite selects it), and ``audit.yml`` names the audit suite;
3. a release has published the pack and every path that a config names in it. A config on ``main`` is read
   at scan time and resolves against the latest published pack, so a suite that exists only on ``main``
   breaks every scan that names it until the next release;
4. the repository's default setup lists the language, and the config's ``query-filters`` keep the query
   (``verify-detection.md`` covers that part).

This script reports the first three, for one language or all of them. ``--apply`` makes the edits that are
safe now: it adds the missing pack lines to the configs and creates a missing audit suite. The ``audit.yml``
line waits for the release that carries the suite (``--after-release`` adds it, and ``--published``
finds out whether that release has happened). Nothing here pushes or opens a pull request.

    python community_packs_onboard.py --ccp <checkout> [--language rust] [--apply [--after-release]]
                                      [--published --codeql <cli>]
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

LANGUAGES = ("actions", "cpp", "csharp", "go", "java", "javascript", "python", "ruby", "rust", "swift")
LABELS = {
    "actions": "GitHub Actions", "cpp": "C/C++", "csharp": "C#", "go": "Go", "java": "Java",
    "javascript": "JavaScript / Typescript", "python": "Python", "ruby": "Ruby", "rust": "Rust", "swift": "Swift",
}
# The configs that a language pack must appear in. ``hardcoded-credentials.yml`` and ``quality.yml`` are themed
# and name queries on purpose, so they are a decision and not a gate.
CONFIGS = ("default.yml", "synthetics.yml", "audit.yml")
# What the suites select: ``<language>.qls`` takes problems and path problems, ``<language>-audit.qls`` adds
# metrics and diagnostics. An audit query of another kind (table, treemap) is an exploration query to run by hand.
SECURITY_KINDS = {"problem", "path-problem"}
AUDIT_KINDS = {"problem", "path-problem", "metric", "diagnostic"}
NOT_MODELS = {"qlpack.yml", "codeql-pack.lock.yml"}

PACK_LINE = re.compile(
    r"""^\s*-\s+["']?(?P<name>[A-Za-z0-9][\w.-]*/[\w.-]+)(?::(?P<path>[^"'#]*?))?["']?\s*(?:#.*)?$"""
)
PACKS_KEY = re.compile(r"^packs:\s*(#.*)?$")
# How a line of each kind looks in a config, to find its neighbours when a line is added.
KIND_PATTERNS = {
    "config-queries-pack": r"githubsecuritylab/codeql-(?P<lang>[a-z]+)-queries",
    "config-ext-pack": r"githubsecuritylab/codeql-(?P<lang>[a-z]+)-extensions",
    "audit-config": r"githubsecuritylab/codeql-(?P<lang>[a-z]+)-queries:suites/(?P=lang)-audit\.qls",
}


# ------------------------------------------------------------------ reading the repository


def config_packs(text: str) -> list[tuple[str, str]]:
    """The (pack, path) entries in the ``packs:`` block of a CodeQL config, commented out lines excluded.

    Both forms work: a list of packs, and a mapping of language to a list. ``query-filters`` and the other
    blocks are not read, because their list items are query ids and not packs.
    """
    entries: list[tuple[str, str]] = []
    inside = False
    for line in text.splitlines():
        if PACKS_KEY.match(line):
            inside = True
        elif inside and line.strip() and not line[0].isspace() and not line.startswith("#"):
            inside = False
        elif inside and (match := PACK_LINE.match(line)):
            entries.append((match["name"], (match["path"] or "").strip()))
    return entries


def query_meta(text: str) -> tuple[str | None, list[str]]:
    """The ``@kind`` and the ``@tags`` of a query's leading metadata comment."""
    match = re.match(r"\A\ufeff?\s*/\*\*(.*?)\*/", text, re.S)
    if not match:
        return None, []
    kind: str | None = None
    tags: list[str] = []
    current = None
    for line in match.group(1).split("\n"):
        content = re.sub(r"^\s*\*?[ \t]?", "", line).strip()
        if tag := re.match(r"@([\w.-]+)\s*(.*)$", content):
            current, content = tag.group(1), tag.group(2)
            if current == "kind":
                kind = content.split()[0] if content.split() else None
        if current == "tags":
            tags += content.split()
    return kind, tags


def pack_name(qlpack: Path) -> str | None:
    if not qlpack.is_file():
        return None
    match = re.search(r"^name:\s*(\S+)", qlpack.read_text(encoding="utf-8", errors="replace"), re.M)
    return match.group(1) if match else None


def language_state(ccp: Path, language: str) -> dict:
    """What a language directory holds that the configs and suites have to account for."""
    src, ext = ccp / language / "src", ccp / language / "ext"
    counts = {"security": 0, "audit": 0, "explore": 0, "other": 0}
    for path in sorted(src.rglob("*.ql")) if src.is_dir() else []:
        parts = path.relative_to(src).parts
        if "suites" in parts or any(part.startswith(".") for part in parts):
            continue
        kind, tags = query_meta(path.read_text(encoding="utf-8", errors="replace")[:6000])
        if "audit" in tags:
            counts["audit" if kind in AUDIT_KINDS else "explore"] += 1
        elif "security" in tags and kind in SECURITY_KINDS:
            counts["security"] += 1
        else:
            counts["other"] += 1
    models = [p for p in ext.rglob("*.yml") if p.name not in NOT_MODELS] if ext.is_dir() else []
    suites = sorted(p.name for p in (src / "suites").glob("*.qls")) if (src / "suites").is_dir() else []
    return {
        "language": language, "queries_pack": pack_name(src / "qlpack.yml"), "queries": counts, "suites": suites,
        "ext_pack": pack_name(ext / "qlpack.yml"), "ext_models": len(models),
    }


def read_configs(ccp: Path) -> dict[str, str]:
    """The text of each config, with its own line endings (a Windows checkout may use CRLF); "" when missing."""
    out = {}
    for name in CONFIGS:
        path = ccp / "configs" / name
        out[name] = path.read_bytes().decode("utf-8") if path.is_file() else ""
    return out


# ------------------------------------------------------------------------ the gaps


def onboard_gaps(state: dict, configs: dict[str, str],
                 published: Callable[[str, str], bool | None] | None = None) -> list[dict]:
    """What is missing so that the language's queries and models run.

    Each gap says ``when`` it can be fixed: "now", or "after-release" for a line that names something only a
    release publishes. ``published(pack, path)`` answers whether the latest release has it (None: unknown).
    """
    language, pack, ext = state["language"], state["queries_pack"], state["ext_pack"]
    queries, suites = state["queries"], state["suites"]
    entries = {name: config_packs(text) for name, text in configs.items()}
    audit_suite = f"{language}-audit.qls"
    gaps: list[dict] = []

    def known(name: str, path: str) -> bool | None:
        return published(name, path) if published else None

    def gap(kind: str, where: str, entry: str | None, message: str, when: str = "now") -> None:
        gaps.append({"language": language, "kind": kind, "file": where, "entry": entry, "message": message, "when": when})

    if pack and queries["security"]:
        for name in ("default.yml", "synthetics.yml"):
            if (pack, "") not in entries[name]:
                gap("config-queries-pack", f"configs/{name}", pack,
                    f"configs/{name} does not name {pack}, so no scan that uses it runs the {language} queries",
                    "after-release" if known(pack, "") is False else "now")
        if f"{language}.qls" not in suites:
            gap("security-suite", f"{language}/src/suites/{language}.qls", None,
                f"{language}/src/suites/{language}.qls is missing: the pack's default suite selects nothing")
    if ext and state["ext_models"] and (ext, "") not in entries["synthetics.yml"]:
        gap("config-ext-pack", "configs/synthetics.yml", ext,
            f"configs/synthetics.yml does not name {ext}, so its {state['ext_models']} data extension file(s) are not loaded",
            "after-release" if known(ext, "") is False else "now")
    if pack and queries["audit"]:
        if audit_suite not in suites:
            gap("audit-suite", f"{language}/src/suites/{audit_suite}", None,
                f"{queries['audit']} audit query(ies) and no {language}/src/suites/{audit_suite}: no suite selects them")
        line = f"{pack}:suites/{audit_suite}"
        if (pack, f"suites/{audit_suite}") not in entries["audit.yml"]:
            gap("audit-config", "configs/audit.yml", line,
                f"configs/audit.yml does not name {line}",
                "now" if known(pack, f"suites/{audit_suite}") is True else "after-release")
    return gaps


# ------------------------------------------------------------------------ the edits


def insert_pack_line(text: str, kind: str, language: str, entry: str) -> str:
    """Add ``- <entry>`` to the ``packs:`` block, beside the entries of the same kind and in language order.

    A commented out line for the same entry (``# - <entry>``, how audit.yml leaves Ruby) is switched on
    instead. A block whose entries have a ``# <Language>`` comment gets one for the new entry, and the entries
    that follow the previous language's line without a comment of their own stay with it.
    """
    eol = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(eol)
    start = next((i for i, line in enumerate(lines) if PACKS_KEY.match(line)), None)
    if start is None:
        raise ValueError("the config has no packs: block")
    end = next((i for i in range(start + 1, len(lines)) if lines[i] and not lines[i][0].isspace() and not lines[i].startswith("#")),
               len(lines))
    pattern = KIND_PATTERNS[kind]
    live = re.compile(rf"^(?P<indent>\s*)-\s+{pattern}\s*$")
    off = re.compile(rf"^(?P<indent>\s*)#\s*-\s+{pattern}\s*$")
    peers: list[tuple[int, str, str]] = []
    for i in range(start + 1, end):
        if match := live.match(lines[i]):
            peers.append((i, match["lang"], match["indent"]))
        elif (match := off.match(lines[i])) and match["lang"] == language:
            lines[i] = f"{match['indent']}- {entry}"
            return eol.join(lines)

    def commented(i: int) -> bool:
        return i > start + 1 and lines[i - 1].lstrip().startswith("#")

    before = [p for p in peers if p[1] < language]
    labelled = False
    if before:
        i, _, indent = before[-1]
        at, labelled = i + 1, commented(i)
        while labelled and at < end and lines[at].strip() and not lines[at].lstrip().startswith("#"):
            at += 1
    elif peers:
        i, _, indent = peers[0]
        labelled = commented(i)
        at = i - 1 if labelled else i
    else:
        found = [j for j in range(start + 1, end) if re.match(r"^\s*-\s", lines[j])]
        at = found[-1] + 1 if found else start + 1
        indent = re.match(r"^(\s*)", lines[found[-1]]).group(1) if found else "  "
    new = ([f"{indent}# {LABELS[language]}"] if labelled else []) + [f"{indent}- {entry}"]
    lines[at:at] = new
    return eol.join(lines)


def audit_suite_text(language: str) -> str:
    """A new ``<language>-audit.qls``, in the shape of the existing ones: the pack's audit tagged queries."""
    return "\n".join([
        f"- description: \"GitHub Security Lab's {LABELS[language]} Audit Suite\"",
        "",
        "- queries: '.'",
        f"  from: githubsecuritylab/codeql-{language}-queries",
        "",
        "- include:",
        "    kind:",
        "      - problem",
        "      - path-problem",
        "      - metric",
        "      - diagnostic",
        "    tags contain:",
        "      - audit",
        "",
    ])


def apply_gaps(ccp: Path, gaps: list[dict], after_release: bool = False) -> list[str]:
    """Make the edits that are safe now (and, with ``after_release``, the ones that wait for a release)."""
    done: list[str] = []
    for gap in gaps:
        if gap["when"] != "now" and not after_release:
            continue
        path = ccp / gap["file"]
        if gap["kind"] == "audit-suite" and not path.exists():
            path.write_bytes(audit_suite_text(gap["language"]).encode("utf-8"))
            done.append(f"created {gap['file']}")
        elif gap["kind"] in KIND_PATTERNS:
            text = path.read_bytes().decode("utf-8") if path.is_file() else ""
            new = insert_pack_line(text, gap["kind"], gap["language"], gap["entry"])
            if new != text:
                path.write_bytes(new.encode("utf-8"))
                done.append(f"{gap['file']}: added {gap['entry']}")
    return done


# ------------------------------------------------------------------ the released packs


def remove_tree(path: Path) -> None:
    """Delete a directory tree, including paths over 260 characters.

    ``codeql pack download`` puts the pack's own dependencies in ``.codeql/libraries`` below it, and those nest
    deep enough for a plain ``rmtree`` to fail on Windows (the extended length prefix avoids it).
    """
    shutil.rmtree("\\\\?\\" + str(path.resolve()) if sys.platform == "win32" else path, ignore_errors=True)


class PublishedPacks:
    """The latest published version of Community Packs packs: ``self(name)`` is its directory, or None when it is not published.

    A pack is downloaded with ``codeql pack download`` (which also fetches its dependencies, so it is slow), once, and
    ``prefetch`` does several at a time.
    """

    def __init__(self, codeql: Path, tmp: Path, workers: int = 4) -> None:
        self.codeql, self.tmp, self.workers = codeql, tmp, workers
        self.cache: dict[str, Path | None] = {}
        self.errors: dict[str, str] = {}

    def fetch(self, name: str) -> Path | None:
        proc = subprocess.run([str(self.codeql), "pack", "download", name, "--dir", str(self.tmp)], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=900)
        found = sorted(Path(self.tmp, *name.split("/")).glob("*")) if proc.returncode == 0 else []
        if not found:
            self.errors[name] = " ".join((proc.stderr or proc.stdout).split())[-160:]
        return found[-1] if found else None

    def __call__(self, name: str) -> Path | None:
        if name not in self.cache:
            self.cache[name] = self.fetch(name)
        return self.cache[name]

    def prefetch(self, names: set[str]) -> None:
        todo = sorted(set(names) - set(self.cache))
        with ThreadPoolExecutor(self.workers) as pool:
            for name, where in zip(todo, pool.map(self.fetch, todo)):
                self.cache[name] = where


@contextlib.contextmanager
def published_packs(codeql: Path, workers: int = 4):
    tmp = Path(tempfile.mkdtemp(prefix="ccp-published-"))
    try:
        yield PublishedPacks(codeql, tmp, workers)
    finally:
        remove_tree(tmp)


def has_published(root: Callable[[str], Path | None], pack: str, path: str) -> bool:
    where = root(pack)
    return bool(where) and (path in ("", ".") or (where / path).exists())


def published_problems(root: Callable[[str], Path | None], configs: dict[str, str]) -> list[str]:
    """Config entries that name a Community Packs pack, or a path in it, that the latest release lacks."""
    problems: list[str] = []
    for name, text in configs.items():
        for pack, path in config_packs(text):
            if not pack.startswith("githubsecuritylab/"):
                continue
            where = root(pack)
            if where is None:
                detail = getattr(root, "errors", {}).get(pack)
                problems.append(f"configs/{name} names {pack}, which is not published" + (f" ({detail})" if detail else ""))
            elif path not in ("", ".") and not (where / path).exists():
                problems.append(f"configs/{name} names {pack}:{path}, which the latest published version ({where.name}) does not contain")
    return problems


# --------------------------------------------------------------------------- the report


def onboard(ccp: Path, languages: list[str], apply: bool = False, after_release: bool = False,
            codeql: Path | None = None, published: bool = False) -> dict:
    languages = languages or [lang for lang in LANGUAGES if (ccp / lang / "src" / "qlpack.yml").is_file()]
    with contextlib.ExitStack() as stack:
        root = stack.enter_context(published_packs(codeql)) if published else None
        lookup = (lambda pack, path: has_published(root, pack, path)) if root else None

        def collect() -> tuple[dict, dict, dict]:
            configs = read_configs(ccp)
            states = {lang: language_state(ccp, lang) for lang in languages}
            return configs, {lang: onboard_gaps(state, configs, lookup) for lang, state in states.items()}, states

        if root:
            named = {pack for text in read_configs(ccp).values() for pack, _ in config_packs(text)}
            root.prefetch({pack for pack in named if pack.startswith("githubsecuritylab/")})
        configs, gaps, states = collect()
        applied: list[str] = []
        if apply:
            for found in gaps.values():
                applied += apply_gaps(ccp, found, after_release)
            if applied:
                configs, gaps, states = collect()
        broken = published_problems(root, configs) if root else []
    open_now = [g for found in gaps.values() for g in found if g["when"] == "now"]
    return {
        "ok": not open_now and not broken,
        "languages": {lang: {"state": states[lang], "gaps": gaps[lang]} for lang in languages},
        "applied": applied,
        "broken": broken,
        "after_release": [g["message"] for found in gaps.values() for g in found if g["when"] != "now"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ccp", type=Path, required=True, help="Community Packs checkout")
    parser.add_argument("--language", action="append", default=[], help="repeatable; default: every language with a pack")
    parser.add_argument("--apply", action="store_true", help="add the missing pack lines and create a missing audit suite")
    parser.add_argument("--after-release", action="store_true",
                        help="with --apply, also add the lines that name something only a release publishes")
    parser.add_argument("--published", action="store_true",
                        help="check the configs against the latest published packs (needs --codeql and the network)")
    parser.add_argument("--codeql", type=Path, help="CodeQL CLI, for --published")
    args = parser.parse_args()
    if args.published and not args.codeql:
        parser.error("--published needs --codeql")
    report = onboard(args.ccp, args.language, args.apply, args.after_release, args.codeql, args.published)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
