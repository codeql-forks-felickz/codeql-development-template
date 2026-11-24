#!/usr/bin/env python3
"""Move the work in a template-repo pull request into the Community Packs layout.

Each step is deterministic so that nobody has to improvise the mechanical parts of
a migration:

* ``plan``     reads the pull request and writes a spec that says where every file
               goes and what the query metadata becomes. Edit the spec where
               judgment is needed: query name, placement, CWE, precision.
* ``apply``    executes the spec in a Community Packs checkout. It copies the
               files, rewrites ``@id``, ``@precision`` and ``@tags``, points
               ``.qlref`` files at the new query path, converts Markdown help to
               ``.qhelp`` where the pack uses it and formats the QL. It leaves pack
               versions alone: a release sets them.
* ``check``    runs the Community Packs rules (metadata, forbidden constructs,
               neutral names) and the same format, compile and test commands CI
               runs, in a clean CodeQL home so that a user level CLI config does
               not change the results. It fails a query that the suite for its
               group does not select and a language pack that no config names
               (``community_packs_onboard.py`` reports and fixes both).
* ``measure``  runs the query on a real database, profiles it and keeps the rows
               for triage. It fails on a timeout or on the query's own predicates
               being slow.
* ``scan``     the last gate before anything is published: the commit message,
               branch name, every changed file and the pull request text.
* ``baseline`` whether CI's strict compile of a whole language passes on main.

The conventions are written down in ``references/migration-guide.md`` (the skill
directory that holds this ``scripts`` directory). Nothing here pushes or opens a pull
request: that is a public write and needs a human.

Names that must never reach Community Packs text and are not public (internal repositories,
customers) are not kept in this file. Set ``CCP_EXTRA_DENY`` (comma separated) in the
environment, and ``prepare``, ``check`` and ``scan`` all deny them.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath, PureWindowsPath

import community_packs_onboard as onboard

PACK_LANGUAGES = (
    "actions", "cpp", "csharp", "go", "java", "javascript", "python", "ruby", "rust", "swift",
)
# The language segment of a query id follows the stock CodeQL query id prefixes.
ID_LANGUAGE = {
    "actions": "actions", "cpp": "cpp", "csharp": "cs", "go": "go", "java": "java",
    "javascript": "js", "python": "py", "ruby": "rb", "rust": "rust", "swift": "swift",
}
# Only these languages have a <language>/ext pack for data extensions (CONTRIBUTING.md in
# Community Packs lists them). Add a language here when its ext pack is merged.
EXT_LANGUAGES = {"cpp", "csharp", "go", "java", "javascript", "python", "ruby", "rust"}
# Packs whose queries conventionally have a .qhelp file (the others accept Markdown help).
QHELP_LANGUAGES = {"csharp", "java"}
# Template languages that have no Community Packs pack of their own.
LANGUAGE_ALIASES = {"html": "javascript"}
PRECISIONS = ("very-high", "high", "medium", "low", "very-low")
GROUPS = ("security", "audit")

ID_PATTERN = re.compile(
    r"^githubsecuritylab/(audit/)?(actions|cpp|cs|go|java|js|py|rb|rust|swift)/[a-z0-9]+(-[a-z0-9]+)*$"
)
REQUIRED_TAGS = ("name", "description", "kind", "problem.severity", "precision", "id", "tags")
HEADER_RE = re.compile(r"\A\ufeff?\s*/\*\*(?P<body>.*?)\*/", re.S)
CWE_TAG_RE = re.compile(r"^external/cwe/cwe-(\d+)$")
VERSION_RE = re.compile(r"^version:\s*(\d+)\.(\d+)\.(\d+)\s*$", re.M)

# A CodeQL CLI config file with no options, and a directory for the locks that cap heavy evaluations.
EMPTY_CONFIG = Path(os.environ.get("CCP_EMPTY_CONFIG", Path(tempfile.gettempdir()) / "ccp-home" / "empty.codeql.config"))
LOCK_DIR = Path(os.environ.get("CCP_LOCK_DIR", Path(tempfile.gettempdir()) / "ccp-locks"))
DEFAULT_THREADS = 4
DEFAULT_SLOTS = 3


# ------------------------------------------------------------- environment and locks


def empty_config() -> Path:
    """A CodeQL CLI config file with no options, for gates that must match CI.

    A user level config (``~/.config/codeql/config``) such as ``--threat-model all`` changes the
    results of ``test run`` and ``query run``, and CI does not have it. ``CODEQL_CONFIG_FILE``
    replaces that file and leaves the user profile alone, so per-user tools (the Python launcher,
    Maven, NuGet and the pack cache) keep working. Overriding ``USERPROFILE`` instead hides the
    config too but breaks the Python extractor, and ``HOME``, ``XDG_CONFIG_HOME`` and JVM
    properties do nothing.
    """
    if not EMPTY_CONFIG.exists():
        EMPTY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        EMPTY_CONFIG.write_text("# intentionally empty: replaces the per-user CodeQL CLI config during gates\n")
    return EMPTY_CONFIG


def codeql_env(isolated: bool = True) -> dict:
    env = dict(os.environ)
    if isolated:
        env["CODEQL_CONFIG_FILE"] = str(empty_config())
    return env


def pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return ctypes.GetLastError() == 5  # access denied: it exists
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


@contextlib.contextmanager
def heavy_slot(slots: int, label: str, poll: float = 20.0):
    """At most ``slots`` heavy evaluations at once, across every worker on this machine.

    A slot is a lock file holding the owner's process id. A lock whose owner is gone is reclaimed.
    """
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    taken: Path | None = None
    waited = time.monotonic()
    while taken is None:
        for i in range(slots):
            path = LOCK_DIR / f"slot-{i}.lock"
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                try:
                    if not pid_alive(int(path.read_text().split()[0])):
                        path.unlink()
                except (OSError, ValueError, IndexError):
                    pass
                continue
            os.write(fd, f"{os.getpid()} {label} {int(time.time())}".encode())
            os.close(fd)
            taken = path
            break
        else:
            time.sleep(poll)
    try:
        yield round(time.monotonic() - waited, 1)
    finally:
        taken.unlink(missing_ok=True)


def run_codeql(codeql: Path, cwd: Path, *args: str, isolated: bool = True,
               timeout: float | None = None) -> subprocess.CompletedProcess:
    """Run the CodeQL CLI. ``timeout`` is a wall clock limit for the whole command, enforced by
    killing the command's process tree (only the process this call started)."""
    proc = subprocess.Popen([str(codeql), *args], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace", env=codeql_env(isolated))
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
        else:
            proc.kill()
        out, err = proc.communicate()
        return subprocess.CompletedProcess(proc.args, 124, out, (err or "") + f"\nkilled after {timeout}s")
    return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8192]


# --------------------------------------------------------------------------- git


def git_bytes(repo: Path, *args: str, check: bool = True) -> bytes:
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if check and proc.returncode:
        raise SystemExit(f"git {' '.join(args)} failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def changed_files(template: Path, pr: int, base: str) -> list[tuple[str, str]]:
    """(status, path) for every file the pull request changes, deletions included."""
    raw = git_bytes(template, "diff", "--name-status", "--no-renames", "-z", f"{base}...refs/prs/{pr}")
    tokens = raw.decode("utf-8", "replace").split("\0")
    return [(tokens[i], tokens[i + 1]) for i in range(0, len(tokens) - 1, 2) if tokens[i]]


def blob(template: Path, pr: int, path: str) -> bytes:
    return git_bytes(template, "show", f"refs/prs/{pr}:{path}")


# ----------------------------------------------------------------- query header


class Header:
    """The leading ``/** ... */`` metadata comment of a query, edited in place.

    Tags that are not changed keep their original lines, so a rewrite only shows
    up in the diff where the metadata really changed.
    """

    def __init__(self, text: str) -> None:
        match = HEADER_RE.match(text)
        if not match:
            raise ValueError("the query has no leading /** ... */ metadata comment")
        self.span = match.span()
        self.preamble: list[str] = []
        self.blocks: list[dict] = []
        for line in match.group("body").split("\n")[1:]:
            content = re.sub(r"^\s*\*?[ \t]?", "", line).rstrip()
            tag = re.match(r"@([A-Za-z][\w.-]*)(?:\s+(.*))?$", content)
            if tag:
                self.blocks.append({"tag": tag.group(1), "values": [tag.group(2) or ""], "raw": [line]})
            elif self.blocks:
                if content or line.strip().strip("*").strip():
                    self.blocks[-1]["values"].append(content)
                    self.blocks[-1]["raw"].append(line)
            elif content:
                self.preamble.append(line)
        # the closing line is not a content line
        if self.blocks and not self.blocks[-1]["values"][-1]:
            self.blocks[-1]["values"].pop()
            self.blocks[-1]["raw"].pop()

    def get(self, tag: str) -> list[str] | None:
        for block in self.blocks:
            if block["tag"] == tag:
                return [v for v in block["values"] if v]
        return None

    def value(self, tag: str) -> str | None:
        values = self.get(tag)
        return " ".join(values) if values else None

    def tags(self) -> list[str]:
        return " ".join(self.get("tags") or []).split()

    def set(self, tag: str, values: list[str]) -> None:
        block = {"tag": tag, "values": values, "raw": None}
        for i, existing in enumerate(self.blocks):
            if existing["tag"] == tag:
                if [v for v in existing["values"] if v] != values:
                    self.blocks[i] = block
                return
        anchors = {
            "problem.severity": ("security-severity", "sub-severity", "precision", "id", "tags"),
            "security-severity": ("sub-severity", "precision", "id", "tags"),
            "sub-severity": ("precision", "id", "tags"),
            "precision": ("id", "tags"),
            "id": ("tags",),
            "tags": (),
        }.get(tag, ())
        for anchor in anchors:
            for i, existing in enumerate(self.blocks):
                if existing["tag"] == anchor:
                    self.blocks.insert(i, block)
                    return
        self.blocks.append(block)

    @staticmethod
    def render_block(block: dict) -> list[str]:
        if block["raw"] is not None:
            return list(block["raw"])
        first, *rest = block["values"]
        pad = " " * (len(block["tag"]) + 2)
        return [f" * @{block['tag']} {first}".rstrip()] + [f" * {pad}{v}".rstrip() for v in rest]

    def render(self) -> str:
        lines = ["/**", *self.preamble]
        for block in self.blocks:
            lines += self.render_block(block)
        lines.append(" */")
        return "\n".join(lines)

    def rewrite(self, text: str) -> str:
        return self.render() + text[self.span[1]:]


def kebab(value: str) -> str:
    value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", value)
    return re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-").lower()


def pascal(value: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in kebab(value).split("-"))


def cwe_dir(tags: list[str]) -> str | None:
    for tag in tags:
        match = CWE_TAG_RE.match(tag)
        if match:
            return f"CWE-{int(match.group(1)):03d}"
    return None


def query_id(language: str, name: str, audit: bool) -> str:
    return f"githubsecuritylab/{'audit/' if audit else ''}{ID_LANGUAGE[language]}/{name}"


def new_tags(existing: list[str], *, cwe: str | None, experimental: bool, audit: bool) -> list[str]:
    cwe_tags = [t for t in existing if CWE_TAG_RE.match(t)]
    if cwe and not cwe_tags:
        cwe_tags = [f"external/cwe/cwe-{int(cwe.split('-')[1]):03d}"]
    other = [t for t in existing if t not in ("security", "experimental", "audit") and not CWE_TAG_RE.match(t)]
    return other + ["security"] + (["experimental"] if experimental else []) + (["audit"] if audit else []) + cwe_tags


# ------------------------------------------------------------------------- plan


def classify(path: str) -> dict:
    """Where a template-repo path belongs. ``kind`` is query, support, test, model, skip or other."""
    parts = PurePosixPath(path).parts
    if len(parts) < 5 or parts[0] != "languages" or parts[2] != "custom":
        return {"kind": "other", "reason": "not under languages/<language>/custom"}
    language, area, rest = parts[1], parts[3], parts[4:]
    info = {"language": language}
    if area == "src":
        if rest[0] == "change-notes":
            return {**info, "kind": "skip", "reason": "Community Packs has no change notes"}
        if len(rest) == 1:
            return {**info, "kind": "skip", "reason": "pack scaffolding"}
        kind = "query" if len(rest) == 2 and rest[1].endswith(".ql") else "support"
        return {**info, "kind": kind, "dir": rest[0], "rel": "/".join(rest[1:])}
    if area == "test" and len(rest) >= 2:
        return {**info, "kind": "test", "dir": rest[0], "rel": "/".join(rest[1:])}
    if area == "models":
        if rest[0] == "change-notes" or rest[-1] in ("qlpack.yml", "README.md", "codeql-pack.lock.yml"):
            return {**info, "kind": "skip", "reason": "model pack scaffolding or change notes"}
        if rest[-1].endswith((".model.yml", ".yml")):
            return {**info, "kind": "model", "file": rest[-1]}
    return {**info, "kind": "other", "reason": "not part of the fix"}


def load_triage(path: Path | None, pr: int) -> dict | None:
    if not path:
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return next((v for v in data.values() if v.get("pr") == pr), None)


def split_units(template: Path, pr: int, base: str) -> list[tuple[str, list[str]]]:
    """Independent units of a pull request as (name, ``--only`` tokens).

    A unit is one query with its help and tests, or the model files with the tests no
    query owns. One query plus models that share its tests stays a single unit, as does
    a pull request that has nothing to split, and then the tokens are empty.
    """
    entries = [(p, classify(p)) for status, p in changed_files(template, pr, base) if status != "D"]
    languages = {c["language"] for _, c in entries if "language" in c and c["kind"] != "skip"}
    if len({LANGUAGE_ALIASES.get(x, x) for x in languages}) > 1:
        return [(x, [x]) for x in sorted(languages)]
    queries = {PurePosixPath(p).stem: c["dir"] for p, c in entries if c["kind"] == "query"}
    if len(set(queries.values())) < len(queries):
        # queries that share a directory cannot be told apart by path
        return [("", [])]
    models = [c["file"] for _, c in entries if c["kind"] == "model"]
    test_dirs = {c["dir"] for _, c in entries if c["kind"] == "test"}
    units: list[tuple[str, list[str]]] = []
    owned: set[str] = set()
    for stem, directory in queries.items():
        mine = sorted(d for d in test_dirs if d in (directory, stem))
        owned.update(mine)
        units.append((stem, sorted({directory, *mine})))
    loose = sorted(test_dirs - owned)
    if models and (loose or len(queries) > 1):
        units.append(("models", sorted(set(models)) + loose))
    elif models and units:
        units[0] = (units[0][0], units[0][1] + sorted(set(models)))
    elif loose and len(queries) == 1:
        units[0] = (units[0][0], units[0][1] + loose)
    elif loose:
        return [("", [])]
    return units if len(units) > 1 else [("", [])]


IMPORT_RE = re.compile(r"^\s*(?:private\s+)?import\s+([A-Za-z_][\w.]*)", re.M)


def shared_libraries(template: Path, pr: int, entries: list, query_dirs: set[str], query_texts: list[str]) -> list[dict]:
    """The `.qll` files of the template pack that the queries import and that no query directory owns.

    A module `a.B` is the file `a/B.qll` under the pack's `src` directory, so a library keeps that path in
    the Community Packs `src` pack and the imports keep resolving. Libraries that a library imports follow.
    """
    candidates: dict[str, dict] = {}
    for path, info in entries:
        if info["kind"] == "support" and info["dir"] not in query_dirs and info["rel"].endswith(".qll"):
            rel = f"{info['dir']}/{info['rel']}"
            candidates[".".join(PurePosixPath(rel).with_suffix("").parts)] = {"source": path, "rel": rel}
    found: dict[str, dict] = {}
    pending = list(query_texts)
    while pending:
        for module in IMPORT_RE.findall(pending.pop()):
            if module in candidates and module not in found:
                found[module] = candidates[module]
                pending.append(blob(template, pr, candidates[module]["source"]).decode("utf-8", "replace"))
    return [found[module] for module in sorted(found)]


def build_plan(template: Path, pr: int, base: str, triage: dict | None, args: argparse.Namespace) -> dict:
    entries = [(p, classify(p)) for status, p in changed_files(template, pr, base) if status != "D"]
    every_entry = list(entries)
    only = list(getattr(args, "only", None) or [])
    if only:
        entries = [(p, c) for p, c in entries if any(token in PurePosixPath(p).parts for token in only)]
        if not entries:
            raise SystemExit(f"--only {only} matches no file of pull request {pr}")
    raw_languages = {c["language"] for _, c in entries if "language" in c and c["kind"] != "skip"}
    languages = {LANGUAGE_ALIASES.get(x, x) for x in raw_languages}
    warnings: list[str] = []
    if len(languages) != 1:
        raise SystemExit(f"expected exactly one language, found {sorted(languages)}; split the pull request first")
    language = languages.pop()
    if language not in PACK_LANGUAGES:
        raise SystemExit(f"{language} has no Community Packs pack")
    if raw_languages != {language}:
        warnings.append(f"template language {sorted(raw_languages)} is migrated into the {language} pack")

    precision = args.precision or (triage or {}).get("assessed_precision")
    experimental = args.experimental if args.experimental is not None else bool((triage or {}).get("experimental", True))
    if triage and triage.get("recommended_destination") != "community-packs":
        warnings.append(f"triage destination is {triage.get('recommended_destination')}, not community-packs")
    if triage and triage.get("split_note"):
        warnings.append("triage split note: " + triage["split_note"])

    queries, tests, models, skipped = [], {}, [], []
    support: dict[str, list[dict]] = {}
    query_dirs = {c["dir"] for _, c in every_entry if c["kind"] == "query"}
    for path, info in entries:
        if info["kind"] == "support" and info["dir"] not in query_dirs and info["rel"].endswith(".qll"):
            continue  # a shared library: found below by what the queries import
        if info["kind"] == "query":
            text = blob(template, pr, path).decode("utf-8", "replace")
            try:
                header = Header(text)
            except ValueError as exc:
                warnings.append(f"{path}: {exc}")
                continue
            tags = header.tags()
            declared = header.value("precision")
            queries.append({
                "source": path, "source_dir": info["dir"], "source_stem": PurePosixPath(path).stem,
                "name": header.value("name"), "declared_precision": declared, "declared_id": header.value("id"),
                "cwe": args.cwe or cwe_dir(tags), "tags": tags,
            })
        elif info["kind"] == "support":
            support.setdefault(info["dir"], []).append({"source": path, "rel": info["rel"]})
        elif info["kind"] == "test":
            tests.setdefault(info["dir"], []).append({"source": path, "rel": info["rel"]})
        elif info["kind"] == "model":
            models.append(path)
        else:
            skipped.append({"path": path, "reason": info.get("reason", info["kind"])})

    audit = args.placement == "audit"
    # the audit bar is the lowest precision (migration guide, section 4), unless a flag says otherwise
    if audit and not args.precision:
        precision = "very-low"
    for q in queries:
        slug = args.id_name if (args.id_name and len(queries) == 1) else kebab(q["source_stem"])
        q.update({
            "id_name": slug, "target_stem": pascal(slug), "audit": audit, "group": "audit" if audit else "security",
            "precision": precision or q["declared_precision"], "experimental": experimental,
            "support": support.get(q["source_dir"], []),
        })
        q["id"] = query_id(language, slug, audit)
        q["target"] = f"{language}/src/{q['group']}/{q['cwe'] or 'CWE-???'}/{q['target_stem']}.ql"
        if not q["cwe"]:
            warnings.append(f"{q['source']}: no external/cwe tag, pass --cwe")
        if q["declared_precision"] and precision and q["declared_precision"] != precision:
            warnings.append(f"{q['target_stem']}: declared @precision {q['declared_precision']} becomes {precision}")
    if len(queries) > 1:
        warnings.append(f"{len(queries)} queries in one pull request: decide whether to split it before migrating")
    for d in support.keys() - {q["source_dir"] for q in queries}:
        warnings.append(f"support files in {d} belong to no query")

    libraries = shared_libraries(template, pr, every_entry, query_dirs, [blob(template, pr, q["source"]).decode("utf-8", "replace") for q in queries])
    for lib in libraries:
        warnings.append(f"shared library {lib['rel']} is copied to {language}/src/{lib['rel']}, so that the queries' imports keep resolving: "
                        f"decide whether it belongs in a {language}/lib pack instead")

    model_only = bool(models) and not queries
    test_name = getattr(args, "test_name", None)
    plan_tests, reference_tests = [], []
    for test_dir, files in sorted(tests.items()):
        owner = next((q for q in queries if test_dir in (q["source_dir"], q["source_stem"])), None)
        if owner is None and len(queries) == 1:
            owner = queries[0]
        if owner:
            target = f"{language}/test/{owner['group']}/{owner['cwe'] or 'CWE-???'}/{owner['target_stem']}"
        elif model_only and not getattr(args, "copy_tests", False):
            # the template tests of a model change point at stock queries that Community Packs does not have
            reference_tests += [f["source"] for f in files]
            continue
        else:
            library = test_name or (kebab(PurePosixPath(models[0]).name.removesuffix(".model.yml")) if models else kebab(test_dir))
            cwe = args.cwe or "CWE-???"
            target = f"{language}/test/security/{cwe}/{library}"
            if not args.cwe:
                warnings.append(f"tests in {test_dir}: model-only change, pass --cwe to place them")
        plan_tests.append({"source_dir": test_dir, "files": files, "target": target})
    if model_only and not plan_tests:
        # the test of a model change is written new: a test query over the real flow module, see the guide
        library = test_name or kebab(PurePosixPath(models[0]).name.removesuffix(".model.yml"))
        cwe = args.cwe or "CWE-???"
        plan_tests.append({"source_dir": None, "files": [], "target": f"{language}/test/security/{cwe}/{library}"})
        warnings.append("model-only unit: template tests are references only, write a library test (guide: Gate 2 for model-only units)")
        if not args.cwe:
            warnings.append("model-only change, pass --cwe to place the test")
    if not plan_tests:
        warnings.append("the pull request has no tests: write them before migrating")

    plan_models = []
    for path in models:
        name = PurePosixPath(path).name
        if not name.endswith(".model.yml"):
            name = name.removesuffix(".yml") + ".model.yml"
        plan_models.append({"source": path, "target": f"{language}/ext/manual/{name}" if language in EXT_LANGUAGES else None})
    if models and language not in EXT_LANGUAGES:
        warnings.append(
            f"{language} has no ext pack: data extension rows cannot go to Community Packs as they are. "
            "Model the API in QL inside the query pack, or decide to create an ext pack first."
        )
    if not queries and not models:
        warnings.append("nothing to migrate: no query and no data extension")

    return {
        "pr": pr, "language": language, "template_language": sorted(raw_languages)[0], "base": base,
        "triage_issue": (triage or {}).get("issue"), "replacements": [r.split("=", 1) for r in args.replace],
        "queries": queries, "libraries": libraries, "tests": plan_tests, "models": plan_models, "reference_tests": reference_tests,
        "skipped": skipped, "warnings": warnings,
    }


# ------------------------------------------------------------------------ apply


WARNING_KINDS = (
    ("no ext pack", re.compile(r"has no ext pack")),
    ("several queries", re.compile(r"queries in one pull request")),
    ("no tests", re.compile(r"has no tests")),
    ("no cwe", re.compile(r"no external/cwe tag|model-only change, pass --cwe")),
    ("model-only unit", re.compile(r"^model-only unit:")),
    ("triage split note", re.compile(r"^triage split note")),
    ("precision changes", re.compile(r"declared @precision")),
    ("language alias", re.compile(r"template language .* is migrated into")),
    ("orphan support files", re.compile(r"support files in")),
    ("shared library", re.compile(r"^shared library ")),
    ("nothing to migrate", re.compile(r"nothing to migrate")),
    ("triage destination differs", re.compile(r"^triage destination is")),
)


def plan_all(template: Path, triage_path: Path, base: str, out_dir: Path, destination: str) -> dict:
    """Plan every triaged pull request for one destination, split into units, and tally what needs a human."""
    triage = json.loads(triage_path.read_text(encoding="utf-8"))
    out_dir.mkdir(parents=True, exist_ok=True)
    rows, tally, issues = [], {}, set()
    for key, entry in sorted(triage.items(), key=lambda kv: int(kv[0])):
        if entry.get("recommended_destination") != destination or not entry.get("pr"):
            continue
        issues.add(key)
        try:
            units = split_units(template, entry["pr"], base)
        except SystemExit as exc:
            rows.append({"issue": int(key), "pr": entry["pr"], "unit": "", "error": str(exc)})
            continue
        for unit, tokens in units:
            defaults = argparse.Namespace(precision=None, experimental=None, placement="security", cwe=None,
                                          id_name=None, replace=[], only=tokens)
            row = {"issue": int(key), "pr": entry["pr"], "unit": unit, "triage_language": entry.get("language"),
                   "precision": entry.get("assessed_precision"), "units_in_issue": len(units)}
            try:
                spec = build_plan(template, entry["pr"], base, entry, defaults)
            except SystemExit as exc:
                row["error"] = str(exc)
            else:
                spec["template"] = str(template)
                spec["unit"] = unit
                spec["only"] = tokens
                name = f"{key}.spec.json" if not unit else f"{key}.{unit}.spec.json"
                (out_dir / name).write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
                kinds = sorted({name for w in spec["warnings"] for name, rx in WARNING_KINDS if rx.search(w)})
                row.update(spec=name, language=spec["language"], queries=len(spec["queries"]), models=len(spec["models"]),
                           tests=len(spec["tests"]), warning_kinds=kinds, warnings=spec["warnings"])
                for kind in kinds:
                    tally[kind] = tally.get(kind, 0) + 1
            rows.append(row)
    planned = [r for r in rows if "error" not in r]
    by_language: dict[str, int] = {}
    for r in planned:
        by_language[r["language"]] = by_language.get(r["language"], 0) + 1
    shape = {
        "query only": sum(1 for r in planned if r["queries"] and not r["models"]),
        "model only": sum(1 for r in planned if r["models"] and not r["queries"]),
        "query and model": sum(1 for r in planned if r["queries"] and r["models"]),
        "no warnings": sum(1 for r in planned if not r["warning_kinds"]),
    }
    return {"destination": destination, "issues": len(issues), "units": len(rows), "planned": len(planned),
            "split_issues": len({r["issue"] for r in rows if r.get("units_in_issue", 1) > 1}),
            "errors": [r for r in rows if "error" in r], "by_language": dict(sorted(by_language.items())),
            "by_shape": shape, "warning_counts": dict(sorted(tally.items())), "rows": rows}


# ------------------------------------------------------------------------ apply


def case_variants(replacements: list[list[str]]) -> list[list[str]]:
    """Each OLD=NEW also in lower, upper and capitalized form, longest first, so one flag covers the casings."""
    seen: dict[str, str] = {}
    for old, new in replacements:
        for a, b in ((old, new), (old.lower(), new.lower()), (old.upper(), new.upper()), (old.capitalize(), new.capitalize())):
            if a and a not in seen:
                seen[a] = b
    return sorted(([a, b] for a, b in seen.items()), key=lambda ab: -len(ab[0]))


def neutralize(text: str, replacements: list[list[str]]) -> str:
    for old, new in replacements:
        text = text.replace(old, new)
    return text


# Markdown query help to .qhelp, for the packs whose queries have a .qhelp (csharp, java).
LINK_RE = re.compile(r"\[((?:[^\[\]]|`[^`]*`)+)\]\(((?:[^()\s]|\([^()\s]*\))+)\)")
BULLET_RE = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$")


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _inline_plain(md: str) -> str:
    out = []
    for part in re.split(r"(`[^`]+`)", md):
        if len(part) > 1 and part.startswith("`") and part.endswith("`"):
            out.append("<code>" + _escape(part[1:-1]) + "</code>")
            continue
        text = _escape(part)
        text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<em>\1</em>", text)
        out.append(text)
    return "".join(out)


def _inline(md: str) -> str:
    out, pos = [], 0
    for m in LINK_RE.finditer(md):
        out.append(_inline_plain(md[pos:m.start()]))
        out.append(f'<a href="{_escape(m.group(2)).replace(chr(34), "%22")}">{_inline_plain(m.group(1))}</a>')
        pos = m.end()
    out.append(_inline_plain(md[pos:]))
    return "".join(out)


def md_to_qhelp(text: str) -> tuple[str, list[str]]:
    """Convert Markdown query help (title, overview, ``## Recommendation``, ``## Example``, ``## References``)
    to ``.qhelp``. Other ``##`` sections become bold headed paragraphs of the overview. Returns the XML and
    notes about anything that needed a guess."""
    notes: list[str] = []
    lines = text.replace("\r\n", "\n").split("\n")
    buckets: dict[str, list] = {"overview": [], "recommendation": [], "example": [], "references": []}
    section, para, i = "overview", [], 0

    def flush() -> None:
        if para:
            buckets[section].append(("p", " ".join(s.strip() for s in para)))
            para.clear()

    while i < len(lines):
        line = lines[i]
        fence = re.match(r"^\s*(```+|~~~+)\s*([\w#+.-]*)", line)
        heading = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        bullet = BULLET_RE.match(line)
        if fence:
            flush()
            marker, lang, code = fence.group(1)[:3], fence.group(2), []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith(marker):
                code.append(lines[i])
                i += 1
            buckets[section].append(("code", (lang, "\n".join(code))))
        elif heading:
            flush()
            level, title = len(heading.group(1)), heading.group(2)
            key = title.lower().rstrip(":")
            if level == 1:
                pass  # the query name is the title
            elif level == 2 and key in ("recommendation", "recommendations"):
                section = "recommendation"
            elif level == 2 and key in ("example", "examples"):
                section = "example"
            elif level == 2 and key in ("reference", "references"):
                section = "references"
            elif level == 2 and key == "overview":
                section = "overview"
            else:
                if level == 2:
                    section = "overview"
                buckets[section].append(("heading", title))
        elif bullet:
            flush()
            items = []
            while i < len(lines):
                m = BULLET_RE.match(lines[i])
                if m:
                    items.append(m.group(3).strip())
                elif lines[i].strip() and lines[i].startswith((" ", "\t")) and items:
                    items[-1] += " " + lines[i].strip()
                else:
                    break
                i += 1
            buckets[section].append(("ul", items))
            continue
        elif line.strip().startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-+:?", c) for c in cells):
                    rows.append(" | ".join(cells))
                i += 1
            notes.append("a Markdown table was converted to a list; check it")
            buckets[section].append(("ul", rows))
            continue
        elif not line.strip():
            flush()
        else:
            para.append(line)
        i += 1
    flush()

    def render(blocks: list) -> list[str]:
        out: list[str] = []
        for kind, payload in blocks:
            if kind == "p":
                out.append(f"<p>{_inline(payload)}</p>")
            elif kind == "heading":
                out.append(f"<p><strong>{_inline(payload)}</strong></p>")
            elif kind == "ul":
                out.append("<ul>" + "".join(f"<li>{_inline(item)}</li>" for item in payload) + "</ul>")
            else:
                lang, code = payload
                attr = f' language="{_escape(lang)}"' if lang else ""
                out.append(f"<sample{attr}>{_escape(code)}</sample>")
        return out

    xml = ['<!DOCTYPE qhelp PUBLIC', '"-//Semmle//qhelp//EN"', '"qhelp.dtd">', "<qhelp>", ""]
    for name in ("overview", "recommendation", "example"):
        if buckets[name] or name == "overview":
            xml += [f"<{name}>", *render(buckets[name]), f"</{name}>", ""]
    refs = [item for kind, payload in buckets["references"] for item in (payload if kind == "ul" else [payload] if kind == "p" else [])]
    if refs:
        xml += ["<references>", *[f"<li>{_inline(r)}</li>" for r in refs], "</references>", ""]
    xml.append("</qhelp>")
    if not buckets["recommendation"]:
        notes.append("the help has no Recommendation section")
    return "\n".join(xml) + "\n", notes


def write(root: Path, rel: str, data: bytes, written: list[str], replacements: list[list[str]], force: bool) -> None:
    rel = neutralize(rel, replacements)
    target = root / rel
    if replacements and not is_binary(data):
        data = neutralize(data.decode("utf-8", "replace"), replacements).encode("utf-8")
    if target.exists() and not force:
        if target.read_bytes() == data:
            return  # the same file, for example a library that two units of one pull request share
        raise SystemExit(f"{rel} already exists. Re-running apply would overwrite hand edits; use --force on a clean tree")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    written.append(rel)


def rewrite_qlref(text: str, mapping: dict[str, str], warnings: list[str], where: str) -> str:
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("postprocess:"):
            warnings.append(
                f"{where}: dropped '{stripped}'. The CCP packs cannot compile the inline expectations postprocess query, "
                "so the .expected file is the only oracle: re-learn it and read the diff")
            continue
        value = stripped.removeprefix("query:").strip() if stripped.startswith("query:") else stripped
        if value.endswith(".ql") and not stripped.startswith("#"):
            if value in mapping:
                out.append(f"query: {mapping[value]}")
                continue
            warnings.append(f"{where}: qlref points at {value}, which is not a migrated query; adapt the test by hand")
        out.append(line)
    return "\n".join(out) + "\n"


def bump_version(ccp: Path, pack_dir: str, base_ref: str, level: str) -> str | None:
    pack_file = ccp / pack_dir / "qlpack.yml"
    if not pack_file.exists():
        return None
    base = VERSION_RE.search(git_bytes(ccp, "show", f"{base_ref}:{pack_dir}/qlpack.yml").decode())
    raw = pack_file.read_bytes()
    current = VERSION_RE.search(raw.decode("utf-8"))
    if not base or not current:
        return None
    major, minor, patch = (int(x) for x in base.groups())
    new = (major, minor + 1, 0) if level == "minor" else (major, minor, patch + 1)
    if tuple(int(x) for x in current.groups()) >= new:
        return None
    # keep the line endings of the working copy, so that only the version line changes
    updated = VERSION_RE.sub(f"version: {new[0]}.{new[1]}.{new[2]}", raw.decode("utf-8"), count=1)
    pack_file.write_bytes(updated.encode("utf-8"))
    return f"{pack_dir}/qlpack.yml: {'.'.join(base.groups())} -> {new[0]}.{new[1]}.{new[2]}"


def without_duplicate_help(items: list[dict], stem: str) -> list[dict]:
    """The support files of a query, minus a Markdown help file that has a .qhelp twin.

    The renderer reads one of them, and two copies of the same help drift apart.
    """
    names = {PurePosixPath(i["rel"]).name for i in items}
    return [i for i in items if not (PurePosixPath(i["rel"]).name == f"{stem}.md" and f"{stem}.qhelp" in names)]


def apply_plan(spec: dict, template: Path, ccp: Path, codeql: Path | None, level: str, bump: bool, force: bool = False) -> dict:
    if not (ccp / "codeql-workspace.yml").is_file() or not (ccp / ".git").exists():
        raise SystemExit(f"{ccp} is not a Community Packs checkout (no codeql-workspace.yml and .git)")
    pr, language = spec["pr"], spec["language"]
    replacements = case_variants(spec.get("replacements", []))
    written: list[str] = []
    warnings: list[str] = []
    mapping: dict[str, str] = {}

    for q in spec["queries"]:
        # a qlref in the template names the query relative to its custom/src directory
        mapping[f"{q['source_dir']}/{q['source_stem']}.ql"] = "/".join(PurePosixPath(q["target"]).parts[2:])
    for q in spec["queries"]:
        target = PurePosixPath(q["target"])
        text = blob(template, pr, q["source"]).decode("utf-8")
        header = Header(text)
        header.set("precision", [q["precision"]])
        header.set("id", [q["id"]])
        header.set("tags", new_tags(q["tags"], cwe=q["cwe"], experimental=q["experimental"], audit=q["audit"]))
        if q["audit"]:
            # the audit bar (migration guide, section 4): a warning that asks for review
            header.set("problem.severity", ["warning"])
            header.set("security-severity", ["2.5"])
            header.set("sub-severity", ["low"])
        write(ccp, q["target"], header.rewrite(text).encode("utf-8"), written, replacements, force)
        for item in without_duplicate_help(q["support"], q["source_stem"]):
            rel = PurePosixPath(item["rel"])
            data = blob(template, pr, item["source"])
            if rel.stem == q["source_stem"] and rel.suffix in (".md", ".qhelp"):
                if rel.suffix == ".md" and language in QHELP_LANGUAGES:
                    xml, notes = md_to_qhelp(data.decode("utf-8"))
                    warnings += [f"{item['source']}: {n}" for n in notes]
                    data, rel = xml.encode("utf-8"), PurePosixPath(q["target_stem"] + ".qhelp")
                else:
                    rel = PurePosixPath(q["target_stem"] + rel.suffix)
            write(ccp, str(target.parent / rel), data, written, replacements, force)

    renames = {q["source_stem"]: q["target_stem"] for q in spec["queries"]}
    for lib in spec.get("libraries", []):
        write(ccp, f"{language}/src/{lib['rel']}", blob(template, pr, lib["source"]), written, replacements, force)
    for t in spec["tests"]:
        for item in t["files"]:
            data = blob(template, pr, item["source"])
            rel = PurePosixPath(item["rel"])
            if rel.suffix == ".qlref":
                data = rewrite_qlref(data.decode("utf-8"), mapping, warnings, item["source"]).encode("utf-8")
            # <Name>.qlref, <Name>.expected, <Name>.ext.yml and the like follow the query's new name
            for old, new in renames.items():
                if rel.name.startswith(old + "."):
                    rel = rel.with_name(new + rel.name[len(old):])
                    break
            write(ccp, f"{t['target']}/{rel}", data, written, replacements, force)

    for m in spec["models"]:
        if m["target"]:
            write(ccp, m["target"], blob(template, pr, m["source"]), written, replacements, force)
    for t in spec["tests"]:
        if not t["files"]:
            warnings.append(f"{t['target']}: no template test files are copied, write the test there "
                            "(references/migration-guide.md, Gate 2 for model-only units)")
    if spec.get("reference_tests"):
        warnings.append("template tests are references only, read them with git show refs/prs/<pr>:<path>: "
                        + ", ".join(spec["reference_tests"][:6]) + (" ..." if len(spec["reference_tests"]) > 6 else ""))

    bumped = []
    if bump:
        base_ref = spec.get("ccp_base", "origin/main")
        if spec["queries"]:
            bumped.append(bump_version(ccp, f"{language}/src", base_ref, level))
        if any(m["target"] for m in spec["models"]):
            bumped.append(bump_version(ccp, f"{language}/ext", base_ref, level))
    formatted = None
    if codeql:
        ql_files = [w for w in written if w.endswith((".ql", ".qll"))]
        if ql_files:
            proc = run_codeql(codeql, ccp, "query", "format", "--in-place", *ql_files)
            formatted = proc.returncode == 0
            if not formatted:
                warnings.append("codeql query format failed: " + proc.stderr.strip()[:300])
    return {"written": written, "version_bumps": [b for b in bumped if b], "formatted": formatted, "warnings": warnings}


# ------------------------------------------------------------------------ check


def changed_paths(ccp: Path, base: str) -> list[str]:
    """Every file the unit changes against ``base``: committed, modified or new, ignored files excluded.

    A new file that ``codeql test run`` generated in a test directory (see GENERATED_TEST_ARTIFACTS) is not
    part of the change.
    """
    tracked = git_bytes(ccp, "diff", "--name-only", "--no-renames", "-z", base).decode("utf-8", "replace").split("\0")
    return sorted({p for p in tracked + untracked_paths(ccp) if p})


# What ``codeql test run`` leaves in a test directory next to the committed files: the Rust extractor builds a
# throwaway crate there. A local run must not turn them into part of a change.
GENERATED_TEST_ARTIFACTS = {"rust": ("Cargo.toml", "lib.rs", "target", ".proc_macro", ".lib")}


def generated_test_artifact(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if len(parts) < 4 or parts[1] != "test":
        return False
    return any(part in GENERATED_TEST_ARTIFACTS.get(parts[0], ()) for part in parts[2:])


def untracked_paths(ccp: Path) -> list[str]:
    """New files that git does not ignore, without what a local test run generated."""
    raw = git_bytes(ccp, "ls-files", "--others", "--exclude-standard", "-z").decode("utf-8", "replace").split("\0")
    return [p for p in raw if p and not generated_test_artifact(p)]


def existing_ids(ccp: Path, ignore: set[str]) -> dict[str, str]:
    ids: dict[str, str] = {}
    for path in ccp.rglob("*.ql"):
        rel = path.relative_to(ccp).as_posix()
        if rel in ignore or "/test/" in rel or rel.startswith(".git/"):
            continue
        match = re.search(r"@id\s+(\S+)", path.read_text(encoding="utf-8", errors="replace")[:6000])
        if match:
            ids.setdefault(match.group(1), rel)
    return ids


def lint(ccp: Path, spec: dict, deny: list[str], base: str = "origin/main") -> list[str]:
    problems: list[str] = []
    queries = {q["target"]: q for q in spec["queries"]}
    others = existing_ids(ccp, set(queries))
    seen: dict[str, str] = {}
    for rel, q in queries.items():
        text = (ccp / rel).read_text(encoding="utf-8")
        try:
            header = Header(text)
        except ValueError as exc:
            problems.append(f"{rel}: {exc}")
            continue
        for tag in REQUIRED_TAGS:
            if not header.value(tag):
                problems.append(f"{rel}: missing @{tag}")
        qid = header.value("id") or ""
        if not ID_PATTERN.match(qid):
            problems.append(f"{rel}: @id {qid!r} does not match githubsecuritylab/[audit/]<language>/<kebab-name>")
        elif f"/{ID_LANGUAGE[spec['language']]}/" not in qid:
            problems.append(f"{rel}: @id {qid!r} has the wrong language segment for {spec['language']}")
        if qid in others:
            problems.append(f"{rel}: @id {qid} is already used by {others[qid]}")
        if qid in seen:
            problems.append(f"{rel}: @id {qid} is also used by {seen[qid]}")
        seen[qid] = rel
        if header.value("precision") not in PRECISIONS:
            problems.append(f"{rel}: @precision {header.value('precision')!r} is not one of {', '.join(PRECISIONS)}")
        tags = header.tags()
        cwe = cwe_dir(tags)
        if "security" not in tags or not cwe:
            problems.append(f"{rel}: @tags need security and external/cwe/cwe-NNN")
        if q["experimental"] != ("experimental" in tags):
            problems.append(f"{rel}: the experimental tag does not match the plan")
        if q["audit"] and "audit" not in tags:
            problems.append(f"{rel}: an audit query needs the audit tag")
        if f"/{q['group']}/" not in rel or (cwe and cwe not in rel):
            problems.append(f"{rel}: lives outside {q['group']}/{cwe}")

    forbidden = [
        (re.compile(r"\bimport\s+[\w.:]*\binternal\b|\.internal\.|\binternal\s*::"), "uses an internal library"),
        (re.compile(r"getAQlClass"), "uses getAQlClass"),
        (re.compile(r"toString\(\)\s*\.\s*(regexp|matches|prefix|suffix|indexOf)"), "matches text on toString()"),
    ]
    denied = [re.compile(re.escape(w), re.I) for w in deny if w]
    for rel in changed_paths(ccp, base):
        file = ccp / rel
        if not file.is_file():
            continue
        if any(part.endswith(".testproj") for part in PurePosixPath(rel).parts) or file.suffix in (".actual", ".bqrs", ".class"):
            problems.append(f"{rel}: a build or test artifact must not be part of the change")
            continue
        problems += [f"{rel}: the file name contains {d.pattern!r}" for d in denied if d.search(rel)]
        data = file.read_bytes()
        if is_binary(data):
            problems.append(f"{rel}: a binary file, check that it belongs")
            continue
        text = data.decode("utf-8", errors="replace")
        if file.suffix in (".ql", ".qll") and "/test/" not in rel:
            problems += [f"{rel}: {why}" for pattern, why in forbidden if pattern.search(text)]
        if file.suffix == ".qlref" and re.search(r"^\s*postprocess:", text, re.M):
            problems.append(f"{rel}: a postprocess line cannot compile in the CCP packs, remove it")
        problems += [f"{rel}: contains {d.pattern!r}" for d in denied if d.search(text)]

    for rel in queries:
        stem = str(Path(rel).with_suffix(""))
        if not any((ccp / (stem + ext)).is_file() for ext in (".qhelp", ".md")):
            problems.append(f"{rel}: no query help file (.qhelp or .md) next to the query")
    if any(m["target"] for m in spec["models"]):
        language = spec["language"]
        test_pack = ccp / language / "test" / "qlpack.yml"
        wanted = f"githubsecuritylab/codeql-{language}-extensions"
        if not test_pack.is_file() or wanted not in test_pack.read_text(encoding="utf-8", errors="replace"):
            problems.append(f"{language}/test/qlpack.yml does not depend on {wanted}: add it, or the model test cannot see the rows")
    return problems


def version_problems(ccp: Path, base: str) -> list[str]:
    """A release sets every pack version (see the guide), so a pull request leaves existing versions alone."""
    problems: list[str] = []
    for rel in changed_paths(ccp, base):
        if PurePosixPath(rel).name != "qlpack.yml" or not (ccp / rel).is_file():
            continue
        was = VERSION_RE.search(git_bytes(ccp, "show", f"{base}:{rel}", check=False).decode("utf-8", "replace"))
        now = VERSION_RE.search((ccp / rel).read_text(encoding="utf-8", errors="replace"))
        if was and now and was.groups() != now.groups():
            problems.append(f"{rel}: the pack version changes from {'.'.join(was.groups())} to {'.'.join(now.groups())}, leave it to the release")
    return problems


def shipped_ql(ccp: Path, spec: dict, base: str) -> list[str]:
    """The .ql and .qll files this unit adds or changes."""
    return [p for p in changed_paths(ccp, base) if p.endswith((".ql", ".qll")) and (ccp / p).is_file()]


def format_problems(codeql: Path, ccp: Path, files: list[str]) -> str:
    """Files that ``codeql query format`` would change, compared with LF line endings.

    A Windows checkout may use CRLF for files that git stores with LF, and the formatter rejects
    CRLF. CI sees the stored LF, so the comparison is made on that.
    """
    if not files:
        return ""
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        copies = []
        for i, rel in enumerate(files):
            dest = Path(tmp) / f"f{i}" / Path(rel).name
            dest.parent.mkdir()
            dest.write_bytes((ccp / rel).read_bytes().replace(b"\r\n", b"\n"))
            copies.append((rel, dest))
        proc = run_codeql(codeql, ccp, "query", "format", "--check-only", *[str(d) for _, d in copies])
        if proc.returncode:
            text = proc.stdout + proc.stderr
            problems = [rel for rel, dest in copies if str(dest) in text] or ["see the formatter output"]
            return "needs formatting (run: codeql query format --in-place): " + ", ".join(problems)
    return ""


def suite_effect(ccp: Path, codeql: Path, spec: dict) -> dict:
    """Which of the language's suites select each query of the unit."""
    language = spec["language"]
    suites = sorted((ccp / language / "src" / "suites").glob("*.qls")) if (ccp / language / "src" / "suites").is_dir() else []
    targets = {Path(q["target"]).as_posix(): q["id"] for q in spec["queries"]}
    effect: dict = {}
    for suite in suites:
        proc = run_codeql(codeql, ccp, "resolve", "queries", "--additional-packs", language, str(suite.relative_to(ccp)))
        resolved = {line.strip().replace("\\", "/") for line in proc.stdout.splitlines()}
        selected = [rel for rel in targets if any(r.endswith(rel) for r in resolved)] if proc.returncode == 0 else None
        effect[suite.name] = {"resolves": proc.returncode == 0, "selects": selected, "queries": len(resolved) if proc.returncode == 0 else None}
    return effect


def suite_gaps(spec: dict, effect: dict) -> list[str]:
    """Queries of the unit that the suite for their group does not select, and audit queries that `<language>.qls` does.

    A security query is selected by `<language>.qls`, an audit query by `<language>-audit.qls` and never by
    `<language>.qls`. A query that no suite selects runs in no config, however the configs are set up.
    """
    language = spec["language"]
    problems: list[str] = []
    default = effect.get(f"{language}.qls") or {}
    for q in spec["queries"]:
        rel = Path(q["target"]).as_posix()
        suite = f"{language}-audit.qls" if q["audit"] else f"{language}.qls"
        info = effect.get(suite)
        if info is None:
            problems.append(f"{rel}: there is no {language}/src/suites/{suite}, so no suite selects it "
                            "(community_packs_onboard.py --apply creates a missing audit suite)")
        elif not info["resolves"]:
            problems.append(f"{rel}: {suite} does not resolve")
        elif rel not in (info["selects"] or []):
            problems.append(f"{rel}: {suite} does not select it: its kind, precision or tags keep it out")
        if q["audit"] and rel in (default.get("selects") or []):
            problems.append(f"{rel}: an audit query must stay out of {language}.qls")
    return problems


def unit_gaps(spec: dict, ccp: Path, base: str) -> list[dict]:
    """The config and suite gaps of the unit's language that this unit's content depends on.

    A pack that does not exist at ``base`` is new: its config lines wait for the first release, because a config
    on main must not name a pack that consumers cannot download yet (configs/README.md).
    """
    language = spec["language"]
    kinds: set[str] = set()
    if any(not q["audit"] for q in spec["queries"]):
        kinds |= {"config-queries-pack", "security-suite"}
    if any(q["audit"] for q in spec["queries"]):
        kinds |= {"audit-suite", "audit-config"}
    if any(m["target"] for m in spec["models"]):
        kinds.add("config-ext-pack")
    new_queries = not git_bytes(ccp, "show", f"{base}:{language}/src/qlpack.yml", check=False)
    new_ext = not git_bytes(ccp, "show", f"{base}:{language}/ext/qlpack.yml", check=False)

    def published(pack: str, path: str) -> bool | None:
        if path == "" and ((pack.endswith("-queries") and new_queries) or (pack.endswith("-extensions") and new_ext)):
            return False
        return None

    gaps = onboard.onboard_gaps(onboard.language_state(ccp, language), onboard.read_configs(ccp), published)
    return [g for g in gaps if g["kind"] in kinds]


def config_rows(codeql: Path, ccp: Path, language: str, query: Path) -> list:
    """The ``threatModelConfiguration`` rows that apply to a query: none when no user config leaks in."""
    proc = run_codeql(codeql, ccp, "resolve", "extensions", "--additional-packs", language, str(query))
    if proc.returncode:
        return [["resolve extensions failed", proc.stderr.strip()[-200:]]]
    rows: list = []
    for pack in json.loads(proc.stdout).get("threatModels", {}).values():
        for ext in pack.get("extensions", []):
            if ext.get("addsTo", {}).get("extensible") == "threatModelConfiguration":
                rows.extend(ext.get("data", []))
    return rows


def lock_changes(ccp: Path) -> dict[str, str]:
    """Lock files that differ from HEAD or are new, as {path: two letter git status}."""
    text = git_bytes(ccp, "status", "--short", "--", "*.lock.yml").decode()
    return {line[3:].strip(): line[:2] for line in text.splitlines() if line.strip()}


def undo_lock_churn(ccp: Path, before: dict[str, str], contents: dict[str, bytes] | None = None) -> list[str]:
    """Undo the lock file changes made since `before` was taken, and return their paths.

    `codeql pack install` rewrites a lock file whenever the pinned CLI bundles the locked packs (the Rust
    libraries of CLI 2.27.5 do), and CI never commits that. A lock file that already differed before the
    gates ran, so that the unit itself changed it, is a finding, and the gates put it back to the content it
    had then (`contents`) when they rewrote it.
    """
    undone = []
    for path, state in lock_changes(ccp).items():
        if path in before:
            if contents and path in contents and (ccp / path).read_bytes() != contents[path]:
                (ccp / path).write_bytes(contents[path])
                undone.append(path)
            continue
        if state.strip() == "??":
            (ccp / path).unlink()
        else:
            git_bytes(ccp, "checkout", "--", path)
        undone.append(path)
    return sorted(undone)


def run_checks(spec: dict, ccp: Path, codeql: Path, deny: list[str], learn: bool,
               threads: int = DEFAULT_THREADS, base: str = "origin/main", run_tests: bool = True,
               allow_locks: list[str] | None = None, allow_unselected: bool = False,
               allow_config_gap: str | None = None) -> dict:
    language = spec["language"]
    results: list[dict] = []
    thread_arg = f"--threads={threads}"
    locks_before = lock_changes(ccp)
    locks_content = {path: (ccp / path).read_bytes() for path in locks_before if (ccp / path).is_file()}

    def step(name: str, ok: bool, detail: str = "") -> None:
        results.append({"step": name, "ok": ok, "detail": detail.strip()[-1500:]})

    expected = (ccp / ".codeqlversion").read_text().strip() if (ccp / ".codeqlversion").exists() else None
    version = run_codeql(codeql, ccp, "version", "--format=terse").stdout.strip()
    step("cli version matches .codeqlversion", expected in (None, version), f"cli {version}, pinned {expected}")
    problems = lint(ccp, spec, deny, base) + version_problems(ccp, base)
    step("community packs rules", not problems, "\n".join(problems))

    ql_files = shipped_ql(ccp, spec, base)
    if ql_files:
        problem = format_problems(codeql, ccp, ql_files)
        step("query format (LF)", not problem, problem)
    for pack in (f"{language}/lib", f"{language}/src", f"{language}/test"):
        if (ccp / pack / "qlpack.yml").exists() and (pack != f"{language}/lib" or any(p.startswith(pack + "/") for p in changed_paths(ccp, base))):
            proc = run_codeql(codeql, ccp, "pack", "install", "--additional-packs", language, pack)
            step(f"pack install {pack}", proc.returncode == 0, proc.stderr)
    probe = next((ccp / q["target"] for q in spec["queries"] if (ccp / q["target"]).exists()), None) \
        or next((ccp / language / "src").rglob("*.ql"), None)
    if probe:
        rows = config_rows(codeql, ccp, language, probe)
        step("no user level CodeQL config applies", not rows, f"threat model rows: {rows}")
    if ql_files:
        # CI compiles every .ql under the language directory strictly, tests included
        proc = run_codeql(codeql, ccp, "query", "compile", "--additional-packs", language, thread_arg, "--check-only",
                          "--warnings=error", *[f for f in ql_files if f.endswith(".ql")])
        step("compile --warnings=error (queries and test queries)", proc.returncode == 0, proc.stdout + proc.stderr)
    if spec["queries"]:
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_codeql(codeql, ccp, "generate", "query-help", "--format=markdown", f"--output={tmp}",
                              *[q["target"] for q in spec["queries"]])
            made = sum(1 for _ in Path(tmp).rglob("*.md"))
            step("query help renders", proc.returncode == 0 and made >= len(spec["queries"]),
                 f"{made} of {len(spec['queries'])} help files rendered. " + proc.stderr)
    test_dirs = [t["target"] for t in spec["tests"] if (ccp / t["target"]).is_dir()]
    if not run_tests:
        step("codeql test run", True, "skipped on request (--skip-tests): CI runs the tests, so the packet says they were not run locally")
    elif test_dirs:
        extra = ["--learn"] if learn else []
        proc = run_codeql(codeql, ccp, "test", "run", "--additional-packs", language, thread_arg, *extra, *test_dirs)
        step("codeql test run" + (" --learn" if learn else ""), proc.returncode == 0, proc.stdout + proc.stderr)
    else:
        step("codeql test run", False, "no tests")
    if any(m["target"] for m in spec["models"]):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_codeql(codeql, ccp, "pack", "create", "--additional-packs", language, f"--output={tmp}", f"{language}/ext")
            step(f"pack create {language}/ext", proc.returncode == 0, proc.stdout + proc.stderr)
    effect = suite_effect(ccp, codeql, spec)
    if spec["queries"]:
        problems = suite_gaps(spec, effect)
        step("every query is selected by the suite for its group", not problems or allow_unselected,
             "\n".join(problems) + ("\n(accepted with --allow-unselected)" if problems and allow_unselected else ""))
    gaps = unit_gaps(spec, ccp, base)
    now = [g for g in gaps if g["when"] == "now"]
    later = [g["message"] for g in gaps if g["when"] != "now"]
    step("the configs and suites make the queries and models run", not now or bool(allow_config_gap),
         "\n".join(g["message"] for g in now)
         + (f"\n(accepted: {allow_config_gap})" if now and allow_config_gap else "")
         + (f"\nfix: python community_packs_onboard.py --ccp <checkout> --language {language} --apply" if now else "")
         + "".join(f"\nafter the release: {m}" for m in later))
    undone = undo_lock_churn(ccp, locks_before, locks_content)
    unexpected = {path: state for path, state in locks_before.items() if path not in (allow_locks or [])}
    step("no lock file churn", not unexpected,
         "\n".join(f"{state} {path}" for path, state in unexpected.items())
         + ("\n(on purpose: " + ", ".join(sorted(set(locks_before) - set(unexpected))) + ")" if len(unexpected) < len(locks_before) else "")
         + (f"\n(undid what pack install rewrote: {', '.join(undone)})" if undone else ""))
    return {"ok": all(r["ok"] for r in results), "tests_run": run_tests, "results": results, "suites": effect,
            "after_release": later}


# ---------------------------------------------------------------------- measure

EVAL_RE = re.compile(r"^\[[^\]]+\] Evaluated (?:non-)?recursive predicate (?P<name>.+?) in (?P<ms>\d+)ms \(size: (?P<size>\d+)\)")
LAYER_RE = re.compile(r"Completed evaluation of a recursive layer containing (?P<n>\d+) different predicates \(took (?P<ms>\d+)ms\)")
CARTESIAN_RE = re.compile(r"^\s*(?P<n>\d+)\s+~\d+%\s+\{\d+\}\s+\|\s+JOIN WITH .* CARTESIAN PRODUCT")
ANONYMOUS_RE = re.compile(r"^_*(let\d+|#select)")


def parse_log_summary(text: str, stem: str, blowup_tuples: int) -> dict:
    """Split an evaluator log summary into the query's own cost and the library's.

    A predicate is the query's own when its name has the query name in it, as in
    ``Query::isSource`` or ``MakeImpl<...>::DefaultState<<Query>::Config>::isSource``, or when it is
    an anonymous ``let`` or ``#select`` predicate. Cartesian products are only in the log when the
    run counted tuples. Those of library predicates are reported but do not fail the gate.
    """
    own = re.compile(rf"(?:^|[^A-Za-z0-9_]){re.escape(stem)}::")
    predicates: list[dict] = []
    layers: list[dict] = []
    products: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        if m := EVAL_RE.match(line):
            current = {"name": m["name"], "ms": int(m["ms"]), "size": int(m["size"])}
            predicates.append(current)
        elif m := LAYER_RE.search(line):
            layers.append({"predicates": int(m["n"]), "ms": int(m["ms"])})
        elif (m := CARTESIAN_RE.match(line)) and current and int(m["n"]) >= blowup_tuples:
            products.append({"predicate": current["name"], "ms": current["ms"], "tuples": int(m["n"])})
    is_own = lambda name: bool(own.search(name) or ANONYMOUS_RE.match(name))  # noqa: E731
    mine = [p for p in predicates if is_own(p["name"])]
    return {
        "predicates": len(predicates),
        "own_ms": sum(p["ms"] for p in mine),
        "own_top": sorted(mine, key=lambda p: -p["ms"])[:5],
        "recursive_layers_ms": sum(layer["ms"] for layer in layers),
        "top_predicates": sorted(predicates, key=lambda p: -p["ms"])[:8],
        "top_layers": sorted(layers, key=lambda layer: -layer["ms"])[:3],
        "blowups": [b for b in products if is_own(b["predicate"])],
        "library_blowups": [b for b in products if not is_own(b["predicate"])][:10],
    }


# Cost classes. The budget (60 s of own predicates by default) stays the hard gate. The classes say how much
# headroom a query that passes has, because the pack's CI only runs tests on databases of a few files and has no
# time limit for a query. The limits assume that the cost grows with the database: 10 s on a corpus of about
# 19,000 files is minutes on a large monorepo database.
MODERATE_OWN_MS = 10_000
MODERATE_PREDICATE_MS = 5_000
MODERATE_WALL_S = 600
COST_ORDER = {"low": 0, "moderate": 1, "high": 2}


def classify_cost(item: dict, budget: float) -> tuple[str, list[str]]:
    """The cost class of one measured query ("low", "moderate" or "high") and the reasons for it.

    High is what the gate fails: the run did not finish, the query's own predicates contain a cartesian
    product, or they take longer than the budget. Moderate passes the gate with little headroom: the own
    predicates take more than MODERATE_OWN_MS, one of them takes more than MODERATE_PREDICATE_MS, or the whole
    run (library included) takes more than MODERATE_WALL_S. Anything else is low.
    """
    high: list[str] = []
    if not item.get("completed"):
        high.append(item.get("timed_out") or "the evaluation did not finish")
    if item.get("blowups"):
        high.append(f"{len(item['blowups'])} cartesian product(s) in the query's own predicates")
    own_ms = item.get("own_ms", 0)
    if own_ms > budget * 1000:
        high.append(f"own predicates take {own_ms / 1000:.1f} s, over the budget of {budget:g} s")
    if high:
        return "high", high
    moderate: list[str] = []
    if own_ms > MODERATE_OWN_MS:
        moderate.append(f"own predicates take {own_ms / 1000:.1f} s (over {MODERATE_OWN_MS / 1000:g} s)")
    slowest = max(item.get("own_top") or [{"ms": 0, "name": ""}], key=lambda p: p["ms"])
    if slowest["ms"] > MODERATE_PREDICATE_MS:
        moderate.append(f"one own predicate takes {slowest['ms'] / 1000:.1f} s ({slowest['name']})")
    if item.get("wall_s", 0) > MODERATE_WALL_S:
        moderate.append(f"the whole run took {item['wall_s'] / 60:.0f} minutes, library included")
    return ("moderate", moderate) if moderate else ("low", [])


def decode_rows(codeql: Path, cwd: Path, bqrs: Path) -> list[dict]:
    proc = run_codeql(codeql, cwd, "bqrs", "decode", "--format=json", "--entities=all", str(bqrs))
    if proc.returncode:
        return []
    rows = []
    for tuple_ in json.loads(proc.stdout).get("#select", {}).get("tuples", []):
        url = next((c["url"] for c in tuple_ if isinstance(c, dict) and c.get("url")), None)
        text = next((c for c in tuple_ if isinstance(c, str)), "")
        rows.append({
            "file": re.sub(r"^file:/+", "", url["uri"]) if url else None,
            "line": url.get("startLine") if url else None,
            "message": text,
            "values": [c["label"] if isinstance(c, dict) and "label" in c else c for c in tuple_],
        })
    return rows


def measure(spec: dict, ccp: Path, codeql: Path, db: Path, out: Path, timeout: int, budget: float,
            blowup_tuples: int, threads: int = DEFAULT_THREADS, max_wall: int = 7200,
            tuple_counting: bool = False, slots: int = DEFAULT_SLOTS) -> dict:
    """Run every query of the spec on a database, profile it and keep the rows for triage.

    A query that passes its tests can still be unusable: a join over every expression of a
    database is invisible on a three file test database and unbounded on a real corpus. The gate
    fails when the evaluation does not finish within ``max_wall`` seconds, or when the query's own
    predicates take more than ``budget`` seconds (or, with ``tuple_counting``, contain a cartesian
    product of ``blowup_tuples`` tuples or more). The library's cost is reported, not judged.

    Counting tuples changes how the evaluator runs: one corpus took 23 minutes counted and 36
    seconds plain. So the default run is plain. Turn counting on to diagnose a failure.

    Every result also gets a cost class (`classify_cost`): a query can pass the gate with little
    headroom, and the pack's CI cannot tell, so the class goes into the packet.
    """
    if not spec["queries"]:
        return {"ok": None, "applicable": False, "results": [],
                "note": "no query in this unit: the evidence is the before and after of a stock query (guide, Gate 2 for model-only units)"}
    language = spec["language"]
    results = []
    for q in spec["queries"]:
        rel = q["target"]
        stem = Path(rel).stem
        target = out / stem
        target.mkdir(parents=True, exist_ok=True)
        bqrs, log = target / "result.bqrs", target / "eval.jsonl"
        args = ["query", "run", f"--database={db}", f"--additional-packs={ccp / language}", f"--output={bqrs}",
                f"--evaluator-log={log}", f"--threads={threads}", f"--timeout={timeout}"]
        if tuple_counting:
            args.append("--tuple-counting")
        with heavy_slot(slots, f"measure {stem}") as waited:
            started = time.monotonic()
            proc = run_codeql(codeql, ccp, *args, rel, timeout=max_wall)
            wall = round(time.monotonic() - started, 1)
        item: dict = {"query": rel, "completed": proc.returncode == 0, "wall_s": wall, "waited_s": waited,
                      "threads": threads, "tuple_counting": tuple_counting, "stderr": proc.stderr.strip()[-400:]}
        if proc.returncode == 124:
            item["timed_out"] = f"killed after {max_wall}s"
        if proc.returncode == 0:
            summary = target / "summary.txt"
            gen = run_codeql(codeql, ccp, "generate", "log-summary", "--format=text", str(log), str(summary))
            if gen.returncode == 0:
                item.update(parse_log_summary(summary.read_text(encoding="utf-8", errors="replace"), stem, blowup_tuples))
            rows = decode_rows(codeql, ccp, bqrs)
            (target / "rows.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
            item["rows"] = len(rows)
        item["ok"] = proc.returncode == 0 and item.get("own_ms", 0) <= budget * 1000 and not item.get("blowups")
        item["cost_class"], item["cost_notes"] = classify_cost(item, budget)
        results.append(item)
    worst = max((r["cost_class"] for r in results), key=COST_ORDER.get)
    return {"ok": all(r["ok"] for r in results), "cost_class": worst, "database": str(db), "budget_s": budget,
            "results": results}


# ------------------------------------------------------------------------- scan

SECRET_PATTERNS = (
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"), "a GitHub token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "an AWS access key id"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "a private key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "a Slack token"),
)
# (pattern, what it is, level in a changed file, level in commit message, branch name and pull request text)
INTERNAL_PATTERNS = (
    (re.compile(r"codeql-development-template|codeql-forks-felickz", re.I),
     "names the template pipeline", "fail", "fail"),
    (re.compile(r"[A-Za-z]:\\(?:Users|\.copilot)\b|C:/Users|/home/[a-z]"), "a local path", "fail", "fail"),
    (re.compile(r"<<[A-Z_]+>>|\bFIXME\b|\blorem ipsum\b", re.I), "an unfinished placeholder", "fail", "fail"),
    (re.compile(r"[\u2013\u2014]"), "an em or en dash", "fail", "fail"),
    (re.compile(r"\bsynthetic\b|\bgap issue\b|\bAI scan\b|\bthe tracker\b", re.I), "pipeline vocabulary", "warn", "fail"),
)
URL_RE = re.compile(r"https?://[^\s)>\]\"'`<]+")
URL_ALLOWED = (
    "docs.github.com", "github.com/github/codeql", "github.com/GitHubSecurityLab", "github.com/actions/",
    "cwe.mitre.org", "owasp.org", "cheatsheetseries.owasp.org", "nvd.nist.gov", "learn.microsoft.com",
    "docs.microsoft.com", "developer.mozilla.org", "en.wikipedia.org", "www.rfc-editor.org", "datatracker.ietf.org",
    "docs.python.org", "docs.oracle.com", "pkg.go.dev", "go.dev", "docs.djangoproject.com", "guides.rubyonrails.org",
    "ruby-doc.org", "example.com", "example.org", "localhost", "127.0.0.1",
)


def local_root_pattern(path: str) -> re.Pattern | None:
    """The top directory of a Windows path (D:\\work for D:\\work\\ccp), which no published text may name.

    The fixed patterns know the user profile, not the directory a person keeps their work in, so the
    checkout itself says where that is.
    """
    win = PureWindowsPath(path)
    if not win.drive or len(win.parts) < 2:
        return None
    return re.compile(re.escape(win.drive) + r"[\\/]" + re.escape(win.parts[1]) + r"(?!\w)", re.I)


def scan(ccp: Path, base: str, deny: list[str], pr_body: Path | None) -> dict:
    """The last gate before anything is published: every outbound string and every changed file."""
    findings: list[dict] = []
    patterns = INTERNAL_PATTERNS
    root = local_root_pattern(os.path.abspath(ccp))
    if root:
        patterns += ((root, "a local path", "fail", "fail"),)

    def add(level: str, where: str, what: str) -> None:
        findings.append({"level": level, "where": where, "what": what})

    denied = [re.compile(re.escape(w), re.I) for w in deny if w]
    if not denied:
        add("warn", "deny list", "no deny terms were given, so application, customer and internal names are not checked "
                                 "(use --deny-file, --deny or CCP_EXTRA_DENY)")

    def scan_text(where: str, text: str, prose: bool) -> None:
        for d in denied:
            if d.search(text):
                add("fail", where, f"contains the denied word {d.pattern!r}")
        for rx, why in SECRET_PATTERNS:
            if rx.search(text):
                add("fail", where, f"looks like {why}")
        for rx, why, in_file, in_prose in patterns:
            if rx.search(text):
                add(in_prose if prose else in_file, where, why)
        for url in sorted(set(URL_RE.findall(text))):
            host_path = re.sub(r"^https?://", "", url)
            if re.search(r"codeql-forks-felickz|codeql-development-template", url):
                add("fail", where, f"links to the template pipeline: {url}")
            elif not host_path.startswith(URL_ALLOWED):
                add("warn", where, f"link to check that it is public and meant to be cited: {url}")

    log = git_bytes(ccp, "log", "--format=%an <%ae>|%cn <%ce>|%G?%n%B%x00", f"{base}..HEAD").decode("utf-8", "replace")
    commits = [c for c in log.split("\0") if c.strip()]
    if not commits:
        add("warn", "commits", f"no commit on top of {base}: the scan covers the working tree only")
    for n, commit in enumerate(commits):
        head, _, message = commit.strip().partition("\n")
        for who in re.findall(r"<([^>]+)>", head):
            if not who.endswith("users.noreply.github.com") and not who.startswith("223556219+Copilot"):
                add("warn", f"commit {n} author or committer", f"an email that is not a GitHub noreply address: {who}")
        if head.rstrip().endswith("|N"):
            add("info", f"commit {n}", "unsigned: sign it before it is pushed")
        scan_text(f"commit {n} message", message, prose=True)
    scan_text("branch name", git_bytes(ccp, "branch", "--show-current").decode().strip(), prose=True)
    if pr_body:
        scan_text("pull request text", pr_body.read_text(encoding="utf-8"), prose=True)
    for rel in changed_paths(ccp, base):
        file = ccp / rel
        if not file.is_file():
            continue
        scan_text(f"file name {rel}", rel, prose=False)
        data = file.read_bytes()
        if is_binary(data):
            add("warn", rel, "binary file")
            continue
        scan_text(rel, data.decode("utf-8", errors="replace"), prose=False)
    counts = {level: sum(1 for f in findings if f["level"] == level) for level in ("fail", "warn", "info")}
    return {"ok": counts["fail"] == 0, "counts": counts, "findings": findings}


# ---------------------------------------------------------------------- baseline


def baseline(ccp: Path, codeql: Path, languages: list[str], out: Path, threads: int, slots: int) -> dict:
    """CI's strict compile of a whole language, on the checkout as it is (use main).

    A change to any file other than a ``.ql`` (a help file, a test fixture, a pack manifest) makes CI compile every query of the language with ``--warnings=error``. If that
    already fails on main, every pull request in that language is red for a reason that is not its own.
    """
    out.mkdir(parents=True, exist_ok=True)
    noise = ("restricted method", "System::load", "native-access", "Restricted methods")
    report: dict = {}
    for language in languages:
        for pack in ("lib", "src", "test"):
            if (ccp / language / pack / "qlpack.yml").exists():
                run_codeql(codeql, ccp, "pack", "install", "--additional-packs", language, f"{language}/{pack}")
        with heavy_slot(slots, f"baseline {language}"):
            started = time.monotonic()
            proc = run_codeql(codeql, ccp, "query", "compile", "--additional-packs", language, f"--threads={threads}",
                              "--check-only", "--warnings=error", f"./{language}/")
        lines = [l for l in (proc.stdout + proc.stderr).splitlines()
                 if l.startswith(("ERROR", "WARNING")) and not any(n in l for n in noise)]
        report[language] = {"ok": proc.returncode == 0, "seconds": round(time.monotonic() - started),
                            "diagnostics": len(lines), "first": lines[:15]}
        (out / f"{language}.json").write_text(json.dumps(report[language], indent=2), encoding="utf-8")
    return report


# ---------------------------------------------------------------------- rollout

PRECISION_RANK = {p: i for i, p in enumerate(PRECISIONS)}
# A unit with one of these warnings needs a decision before a worker can start.
BLOCKING_WARNINGS = {"no ext pack", "nothing to migrate", "no tests"}
GENERIC_APP_WORDS = {
    "flask", "broken", "vulnerable", "snippets", "insecure", "django", "spring", "express", "android",
    "java", "python", "ruby", "node", "swift", "dotnet", "application", "project", "example", "tests",
}
COMMON_DENY = ["codeql-development-template", "codeql-forks-felickz"]


def unit_key(row: dict) -> str:
    return str(row["issue"]) + (f".{row['unit']}" if row.get("unit") else "")


def unit_status(work_root: Path, key: str) -> tuple[str, dict]:
    work = work_root / key
    if (work / "report.json").exists():
        data = json.loads((work / "report.json").read_text(encoding="utf-8"))
        return str(data.get("status", "UNKNOWN")), data
    return ("RUNNING" if work.exists() else "NOT_STARTED"), {}


def rollout_rows(specs_dir: Path) -> list[dict]:
    return [r for r in json.loads((specs_dir / "summary.json").read_text(encoding="utf-8"))["rows"] if "error" not in r]


def rollout_status(specs_dir: Path, work_root: Path) -> dict:
    """Where every unit stands, from the reports the workers left in their work directories."""
    units, counts = [], {}
    for row in rollout_rows(specs_dir):
        state, report = unit_status(work_root, unit_key(row))
        counts[state] = counts.get(state, 0) + 1
        units.append({"unit": unit_key(row), "language": row["language"], "precision": row["precision"], "state": state,
                      "branch": report.get("branch"), "commit": (report.get("commit") or "")[:10]})
    return {"counts": dict(sorted(counts.items())), "units": units}


def next_batch(specs_dir: Path, work_root: Path, corpus_root: Path | None, size: int, languages: list[str],
               allow: list[str]) -> list[dict]:
    """The next units to start: highest precision first, clean ones first, queries before model rows."""
    pool = []
    for row in rollout_rows(specs_dir):
        if unit_status(work_root, unit_key(row))[0] != "NOT_STARTED":
            continue
        if set(row["warning_kinds"]) & (BLOCKING_WARNINGS - set(allow)):
            continue
        if languages and row["language"] not in languages:
            continue
        if corpus_root and row["queries"] and not (corpus_root / row["language"] / "READY").exists():
            continue
        pool.append(row)
    pool.sort(key=lambda r: (PRECISION_RANK.get(r["precision"], 9), bool(r["warning_kinds"]), not r["queries"],
                             r["language"], r["issue"]))
    return pool[:size]


def extra_deny_names(names: list[str] | None = None) -> list[str]:
    """Names that must not reach Community Packs text and are not public: CCP_EXTRA_DENY and any flags."""
    env = [w.strip() for w in re.split(r"[,;\n]", os.environ.get("CCP_EXTRA_DENY", "")) if w.strip()]
    return env + [w for w in (names or []) if w]


def deny_words(apps: list[str], extra: list[str] | None = None) -> list[str]:
    words = {app.lower() for app in apps}
    for app in apps:
        words.update(t for t in re.split(r"[-_. ]+", app.lower()) if len(t) >= 5 and t not in GENERIC_APP_WORDS)
    return sorted(words) + COMMON_DENY + extra_deny_names(extra)


def prepare_unit(spec_path: Path, ccp: Path, wt_root: Path, work_root: Path, stubs: Path | None,
                 deny_source: Path | None, extra_deny: list[str] | None = None) -> dict:
    """Create the worktree, the stubs junction, the work directory and the deny list for one unit."""
    key = spec_path.name.removesuffix(".spec.json")
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    wt, work = wt_root / key, work_root / key
    if wt.exists():
        raise SystemExit(f"{wt} already exists")
    git_bytes(ccp, "worktree", "add", "-q", "-b", f"wip/{key}", str(wt), "origin/main")
    if stubs and sys.platform == "win32":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(wt / "codeql"), str(stubs)], capture_output=True, check=True)
    elif stubs:
        (wt / "codeql").symlink_to(stubs, target_is_directory=True)
    work.mkdir(parents=True, exist_ok=True)
    apps: list[str] = []
    if deny_source:
        apps = json.loads(deny_source.read_text(encoding="utf-8")).get(str(spec["pr"]), {}).get("apps", [])
    (work / "deny.txt").write_text("\n".join(deny_words(apps, extra_deny)) + "\n", encoding="utf-8")
    return {"unit": key, "worktree": str(wt), "work": str(work), "branch": f"wip/{key}", "pr": spec["pr"],
            "language": spec["language"], "apps": apps}


def commit_unit(ccp: Path, base: str, specs: list[dict], message: Path, include: list[str], amend: bool = False) -> dict:
    """Stage exactly what the unit changes and commit it, unsigned (the human signs when publishing is approved).

    The files are the ones `changed_paths` lists, so what a local test run generated stays out. An untracked
    `Cargo.lock` is also left out unless a spec supplies it or `include` names it: `codeql test run`
    generates one when the template had none.
    """
    branch = git_bytes(ccp, "branch", "--show-current").decode().strip()
    if branch in ("", "main", "master"):
        raise SystemExit(f"refusing to commit on {branch or 'a detached HEAD'}")
    provided = {f"{t['target']}/{item['rel']}" for spec in specs for t in spec["tests"] for item in t["files"]}
    fresh = set(untracked_paths(ccp))
    stage: list[str] = []
    left_out: list[str] = []
    for rel in changed_paths(ccp, base):
        if PurePosixPath(rel).name == "Cargo.lock" and rel in fresh and rel not in provided and rel not in include:
            left_out.append(rel)
        else:
            stage.append(rel)
    if not stage:
        raise SystemExit("nothing to commit")
    git_bytes(ccp, "add", "-A", "--", *stage)
    git_bytes(ccp, "-c", "commit.gpgsign=false", "commit", "-q", "-F", str(message), *(["--amend"] if amend else []))
    return {"branch": branch, "commit": git_bytes(ccp, "rev-parse", "HEAD").decode().strip(), "files": stage, "left_out": left_out}


# -------------------------------------------------------------------------- CLI


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    plan_p = sub.add_parser("plan", help="write a migration spec for a template pull request")
    plan_p.add_argument("pr", type=int)
    plan_p.add_argument("--template", type=Path, required=True)
    plan_p.add_argument("--ccp", type=Path, help="Community Packs checkout, used for the base ref")
    plan_p.add_argument("--base", default="origin/main", help="template base ref the pull request is compared with")
    plan_p.add_argument("--triage", type=Path, help="triage json (precision, experimental, destination)")
    plan_p.add_argument("--precision", choices=PRECISIONS)
    plan_p.add_argument("--experimental", action=argparse.BooleanOptionalAction, default=None)
    plan_p.add_argument("--placement", choices=GROUPS, default="security")
    plan_p.add_argument("--cwe", help="CWE-NNN, when the query has no external/cwe tag or this is a model-only change")
    plan_p.add_argument("--id-name", help="kebab-case name for the @id of a single-query pull request")
    plan_p.add_argument("--replace", action="append", default=[], metavar="OLD=NEW",
                        help="neutralize an app-specific identifier in every copied file; repeatable")
    plan_p.add_argument("--only", action="append", default=[], metavar="NAME",
                        help="plan one unit of a bundle: keep files with this path segment (a query or test "
                             "directory, a model file name, or a template language); repeatable")
    plan_p.add_argument("--test-name", help="directory name for the test of a model-only unit (default: the model file name)")
    plan_p.add_argument("--copy-tests", action="store_true",
                        help="copy the template tests of a model-only unit (default: they are references only)")
    plan_p.add_argument("--out", type=Path, help="write the spec here")

    plan_all_p = sub.add_parser("plan-all", help="plan every triaged pull request for one destination, split into units")
    plan_all_p.add_argument("--template", type=Path, required=True)
    plan_all_p.add_argument("--triage", type=Path, required=True)
    plan_all_p.add_argument("--base", default="origin/main")
    plan_all_p.add_argument("--destination", default="community-packs")
    plan_all_p.add_argument("--out-dir", type=Path, required=True,
                            help="one <issue>.spec.json (or <issue>.<unit>.spec.json) each, plus summary.json")

    apply_p = sub.add_parser("apply", help="execute a spec in a Community Packs checkout")
    apply_p.add_argument("--spec", type=Path, required=True)
    apply_p.add_argument("--template", type=Path, help="template repo clone (defaults to the one in the spec)")
    apply_p.add_argument("--ccp", type=Path, required=True)
    apply_p.add_argument("--codeql", type=Path)
    apply_p.add_argument("--bump", choices=("minor", "patch", "none"), default="none",
                         help="change the pack versions (default none: a release sets every version)")
    apply_p.add_argument("--force", action="store_true", help="overwrite files that already exist")

    check_p = sub.add_parser("check", help="run the Community Packs rules plus format, compile and test, with the user CodeQL config hidden")
    check_p.add_argument("--spec", type=Path, required=True)
    check_p.add_argument("--ccp", type=Path, required=True)
    check_p.add_argument("--codeql", type=Path, required=True)
    check_p.add_argument("--deny-file", type=Path, help="one word per line that must not appear (app names, repo names)")
    check_p.add_argument("--deny", action="append", default=[], help="a word that must not appear; repeatable")
    check_p.add_argument("--learn", action="store_true", help="accept the current test output as .expected")
    check_p.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    check_p.add_argument("--base", default="origin/main", help="the ref the unit is compared with")
    check_p.add_argument("--skip-tests", action="store_true",
                         help="do not run codeql test run (for crates that are slow to build locally, CI runs them); "
                              "the report has tests_run false and the packet must say so")
    check_p.add_argument("--allow-lock", action="append", default=[], metavar="PATH",
                         help="a lock file that the unit changes on purpose, for example for a new test pack dependency "
                              "(repeatable); it is kept, not a finding, and the gates put it back if pack install rewrites it")
    check_p.add_argument("--allow-unselected", action="store_true",
                         help="accept a query that the suite for its group does not select (it then runs in no config unless "
                              "someone names it); the packet must say so")
    check_p.add_argument("--allow-config-gap", metavar="NOTE",
                         help="accept a missing pack line in a config or a missing suite, for a reason the maintainers decided; "
                              "the note goes into the report and the packet")

    measure_p = sub.add_parser("measure", help="run the queries on a real database, profile them and keep the rows")
    measure_p.add_argument("--spec", type=Path, required=True)
    measure_p.add_argument("--ccp", type=Path, required=True)
    measure_p.add_argument("--codeql", type=Path, required=True)
    measure_p.add_argument("--db", type=Path, required=True, help="database of a public corpus for the query's language")
    measure_p.add_argument("--out", type=Path, required=True, help="directory for the log, results and rows")
    measure_p.add_argument("--timeout", type=int, default=900, help="seconds for one evaluation layer (the CLI's --timeout)")
    measure_p.add_argument("--max-wall", type=int, default=7200, help="seconds for the whole evaluation, then it is killed")
    measure_p.add_argument("--budget", type=float, default=60.0,
                           help="seconds the query's own predicates may take, library cost excluded")
    measure_p.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    measure_p.add_argument("--slots", type=int, default=DEFAULT_SLOTS, help="heavy evaluations allowed at once on this machine")
    measure_p.add_argument("--tuple-counting", action="store_true",
                           help="count tuples to find cartesian products (changes the evaluation and is much slower)")
    measure_p.add_argument("--blowup-tuples", type=int, default=1_000_000,
                           help="with --tuple-counting, a cartesian product this large in the query's own predicates fails")

    commit_p = sub.add_parser("commit", help="stage exactly the unit's files and commit them, unsigned")
    commit_p.add_argument("--spec", type=Path, action="append", default=[],
                          help="a unit spec; repeatable for the units of one pull request (it names the test files a template supplied)")
    commit_p.add_argument("--ccp", type=Path, required=True)
    commit_p.add_argument("--message-file", type=Path, required=True, help="the commit message, with the trailers the environment requires")
    commit_p.add_argument("--base", default="origin/main")
    commit_p.add_argument("--include", action="append", default=[], metavar="PATH",
                          help="an untracked Cargo.lock that no spec supplies but belongs to the change; repeatable")
    commit_p.add_argument("--amend", action="store_true", help="amend the last commit instead of adding one")

    scan_p = sub.add_parser("scan", help="the last gate before publishing: commits, branch, changed files and the pull request text")
    scan_p.add_argument("--ccp", type=Path, required=True)
    scan_p.add_argument("--base", default="origin/main")
    scan_p.add_argument("--deny-file", type=Path)
    scan_p.add_argument("--deny", action="append", default=[])
    scan_p.add_argument("--pr-body", type=Path, help="the drafted pull request text")

    baseline_p = sub.add_parser("baseline", help="CI's strict compile of whole languages, on the checkout as it is")
    baseline_p.add_argument("--ccp", type=Path, required=True)
    baseline_p.add_argument("--codeql", type=Path, required=True)
    baseline_p.add_argument("--language", action="append", default=[], help="repeatable; default: all packs")
    baseline_p.add_argument("--out", type=Path, required=True)
    baseline_p.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    baseline_p.add_argument("--slots", type=int, default=DEFAULT_SLOTS)

    def rollout(p: argparse.ArgumentParser) -> None:
        p.add_argument("--specs-dir", type=Path, required=True, help="plan-all output with summary.json")
        p.add_argument("--work-root", type=Path, required=True, help="one directory per unit, holding report.json")

    status_p = sub.add_parser("status", help="where every unit stands, from the workers' reports")
    rollout(status_p)

    batch_p = sub.add_parser("next-batch", help="the next units to start")
    rollout(batch_p)
    batch_p.add_argument("--size", type=int, default=6)
    batch_p.add_argument("--language", action="append", default=[], help="restrict to a pack language; repeatable")
    batch_p.add_argument("--corpus-root", type=Path, help="only languages with <root>/<lang>/READY (query units)")
    batch_p.add_argument("--allow", action="append", default=[], choices=sorted(BLOCKING_WARNINGS),
                         help="start units that carry this otherwise blocking warning")

    prepare_p = sub.add_parser("prepare", help="worktree, stubs junction, work directory and deny list for units")
    prepare_p.add_argument("--spec", type=Path, action="append", required=True, help="a unit spec; repeatable")
    prepare_p.add_argument("--ccp", type=Path, required=True, help="the main Community Packs checkout")
    prepare_p.add_argument("--wt-root", type=Path, required=True)
    prepare_p.add_argument("--work-root", type=Path, required=True)
    prepare_p.add_argument("--stubs", type=Path, help="sparse github/codeql clone to junction as <worktree>/codeql")
    prepare_p.add_argument("--deny-source", type=Path, help="json of pull request number to apps (deny-by-pr.json)")
    prepare_p.add_argument("--extra-deny", action="append", default=[], metavar="NAME",
                           help="a name that must not appear in the unit's text (internal repositories, customers); "
                                "repeatable, and the CCP_EXTRA_DENY environment variable adds to it")

    args = parser.parse_args()
    if args.command == "status":
        print(json.dumps(rollout_status(args.specs_dir, args.work_root), indent=2))
        return 0
    if args.command == "next-batch":
        batch = next_batch(args.specs_dir, args.work_root, args.corpus_root, args.size, args.language, args.allow)
        print(json.dumps([{"unit": unit_key(r), "spec": r["spec"], "language": r["language"], "precision": r["precision"],
                           "queries": r["queries"], "models": r["models"], "warnings": r["warning_kinds"]} for r in batch],
                         indent=2))
        return 0
    if args.command == "prepare":
        print(json.dumps([prepare_unit(s, args.ccp, args.wt_root, args.work_root, args.stubs, args.deny_source,
                                       args.extra_deny) for s in args.spec], indent=2))
        return 0
    if args.command == "plan-all":
        report = plan_all(args.template, args.triage, args.base, args.out_dir, args.destination)
        (args.out_dir / "summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps({k: v for k, v in report.items() if k != "rows"}, indent=2))
        return 0
    if args.command == "plan":
        triage = load_triage(args.triage, args.pr)
        spec = build_plan(args.template, args.pr, args.base, triage, args)
        spec["template"] = str(args.template)
        if args.ccp:
            spec["ccp_base"] = "origin/main"
        text = json.dumps(spec, indent=2)
        if args.out:
            args.out.write_text(text + "\n", encoding="utf-8")
        print(text)
        return 0

    if args.command == "scan":
        deny = list(args.deny) + (args.deny_file.read_text(encoding="utf-8").split() if args.deny_file else []) + extra_deny_names()
        report = scan(args.ccp, args.base, deny, args.pr_body)
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 1
    if args.command == "commit":
        specs = [json.loads(p.read_text(encoding="utf-8")) for p in args.spec]
        print(json.dumps(commit_unit(args.ccp, args.base, specs, args.message_file, args.include, args.amend), indent=2))
        return 0
    if args.command == "baseline":
        report = baseline(args.ccp, args.codeql, args.language or list(PACK_LANGUAGES), args.out, args.threads, args.slots)
        print(json.dumps(report, indent=2))
        return 0 if all(r["ok"] for r in report.values()) else 1

    spec = json.loads(args.spec.read_text(encoding="utf-8"))
    if args.command == "apply":
        template = args.template or Path(spec["template"])
        report = apply_plan(spec, template, args.ccp, args.codeql, args.bump, args.bump != "none", args.force)
        print(json.dumps(report, indent=2))
        return 0
    if args.command == "measure":
        args.out.mkdir(parents=True, exist_ok=True)
        report = measure(spec, args.ccp, args.codeql, args.db, args.out, args.timeout, args.budget, args.blowup_tuples,
                         args.threads, args.max_wall, args.tuple_counting, args.slots)
        (args.out / "measure.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] in (True, None) else 1
    deny = list(args.deny) + (args.deny_file.read_text(encoding="utf-8").split() if args.deny_file else []) + extra_deny_names()
    report = run_checks(spec, args.ccp, args.codeql, deny, args.learn, args.threads, args.base, not args.skip_tests,
                        args.allow_lock, args.allow_unselected, args.allow_config_gap)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
