# Worker brief: migrate one template fix into a local Community Packs branch

You are a worker. You migrate exactly **one** tracker issue (one template pull
request) into a **local** branch of a CodeQL Community Packs (CCP) worktree and leave a
reviewable packet for the human. You never publish anything.

Read [`migration-guide.md`](./migration-guide.md) completely
before you start. It is the contract: layout, ids, metadata, tests, the quality
bar, disclosure, and what a packet contains. This brief only adds the operating
rules for a worker.

## Hard rules

1. **No public or remote write, of any kind.** No `git push`, no `gh pr`, `gh issue`,
   `gh api -X POST|PATCH|PUT|DELETE`, no comments, labels, forks or reviews. Read
   only `gh api` and `gh search` calls are fine. Do not touch the template repo
   or its pull request.
2. Work only in your own worktree (`<wt>`) and your own work directory (`<work>`).
   Never touch another worktree, the main CCP checkout, the shared corpora
   (read only), or the skill's `scripts/` and `references/`. If the
   script has a bug, work around it by hand in your worktree and report the bug.
3. Never kill processes by name. Other sessions may run `codeql` and `java` on the same
   machine. Use
   `Stop-Process -Id <your own pid>` only for processes you started.
4. Run `codeql` only through the scripts where they cover the step. When you run
   it by hand, run one command at a time with `--threads=4`, and **with the user
   config hidden**: `$env:CODEQL_CONFIG_FILE='<an empty config file>'`
   (do not override `HOME` or `USERPROFILE`, which breaks the Python extractor).
   A user config that enables every threat model, which CI does not, changes the
   results of `codeql test run` and `codeql query run`. `check`, `measure` and
   `baseline` already do this.
5. Commit locally, once, unsigned: `git -c commit.gpgsign=false commit`. The
   message is neutral (see Disclosure in the guide) and carries only the trailers your
   environment requires.
6. Public text (code, comments, help, fixtures, test names, commit message,
   branch name, PR body draft) never mentions the template repo, its issues or
   pull requests, the tracker, any internal repository, any customer, or the
   synthetic applications. Replace their identifiers at plan time (`--replace`)
   and let `check` and `scan` deny them (`--deny-file <work>\deny.txt`). Names that
   are not public come from `CCP_EXTRA_DENY`, which every gate applies.
7. No em dashes and no en dashes anywhere in text you write. Use commas, periods
   or parentheses.
8. Use the real, current files. Do not rely on the triage text where it can be
   checked: read the template pull request's files and test the claim.
9. **Time budget.** A unit should take 1 to 2 hours of your time. Do not build a
   corpus yourself (the shared ones are `<corpus-root>/<lang>`), and build a
   targeted database only when your tier asks for a true positive, with at most 3
   repositories and at most 45 minutes of build time. If a step runs past its
   budget, stop it, say so in the packet, and carry on with what you have. Start
   `measure` early (it waits for a slot) and write the packet while it runs.

## Inputs you are given

- Issue number, template pull request number, language, the triage entry key and
  the **tier** (1: assessed precision high or very-high; 2: the rest, see the
  guide's evidence tiers).
- `<wt>`: your CCP worktree (created by `prepare`, on a temporary branch `wip/<unit>`,
  with the `codeql` stubs junction in place).
- `<work>`: your work directory, with `deny.txt` (names that must not appear
  anywhere) already in it. Keep the spec, reports and packet there.
- Paths: template clone, triage json, CLI, `scripts/community_packs_migrate.py`,
  `scripts/community_packs_corpus.py`, the corpus for your language
  (`<corpus-root>/<lang>`, read only, built by the coordinator).
- A pilot to copy the format from: the body of
  [GitHubSecurityLab/CodeQL-Community-Packs#253](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/253)
  (the public draft). The local packet follows the list in the guide's Human gate section.

## What the scripts already do (do not redo it by hand)

`apply` drops `postprocess:` lines from `.qlref` files (re-learn `.expected` and
read the diff), renames every file that carries the query name, applies
`--replace` to file names and text in every casing, converts Markdown help to
`.qhelp` for C# and Java, sets the audit metadata for an audit query
(`--placement audit`), and keeps the line endings of `qlpack.yml`. `check` runs
the CI commands with the user config hidden, compares formatting on LF content, compiles the
test queries strictly, renders the help, scans every changed file for denied
names, reports which suites select the query, and fails a query that the suite for its group does not
select or a language pack that the configs do not name. `measure` is plain and capped,
and judges only the query's own predicates. If one of them is wrong, report a
script bug.

## Steps

1. **Understand.** Read the triage entry (assessed precision, readiness items,
   split note, overlaps) and the template pull request's files. Decide go or
   no-go with section 1 of the guide. If it is a no-go, stop with `BLOCKED` and
   the reason. Do not improvise around a no-go.
2. **Plan.** Run `plan` with `--triage`, `--cwe`, `--id-name`, `--precision`,
   `--placement` and `--replace OLD=NEW` flags and write the spec to
   `<work>\spec.json`. Do not hand edit the spec: change a flag and plan again.
   The id name describes the weakness (never the gap key). Read every warning.
3. **Apply once** on the clean worktree. Then hand edit.
4. **Hand edit.** For every readiness item in the triage, either resolve it in
   the code, the tests or the help, or accept it with a reason, or stop with
   `BLOCKED`. Write one line per item in the packet. In addition:
   - Neutral fixture names, no app vocabulary.
   - A negative test for every false positive class you find.
   - Query help states what it cannot decide ("Known limitations").
   - Read the final `.expected` diff before you learn it. Never commit `.actual`.
5. **Gate 1.** `check --deny-file <work>\deny.txt` must pass. Fix what it reports.
6. **Gate 2 (queries).** The corpus is ready when `<corpus>\READY` exists (poll
   every 2 minutes for up to 45 minutes, and do other steps meanwhile). Run
   `measure` on it (`--out <work>\measure`). Read the top predicates even when it
   passes. If it fails because the query's own predicates are slow, fix the query
   (see the performance notes in the guide) and measure again; use
   `--tuple-counting` only to find the cause. Copy the `cost_class` and its notes into
   the packet. When it is not `low`, follow the guide's Performance risk steps (fix,
   narrow, audit only if it is audit-grade, a suite change for the maintainers, or
   withhold) and stop with `NEEDS_DECISION` rather than choose a suite change or a
   withdrawal yourself. Classify **every** row on the corpus
   as true positive, false positive or unclear, fix systematic false positive
   classes, and add negative tests for them. A model-only unit has no query to
   measure: follow the guide's Gate 2 for model-only units.
7. **Evidence.** Tier 1: find at least one true positive on a real public project,
   first in the shared corpus rows, then (only if none) in one small targeted
   database (`community_packs_corpus.py targeted --repo owner/name@sha`, at most 3
   repositories, at most 45 minutes of build time). Prefer a revision where the bug
   is already fixed, an archived project, or a deliberately vulnerable one, and use
   `links` for permalinks. Tier 2: the classified corpus rows are the evidence; if
   there is no true positive, write "no true positive found in <N> repositories".
   Keep permalinks in the local packet. Never cite a live unpatched vulnerability
   or a live leak, and never paste a secret.
8. **Suites and configs.** `check` reports which suites select the query and fails when the suite for its
   group does not (`<lang>.qls` for a security query, `<lang>-audit.qls` for an audit query), when the
   language pack is not named in `configs/default.yml` and `configs/synthetics.yml` (or the ext pack in
   `synthetics.yml`, for model rows), or when an audit query has no audit suite. Fix it with
   `python scripts/community_packs_onboard.py --ccp <wt> --language <lang> --apply`, which adds the pack
   lines and creates the missing audit suite, then run `check` again. Do not change what an existing suite
   selects: that is a maintainer decision (`NEEDS_DECISION`). The `audit.yml` line and the lines of a pack
   that was never published are listed as `after_release` in the report: do not add them, copy them into the
   packet, because a config line that names something the latest release lacks breaks every scan.
9. **Finish.** Rename the branch to `<lang>/<id-name>` with `git branch -m`.
   Make one commit. Run `check` again on the committed tree, then `scan --ccp <wt>
--deny-file <work>\deny.txt --pr-body <work>\pr-body.md`, which must have no
   `fail`. Write `<work>\packet.md` (local only), `<work>\pr-body.md` (the public
   draft) and `<work>\report.json`.

## Decision rules (defaults, from the guide)

- `@precision` is the assessed precision from the triage. A query you had to
  weaken stays at the lower value.
- Tag `experimental` for everything the tracker labels `tags:experimental`
  (every item sent to CCP).
- Security-grade goes to `src/security/CWE-NNN/`. Audit-grade only when the query
  cannot claim reachability (guide section 4). Say which and why.
- One branch per unit (a query with its help and tests, or the model files with
  the tests no query owns). The unit you are given is named in its spec
  (`<issue>.<unit>.spec.json`); plan it with `--only` tokens from the spec's
  `only` list. Queries that share a template directory stay together; you may
  split them by hand with `--only <file name>` when they are independent.
- A copy of a stock query is not acceptable. Extend the stock library, or give the
  variant its own id and a documented reason, or stop with `NEEDS_DECISION`.
- Model rows for a language without an ext pack: do not create a pack. Stop with
  `BLOCKED` and say which options the guide lists.
- Never raise `@precision` to reach a suite.

## Report

`<work>\report.json`:

```json
{
  "issue": 0,
  "pr": 0,
  "unit": "",
  "tier": 1,
  "status": "READY_FOR_REVIEW | BLOCKED | NEEDS_DECISION",
  "branch": "",
  "commit": "",
  "files": 0,
  "id": "",
  "precision": "",
  "placement": "",
  "check": { "ok": true },
  "scan": { "ok": true, "warnings": 0 },
  "measure": {
    "ok": true,
    "cost_class": "low | moderate | high",
    "own_s": 0,
    "wall_s": 0,
    "rows": 0,
    "tp": 0,
    "fp": 0,
    "unclear": 0
  },
  "readiness": [{ "item": "", "status": "resolved | accepted | blocked", "how": "" }],
  "suite": { "selected_by_default": true, "audit_suite_added": false },
  "configs": { "added": [], "after_release": [] },
  "timeline": [{ "step": "plan", "minutes": 0 }],
  "script_bugs": [],
  "decisions_needed": []
}
```

`timeline` is the minutes you spent on each step, including waiting for the
machine, so the coordinator can see where the time goes. Your final message is at
most 200 words: status, branch and commit, gate results, measure numbers, the
evidence (without a live victim), open decisions, and script bugs. The packet
holds the detail.
