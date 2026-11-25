---
name: community-packs-migration
description: Move a gap-issue query or data extension model from a Copilot pull request in this repository into GitHubSecurityLab/CodeQL-Community-Packs as a neutral, tested, reviewable pull request, then verify that the released query detects the original finding and that the scans did not get much slower. Use when asked to migrate, port, upstream or contribute a gap issue to Community Packs, to check or measure a Community Packs unit, to run the Copilot code review loop on such a pull request, to update the tracker after one merges, to check that a language pack and its audit suite are named in the configs and selected by a suite, to verify and count detections after a release, or to compare the code scanning job times before and after a release. Runs in a local, human-gated session. Do not use it from the cloud agent.
---

# Community Packs migration

A gap issue in this repository has a Copilot draft pull request with a prototype query or model
rows. When the triage says the destination is
[CodeQL Community Packs](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs) (CCP), this skill turns
the prototype into a CCP pull request that stands on its own, and afterwards checks that the released
query finds what it was written for.

Develop and test the prototype with the `ql-tdd-agent`. Use this skill once a prototype exists.
Paths are relative to this skill's directory (`.github/skills/community-packs-migration`).

## Do not use it when

- The triage destination is `github/codeql` (a data extension edit or an unambiguous add, or a
  query with very-high precision and no concerns). Raise it there instead.
- The pull request spans more than one language. Split it first (`plan` refuses it).
- You are the Copilot cloud agent. It cannot publish to another repository, and every public
  write below needs a human.

## Rules that cost the most when missed

1. **Nothing public without a human's approval.** No push, pull request, issue, comment or tracker
   edit until the human has reviewed the whole diff and every outbound string. The scripts never do
   it for you.
2. **Public text is neutral.** It never mentions this repository, its issues or pull requests, the
   tracker, any internal repository, any customer or the synthetic applications. Replace their
   identifiers at plan time (`--replace OLD=NEW`) and deny them at check time. Set `CCP_EXTRA_DENY`
   (comma separated) to the names that are not public; every gate applies it.
3. **Never change a pack `version:`.** A release sets every version, and merging never publishes.
   `check` fails on it. (The CCP `CONTRIBUTING.md` still lists a version bump in its checklist. This
   skill does not follow that line.)
4. **One pull request per gap issue**, opened as a draft. Experimental queries stay in the default
   suite: do not change what an existing suite selects. `@precision` is the assessed value from
   the triage, never the prototype's.
5. **A merged query does not run until a config names its pack and a suite selects it.** Adding
   queries does not add the pack to `configs/default.yml` and `configs/synthetics.yml`, and an
   audit query is selected only by `<language>-audit.qls`, which `configs/audit.yml` names after
   the release that carries the suite. This was missed for Actions and again for Rust. `check`
   fails on both, `community_packs_onboard.py` reports every language and fixes them with
   `--apply`, and a config on `main` must not name a suite or pack that the latest release lacks:
   the CLI cannot read it, and a scan that uses that config would fail (`--published` finds those)
   ([guide](references/migration-guide.md), section 4).
6. **Hide the user CodeQL config for every local gate** (`CODEQL_CONFIG_FILE` pointing at an empty
   file; the scripts do it). Use the CLI version in `.codeqlversion` of CCP.
7. **Read Copilot code review in full.** Findings in unchanged code appear only in the review body,
   with no thread. Reply once to each, fix the real ones test first, and stop when a review lists
   nothing open.
8. **Cost is yours to judge.** The pack's CI runs queries only on tiny databases and `experimental`
   does not keep a query out of the default suite, so `measure` is the only performance check.
   Record the cost class it reports. A query that is not `low` needs a decision (fix, narrow, audit
   only when it is audit-grade, a maintainer suite change, or withhold) before it leaves draft
   ([guide](references/migration-guide.md), Performance risk).
9. **Passing tests do not prove detection.** A test database and a scan database can resolve the same
   code differently, and a fixture that imports the same names explicitly elsewhere in the file
   resolves what the real code does not (the Iron prelude, which `check` cannot see). Give a library
   model a fixture with the imports of the real sample and nothing more. After the release, look for
   the alert in the scan, and when it is missing read the call resolution of that database
   (`scripts/scan_database.py`) before blaming the query
   ([verify-detection.md](references/verify-detection.md), section 6). When the calls turn out to have
   no target, the fix is a fallback by name with its own test pattern
   ([guide](references/migration-guide.md), "A fallback for calls that have no target"), and its result
   is checked on that scan database before the pull request opens.

## Setup, once

- `gh` signed in, the `codeql` CLI at the version in the CCP `.codeqlversion`, Python 3.
- A clone of CCP (fetch `origin/main`), and a sparse clone of `github/codeql` for stubs
  ([guide](references/migration-guide.md), Tooling).
- A clone of this repository with the pull request heads fetched, because `plan` reads them from
  `refs/prs/*`: `git fetch origin '+refs/pull/*/head:refs/prs/*'`.
- Short paths outside every repository for `<work-root>`, `<wt-root>`, `<corpus-root>`, `<stubs>`.

## Workflow

| Step       | Do                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Details                                                                |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| 1. Read    | The gap issue (labels `precision:*`, `tags:experimental`, the CWE, and the triage comment that starts with `<!-- upstream-triage -->`) and its pull request. Go or no-go.                                                                                                                                                                                                                                                                                 | Guide, section 1                                                       |
| 2. Plan    | `plan <pr> --template <clone> --triage ... --replace OLD=NEW` (or the flags `--precision --experimental --placement --cwe --id-name` when there is no triage file)                                                                                                                                                                                                                                                                                        | Guide, sections 2 to 5                                                 |
| 3. Port    | `prepare`, then `apply`, then hand edits: readiness items, neutral fixtures, negative tests                                                                                                                                                                                                                                                                                                                                                               | Guide, section 6                                                       |
| 4. Gate 1  | `check`: CCP rules, format, strict compile, tests                                                                                                                                                                                                                                                                                                                                                                                                         | Guide, section 7                                                       |
| 5. Gate 2  | `measure` on a real corpus (`community_packs_corpus.py`), classify every row, record the cost class                                                                                                                                                                                                                                                                                                                                                       | Guide, section 7                                                       |
| 6. Packet  | The evidence and the drafted pull request text; `scan` must have no `fail`                                                                                                                                                                                                                                                                                                                                                                                | Guide, Human gate                                                      |
| 7. Publish | Human approves, then sign, push the branch, `gh pr create --draft`                                                                                                                                                                                                                                                                                                                                                                                        | Guide, Human gate                                                      |
| 8. Review  | Copilot code review loop until a review lists nothing open                                                                                                                                                                                                                                                                                                                                                                                                | Guide, Human gate                                                      |
| 9. Track   | `tracker_action.py set <issue> "<link>" --apply`                                                                                                                                                                                                                                                                                                                                                                                                          | Guide, Tracker                                                         |
| 10. Verify | After the release: run `community_packs_onboard.py --apply --published` on a fresh `main` (a pack or an audit suite that no config names is the usual reason nothing shows up), then predict locally, enable the language, point the scan at the pack, count. A linked alert that is missing although the query ran: read the scan database (`scan_database.py download`, then `calls`; [verify-detection.md](references/verify-detection.md), section 6) | [verify-detection.md](references/verify-detection.md), sections 1 to 6 |
| 11. Time   | Last check, before recording: save the scan times before the release, then confirm that every repository uses the new pack (`packs`), compare the job times before and after (`compare`), and for a pair that got much slower read the logs (`explain`): new queries, other new queries of the release, or something else                                                                                                                                 | [verify-detection.md](references/verify-detection.md), section 7       |

```powershell
python scripts/community_packs_migrate.py plan <pr> --template <clone> --out <work>\spec.json --replace OLD=NEW
python scripts/community_packs_migrate.py prepare --spec <work>\spec.json --ccp <ccp-checkout> --wt-root <wt-root> --work-root <work-root> --stubs <stubs>
python scripts/community_packs_migrate.py apply --spec <spec> --ccp <worktree> --codeql <cli>
python scripts/community_packs_migrate.py check --spec <spec> --ccp <worktree> --codeql <cli> --deny-file <work>\deny.txt
python scripts/community_packs_onboard.py --ccp <worktree> --language <language> [--apply]   # pack lines in the configs, the audit suite
python scripts/community_packs_migrate.py measure --spec <spec> --ccp <worktree> --codeql <cli> --db <db> --out <work>\measure
python scripts/community_packs_migrate.py scan --ccp <worktree> --deny-file <work>\deny.txt --pr-body <work>\pr-body.md
python scripts/tracker_action.py set <issue> "<link>" --apply
python scripts/verify_alerts.py gap --issue <issue> --rule <released query id>
python scripts/scan_database.py download --repo <owner/repo> --language rust --out <work>\scan-db   # the database of the newest scan
python scripts/scan_database.py calls --db <work>\scan-db\db\rust --codeql <cli> --file "%<file>%" --unresolved   # the calls that have no target (Rust)
python scripts/scan_timing.py collect --out <work>\scan-before.json   # before the release, and again after it
python scripts/trigger_scans.py --property Synthetic=true --language <language> --apply   # scan again after the release
python scripts/scan_timing.py packs --jobs <work>\scan-after.json --version <release> --since <published at> --ours <rule id>
python scripts/scan_timing.py compare --jobs <work>\scan-before.json --jobs <work>\scan-after.json --cutoff <published at> --version <release>
python scripts/scan_timing.py explain --jobs <work>\scan-before.json --jobs <work>\scan-after.json --cutoff <published at> --version <release> --ours <rule id>
```

`apply` never overwrites, `plan` is deterministic (change a flag and plan again, do not edit the
spec), and `check`, `measure`, `scan` and `baseline` run with the user config hidden. A model-only
unit has no query to measure; the guide says what replaces it. All options: `--help` on each
command.

## Handing a unit to the Copilot coding agent in CCP

The maintainer asked (2026-11-24) that work for CCP go to the coding agent (CCA) next time rather than be
done locally for hours. Do that when the design is clear: a fix with a failing test, a query with its
cases written down. The agent sees only the repository it runs in, not this one. Write the task yourself,
with no name of this repository, the tracker or a synthetic application: the weakness, what the query must
report and must not, the positive and negative cases as code, the contract in
[the guide](references/migration-guide.md) (ids, metadata, tests, no version change, experimental
tag), and the Copilot review rule above. Then
`gh agent-task create -R GitHubSecurityLab/CodeQL-Community-Packs -F <task.md>`. Review the pull
request as you would your own, and run `scan` against its branch before it leaves draft.

What the agent has and lacks (**checked** 2026-11-24 in its run logs, `gh run view <id> -R
GitHubSecurityLab/CodeQL-Community-Packs --log`, the `GITHUB_COPILOT_MCP_JSON_FROM_INPUT` value decoded from base64):

- It has the pinned CodeQL CLI, the pack dependencies and the `github/codeql` test stubs, which
  `.github/workflows/copilot-setup-steps.yml` installs, so it can run `codeql test run` and
  `codeql query compile`. Its instructions (`.github/copilot-instructions.md`) cover releases and CLI
  bumps, not writing queries, so the task has to carry the query rules.
- **It has no CodeQL Development MCP server.** The MCP configuration of its 2026-11-19 run was only the
  built in Playwright server. The template repository's agent has one (`ql-mcp`: `"type": "local"`,
  `"command": "codeql-development-mcp-server"`, `"tools": ["*"]`), installed by setup steps: Node 26, then
  `npm install --global codeql-development-mcp-server@<version>` and `codeql-development-mcp-server-setup-packs`.
  Giving the CCP agent the same takes a pull request for `copilot-setup-steps.yml` and the MCP configuration
  in the repository settings (an admin, no API). Neither is done. Look again before relying on it.
- It cannot see a scan database, the org that scans, or this repository, so the diagnosis that needs them
  (why a query found nothing live), the tracker, and the check after the release stay local. Give the agent the
  small reproduction and the cases instead.
- A Rust test run takes 3 to 4 minutes wherever it runs (the extractor builds the crate and extracts its
  dependency sources), and the CCP CI runs all of the language's tests when a pull request changes a file that
  is not a query (8 Rust tests took 17 minutes on 2026-11-24). A hand-off does not make either faster, it moves
  the wait to a place where nobody is waiting, so ask the agent for one batch of fixes per review round.

## References

- [references/migration-guide.md](references/migration-guide.md): the contract. Layout, ids,
  metadata, suites, tests, quality bar, disclosure, human gate, tooling.
- [references/worker-brief.md](references/worker-brief.md): the operating rules for one delegated
  worker that migrates a single issue into a local branch.
- [references/verify-detection.md](references/verify-detection.md): after the release, closing the
  loop, counting alerts and timing the scans before and after.
- `scripts/`: `community_packs_migrate.py`, `community_packs_corpus.py`, `community_packs_onboard.py`, `tracker_action.py`,
  `verify_alerts.py`, `scan_database.py`, `scan_timing.py`, `trigger_scans.py`, `rule_value.py`, `gap_overlap.py`, `default_setup_languages.py`,
  `enable_workflows.browser.js` (run in a signed-in browser page) and their offline tests
  (`python -m unittest` in that directory).
