---
name: community-packs-migration
description: Move a gap-issue query or data extension model from a Copilot pull request in this repository into GitHubSecurityLab/CodeQL-Community-Packs as a neutral, tested, reviewable pull request, then verify that the released query detects the original finding. Use when asked to migrate, port, upstream or contribute a gap issue to Community Packs, to check or measure a Community Packs unit, to run the Copilot code review loop on such a pull request, to update the tracker after one merges, or to verify and count detections after a release. Runs in a local, human-gated session. Do not use it from the cloud agent.
---

# Community Packs migration

A gap issue in this repository has a Copilot draft pull request with a prototype query or model
rows. When the triage says the destination is
[Community Packs](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs) (CP), this skill turns
the prototype into a CP pull request that stands on its own, and afterwards checks that the released
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
   identifiers at plan time (`--replace OLD=NEW`) and deny them at check time. Set `CPM_EXTRA_DENY`
   (comma separated) to the names that are not public; every gate applies it.
3. **Never change a pack `version:`.** A release sets every version, and merging never publishes.
   `check` fails on it. (CP's `CONTRIBUTING.md` still lists a version bump in its checklist. This
   skill does not follow that line.)
4. **One pull request per gap issue**, opened as a draft. Experimental queries stay in the default
   suite (do not edit suites). `@precision` is the assessed value from the triage, never the
   prototype's.
5. **Hide the user CodeQL config for every local gate** (`CODEQL_CONFIG_FILE` pointing at an empty
   file; the scripts do it). Use the CLI version in `.codeqlversion` of CP.
6. **Read Copilot code review in full.** Findings in unchanged code appear only in the review body,
   with no thread. Reply once to each, fix the real ones test first, and stop when a review lists
   nothing open.

## Setup, once

- `gh` signed in, the `codeql` CLI at the version in CP's `.codeqlversion`, Python 3.
- A clone of CP (fetch `origin/main`), and a sparse clone of `github/codeql` for stubs
  ([guide](references/migration-guide.md), Tooling).
- A clone of this repository with the pull request heads fetched, because `plan` reads them from
  `refs/prs/*`: `git fetch origin '+refs/pull/*/head:refs/prs/*'`.
- Short paths outside every repository for `<work-root>`, `<wt-root>`, `<corpus-root>`, `<stubs>`.

## Workflow

| Step | Do | Details |
| --- | --- | --- |
| 1. Read | The gap issue (labels `precision:*`, `tags:experimental`, the CWE, and the triage comment that starts with `<!-- upstream-triage -->`) and its pull request. Go or no-go. | Guide, section 1 |
| 2. Plan | `plan <pr> --template <clone> --triage ... --replace OLD=NEW` (or the flags `--precision --experimental --placement --cwe --id-name` when there is no triage file) | Guide, sections 2 to 5 |
| 3. Port | `prepare`, then `apply`, then hand edits: readiness items, neutral fixtures, negative tests | Guide, section 6 |
| 4. Gate 1 | `check`: CP rules, format, strict compile, tests | Guide, section 7 |
| 5. Gate 2 | `measure` on a real corpus (`community_packs_corpus.py`), classify every row | Guide, section 7 |
| 6. Packet | The evidence and the drafted pull request text; `scan` must have no `fail` | Guide, Human gate |
| 7. Publish | Human approves, then sign, push the branch, `gh pr create --draft` | Guide, Human gate |
| 8. Review | Copilot code review loop until a review lists nothing open | Guide, Human gate |
| 9. Track | `tracker_action.py set <issue> "<link>" --apply` | Guide, Tracker |
| 10. Verify | After the release: predict locally, enable the language, point the scan at the pack, count | [verify-detection.md](references/verify-detection.md) |

```powershell
python scripts/community_packs_migrate.py plan <pr> --template <clone> --out <work>\spec.json --replace OLD=NEW
python scripts/community_packs_migrate.py prepare --spec <work>\spec.json --cp <cp-checkout> --wt-root <wt-root> --work-root <work-root> --stubs <stubs>
python scripts/community_packs_migrate.py apply --spec <spec> --cp <worktree> --codeql <cli>
python scripts/community_packs_migrate.py check --spec <spec> --cp <worktree> --codeql <cli> --deny-file <work>\deny.txt
python scripts/community_packs_migrate.py measure --spec <spec> --cp <worktree> --codeql <cli> --db <db> --out <work>\measure
python scripts/community_packs_migrate.py scan --cp <worktree> --deny-file <work>\deny.txt --pr-body <work>\pr-body.md
python scripts/tracker_action.py set <issue> "<link>" --apply
python scripts/verify_alerts.py gap --issue <issue> --rule <released query id>
```

`apply` never overwrites, `plan` is deterministic (change a flag and plan again, do not edit the
spec), and `check`, `measure`, `scan` and `baseline` run with the user config hidden. A model-only
unit has no query to measure; the guide says what replaces it. All options: `--help` on each
command.

## Handing a unit to the Copilot coding agent in CP

The agent sees only the repository it runs in, not this one. Write the task yourself, with no name
of this repository, the tracker or a synthetic application: the weakness, what the query must
report and must not, the positive and negative cases as code, the contract in
[the guide](references/migration-guide.md) (ids, metadata, tests, no version change, experimental
tag), and the Copilot review rule above. Then
`gh agent-task create -R GitHubSecurityLab/CodeQL-Community-Packs -F <task.md>`. Review the pull
request as you would your own, and run `scan` against its branch before it leaves draft.

## References

- [references/migration-guide.md](references/migration-guide.md): the contract. Layout, ids,
  metadata, suites, tests, quality bar, disclosure, human gate, tooling.
- [references/worker-brief.md](references/worker-brief.md): the operating rules for one delegated
  worker that migrates a single issue into a local branch.
- [references/verify-detection.md](references/verify-detection.md): after the release, closing the
  loop and counting alerts.
- `scripts/`: `community_packs_migrate.py`, `community_packs_corpus.py`, `tracker_action.py`,
  `verify_alerts.py`, `rule_value.py`, `gap_overlap.py`, `default_setup_languages.py`,
  `enable_workflows.browser.js` (run in a signed-in browser page) and their offline tests
  (`python -m unittest` in that directory).
