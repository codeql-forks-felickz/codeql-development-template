# Verify the detection after the release

A migrated query is only useful if it finds what it was written for. This step closes the
loop: after a release contains the query, show that the original AI scan finding is now
reported by CodeQL, and count how many alerts the query raises on the synthetic forks.

What is proven and what is still to be proven is marked **Checked** and **Pilot pending**.

## 1. Is the query in a release?

Merging a pull request does not publish (see [the guide](./migration-guide.md), section 2). Wait
for the release, then check the published pack, not the repository:

```powershell
codeql pack download githubsecuritylab/codeql-<lang>-queries@<version> --dir <packs>
codeql resolve queries githubsecuritylab/codeql-<lang>-queries --additional-packs <packs>
```

The second command prints what the pack's default suite selects. The query must be in the list,
because a config that names the pack without a suite runs exactly that.

**Checked** (2026-11-19): `codeql-actions-queries@0.9.1` contains
`githubsecuritylab/actions/encoded-secret-in-log`, and its default suite selects it.

## 2. Predict the live result locally

Before touching any repository, run the released pack on the files that produced the finding.
This gives the result to expect, and it separates "the query does not detect it" from "the scan
did not run".

For an Actions finding no build is needed:

```powershell
gh api repos/<owner>/<repo>/contents/.github/workflows/<file>.yml -H "Accept: application/vnd.github.raw" > <work>\src\.github\workflows\<file>.yml
codeql database create --language=actions --source-root=<work>\src <work>\db
# the baseline: the stock suite that default setup runs (query suite "extended")
codeql database analyze <work>\db codeql/actions-queries:codeql-suites/actions-security-extended.qls --download --format=sarif-latest --output=<work>\stock.sarif
# the released pack, with its default suite
codeql database analyze <work>\db githubsecuritylab/codeql-actions-queries --additional-packs <packs> --format=sarif-latest --output=<work>\pack.sarif
```

Run `codeql` with the user config hidden (`CODEQL_CONFIG_FILE`, see the guide's Tooling section).
For other languages build the database of the whole repository with
`scripts/community_packs_corpus.py targeted --repo owner/name@sha` and analyze it the same way.

The finding is covered when a result of the new rule contains the line of the AI scan alert. An alert is
reported once per script, so its lines can span the whole `run:` block.

**Checked** (issue 230, the DVWA fork, workflow `vulnerable.yml`): the stock extended suite reports three
alerts (two `actions/missing-workflow-permissions`, one `actions/excessive-secrets-exposure`) and none on the
encoded print at line 59. The released pack reports one `githubsecuritylab/actions/encoded-secret-in-log`
alert on lines 39 to 59, which contains line 59. That is the result to expect live.

## 3. Make the repository analyze the language

A query cannot alert on a language that is not analyzed. Read the default setup of each repository:

```powershell
gh api repos/<owner>/<repo>/code-scanning/default-setup --jq '.languages'
```

**Checked** (2026-11-19): all 61 forks that have the `Synthetic` property set to `true` have default setup
configured, and none of them lists `actions`. No `actions` analysis has ever run on them, so the organization
has no stock `actions/*` alert either. Nothing in section 4 changes that.

The language is added with `PATCH /repos/{owner}/{repo}/code-scanning/default-setup` (repository admin rights,
a settings change that needs the owner's approval). The call replaces the list, so it sends the existing
languages by their canonical names plus the new one, and the current suite and threat model:

```powershell
'{"state":"configured","languages":["actions","javascript-typescript","python"],"query_suite":"extended","threat_model":"remote"}' | gh api -X PATCH repos/<owner>/<repo>/code-scanning/default-setup --input -
```

`scripts/default_setup_languages.py` does this for a whole organization: `plan` reads every repository and writes
a plan, `apply --plan <file>` sends the calls (add `--apply` to write, `--only` or `--property` to limit it),
`revert --plan <file>` puts the earlier languages back from the same file, and `disable-workflows --only <repo>`
(or `--repos-file <file>`, one repository per line) disables the workflows of a repository's own that are still active.

**Checked** (2026-11-19): the call is refused with `422 One or more languages you selected are not present in the
repository` for a fork whose workflow files are on the default branch. For `actions`, "present" means that GitHub
Actions has registered workflows of the repository. A fork starts with the workflows it inherited disabled and not
registered: the workflow list of the DVWA fork shows only GitHub's own dynamic workflows (CodeQL, AI security scan)
and the workflow file is not found by name. Of the 80 repositories of the organization that have workflow files and
a configured default setup, none has a registered workflow of its own, and the two that already analyze `actions`
(one fork with enabled workflows, one repository that is not a fork) have theirs `active`. The language statistics
of the repository (`/languages`) play no part: they list neither YAML nor Actions for any of them.

So the workflows of a fork must be registered before the language can be added. Enable them in the Actions tab
(the button "I understand my workflows, go ahead and enable them"; a repository that is not a fork has a button
"Enable Actions on this repository"). There is no REST API for it, but the button is one web request,
`POST /<owner>/<repo>/actions/enable`, that needs a signed-in browser session. **Checked** (2026-11-19, 79
repositories): the same request works for both buttons when it is sent from a page of the signed-in browser with the
headers `Accept: application/json`, `Content-Type: application/json`, `GitHub-Verified-Fetch: true`,
`X-Requested-With: XMLHttpRequest`, `X-Fetch-Nonce` (the `fetch-nonce` meta tag of that repository's Actions page; it
differs per page, so fetch the page first) and `X-GitHub-Client-Version` (the `release` meta tag). The answer is
`{"message":"Actions Enabled."}`, and the button text is gone from the page afterwards. `scripts/enable_workflows.browser.js`
sends it for a list of repositories. Always confirm through the workflow list of the API, not the page. Then run `plan`
again: the repository moves from "workflows are not enabled" to ready.

**Checked** (the DVWA fork, 2026-11-19): after the workflows were enabled in the Actions tab, the call was accepted
(202) and started a `CodeQL Setup` validation run. About 90 seconds later the default setup listed `actions`, the run
had an `Analyze (actions)` job, and an `/language:actions` analysis with 11 results (the stock extended suite) was
uploaded. The suite, threat model and runner were unchanged.

The workflows that the button makes active run on the fork's events, and some are unsafe in an intentionally
vulnerable application. Disable them one by one: `PUT /repos/{owner}/{repo}/actions/workflows/{id}/disable`
(`gh api -X PUT`). **Checked**: on DVWA the three active workflows became `disabled_manually`, the two others were
already `disabled_fork`, none had run (they fire only on a push to the default branch), and default setup still lists
`actions`. Disabling Actions for the whole repository would also stop default setup, so it is not an option.

**For many repositories** (checked on 79, 2026-11-19): enable a batch from the browser page, and at the same time run
`disable-workflows --repos-file <batch> --apply` in a loop every few seconds. The button makes workflows active within
seconds, some forks inherit dozens, and a pass every few seconds keeps the window in which one could start short.
Sweep the whole list once more at the end, run `plan` again, then `apply --apply`. A workflow that is only
`disabled_fork` already counts as registered, so a fork whose inherited workflows are all `disabled_fork` needs no
disabling. On these 79, no workflow run started.

The PATCH enum does not list Rust: the call is refused with `422 Invalid property /languages/N: rust is not a possible
value` although the GET lists `rust`. For a repository that has Rust, use the form behind the "Edit" link of the
CodeQL default setup (`/<owner>/<repo>/settings/code-scanning/default-setup`). It has a Rust checkbox. Tick only
"GitHub Actions", check what the form would submit (`config[languages][]`, `config[query_suite]`,
`config[runner_type]`, `config[threat_model]`) against the plan, then save. **Checked** on three repositories: a
validation run started, and the stored languages kept Rust, gained `actions` and left the suite, runner and threat
model unchanged.

The stored languages change 1 to 4 seconds after the whole validation run ends, and a run ends with its slowest
job: a compiled language takes minutes, and a very large C codebase took about 45 to 55 minutes in its earlier full
runs. Until then the GET still shows the old list, although the `Analyze (actions)` job is already done. While an update
is pending, the same config returns the same run id, and a different config is refused with
`409 Configuration update already in progress`.

**Seen once** (2026-11-20, 1 of 79): the validation run ended in success and its `/language:actions` analysis and
alerts exist, but the stored languages never gained `actions`. More than an hour later the repository still answered
409 to a different config and the old run id to the same one. Re-sending the config (also with `runner_type` made
explicit, or through the settings form) changed nothing, and the organization audit log shows the same events as for
a repository that worked. The scan did happen, so only the saved list is stale; the next scheduled scan probably
leaves `actions` out. Turning default setup off and on again was not tried: if the re-enable stalled the same way,
the repository would be left with no scanning.

A dynamic default setup run cannot be re-run (HTTP 403). **Checked** (2026-11-20): a push to the default branch of a
repository whose workflows are all disabled started a run that included `Analyze (actions)` and uploaded the
`/language:actions` analysis. **Pilot pending**: the weekly scheduled run. Registering a workflow without the button,
by adding one `workflow_dispatch`-only file to the default branch, has not been tried.

## 4. Point the analysis at the pack

Repository custom properties configure code scanning without editing workflows
([docs](https://docs.github.com/en/enterprise-cloud@latest/code-security/concepts/code-scanning/repository-properties)).
Create the property `github-codeql-config-file` (type Text, no default value) in the organization, and set it
on the repositories you want, one first as a test. **Checked** (2026-11-20): both REST calls,
`PUT /orgs/{org}/properties/schema/github-codeql-config-file` and `PATCH /orgs/{org}/properties/values` (up to 30
repository names per call), answer `404 This API operation needs the "admin:org" scope` to a token that has `repo` and
`read:org` only, and work with `admin:org`. The web form (Organization settings, Custom properties) asks to confirm
access with a passkey before it saves, which only the signed-in person can do.

Its value is a config file address, the same as the `config-file` input of `codeql-action/init`. The CodeQL
Action reads these forms (`src/config/remote-file.ts`):

| Form | Example |
| --- | --- |
| `remote=[OWNER/]REPO[@REF][:PATH]` | `remote=GitHubSecurityLab/CodeQL-Community-Packs@main:configs/default.yml` |
| `OWNER/REPO/PATH@REF` | `GitHubSecurityLab/CodeQL-Community-Packs/configs/default.yml@main` |

Defaults of the first form: `OWNER` is the owner of the analyzed repository, `REF` is `main`, `PATH` is
`.github/codeql-config.yml`. A public repository needs no registry or token. A tag (`@v0.9.1`) pins the file.

**You can point it straight at a Community Packs config. You do not need one of your own**, with these facts:

- **The file is the base.** With default setup the Action merges the two: the config file is used as it is, and
  default setup adds only its threat models and the model packs chosen in the settings
  (`mergeDefaultSetupAndUserConfigs`). Everything else in the file applies, including `packs`,
  `disable-default-queries`, `query-filters` and `paths-ignore`.
- **`configs/default.yml`** adds the Community Packs queries and extensions and filters nothing, so the baseline
  stays as it was. **`configs/synthetics.yml`** is meant for synthetic apps: it turns the default queries off and
  runs every stock, Community Packs and OSS query that is security related, with `threat-models: local`. Expect
  more alerts, more false positives and longer runs, and a different baseline. Both work for counting, because the
  rule id of every Community Packs query starts with `githubsecuritylab/`.
- **`synthetics.yml` ignores paths, and a language with nothing left fails its job.** Its `paths-ignore` skips
  `vendor/**`, `examples/**`, `tests/**`, `test/**`, `site-packages/**`, `node_modules`, `**/wwwroot/lib/**` and
  similar. **Checked** (2026-11-20, 61 repositories): in four of them a language was left with nothing, and its job
  failed with `CodeQL detected code written in X but could not process any of it`. In three of them the only Python
  sat under `tests/` or `test/`. In the fourth the only JavaScript left was an empty template file next to vendored
  libraries, which a file listing does not show, so read the first run of every repository. Take the language out of
  default setup (`default_setup_languages.py remove-language`). The call answers at once with `run_id: 0` and starts no
  scan, so push a commit afterwards. The other jobs of the same run are not affected.
- **The Actions pack was missing, and is now there** (2026-11-19: neither config named it; they named cpp, csharp,
  go, java, javascript, python and ruby queries and some extensions, and `synthetics.yml` named the stock Actions pack
  only). The configs README of Community Packs says to add a new pack to the configs after its first release, and a
  Community Packs pull request did that for `githubsecuritylab/codeql-actions-queries` in both files (merged
  2026-11-20; release v0.9.1 holds the query). **Checked** on `main` that day. Point the property at `@main`: the
  `v0.9.1` tag predates that change, and neither of its configs names the Actions pack (checked). A pack without a
  config entry is not run, so check a pack's presence in the file you point at whenever a new language gets its
  first queries.
- **Own config**: only needed to pin pack versions (`githubsecuritylab/codeql-actions-queries@0.9.1`) or to be
  independent of changes to the Community Packs configs. **Checked locally** (2026-11-19, CLI 2.27.4):
  `codeql database create --codescanning-config=<file>` on an Actions database accepts a plain `packs` list that
  also names Python packs (the shape of the Community Packs configs) and the same packs by language. The Python
  packs are ignored, and the Actions pack runs next to the default queries: four results on the pilot workflow,
  the new rule and the three stock alerts. That is the call the Action makes. **Checked** (2026-11-20, default setup,
  DVWA fork): default setup's own jobs accept the plain list. Each language job installed every pack of the list at
  the newest version (0.9.1), including the packs of other languages, and only the packs that match the job's
  language produced results.
- **Two feature flags decide whether it works.** The Action ignores the property unless
  `ConfigFileRepositoryProperty` is on, and ignores the config file with a warning unless `AllowMergeConfigFiles`
  is on. Both default to off in the Action and are set by GitHub. The log of the `Initialize CodeQL` step says
  which: look for `Using configuration file input from repository property: ...` and make sure that neither
  `Ignoring configuration file input from repository property` nor `Both a config file and config input were
  provided. Ignoring config file.` appears. **Checked** (2026-11-20): the `Initialize CodeQL` step of the
  `Analyze (actions)` job on the DVWA fork logged `Using configuration file input from repository property:
  GitHubSecurityLab/CodeQL-Community-Packs/configs/default.yml@main` and then `Writing augmented user configuration
  file`, so both flags were on there. A job log is readable through the API
  (`gh api repos/<owner>/<repo>/actions/jobs/<job id>/logs`).

**Checked** (2026-11-20, the DVWA fork, `configs/default.yml@main`): the property was created in the organization and
set on that one repository. An empty commit on its default branch started two dynamic runs ("Push on master" for
CodeQL, and "Code Quality: Push on master"), and the CodeQL one ended after about 75 seconds. Result:
`githubsecuritylab/actions/encoded-secret-in-log` (error, CWE-532) on `.github/workflows/vulnerable.yml` lines 39 to
59, which contain the line of the AI scan alert, and `verify_alerts.py gap` says `COVERED`. Four alerts of
`githubsecuritylab/actions/unpinned-tag` (warning, CWE-829) appeared on two other workflow files, in the
`/language:javascript-typescript` category: that rule lives in the Community Packs JavaScript pack
(`javascript/src/security/CWE-829/UnpinnedActionsTag.ql`), which reads the workflow YAML, so it runs in the
JavaScript job and not in the Actions job. The 11 stock `actions/*` alerts stayed.

**Checked** (2026-11-20, rollout of `configs/synthetics.yml@main` to the 61 repositories that have `Synthetic=true`):
the property was set with `PATCH /orgs/{org}/properties/values` in three calls, and an empty commit on each default
branch started 58 scans. Two repositories have no language that default setup supports, and one has none configured.
Of the 58, 56 finished green. The failures were the four cases above, and two long scans (Swift, and a very large C#
suite) were still running when this was written.

## 5. Re-run, then count

Default setup runs on push, on pull requests and on its schedule, and the Action reads the property from the API when
the analysis starts. So the property only takes effect on the next run. A dynamic run cannot be re-run, so wait for
the weekly schedule or push a commit. **Checked** (2026-11-20): a push to the default branch starts the run, and an
empty commit is enough. `gh api` can make one without a clone: read the head commit and its tree, `POST git/commits`
with that tree and the head as parent, then `PATCH git/refs/heads/<branch>`.

```powershell
python scripts/verify_alerts.py gap --issue <gap issue> --rule <rule id>
python scripts/verify_alerts.py count --rule <rule id> --property Synthetic=true --snapshot <history>.jsonl
python scripts/rule_value.py report --org <org> --since <time> --property Synthetic=true
```

`gap` reads the AI scan alerts that the gap issue links and says, for each, `COVERED` (an open alert of the rule
contains its lines), `NOT_COVERED` (the language is analyzed and nothing matches) or `NOT_ANALYZED` (the language has
no CodeQL analysis in that repository, with the categories it does have). It exits 0 only when all are covered.
`count` counts the alerts of the rule in the organization's repositories that have the property value. It takes about
a minute, because the organization endpoint lists every alert. `--snapshot` appends one line per run, so the trend is
kept. `rule_value.py report` answers a different question, which queries found things: it takes the alerts created
since a time, and groups them by pack family, precision and language, and it names the busiest rules of low or no
precision. The alerts API does not return the precision of a rule, so the script reads it from the SARIF of one
analysis per rule.

**Checked** (before any change): for issue 230, `gap` reports `NOT_ANALYZED` for the DVWA alert (categories
`/language:javascript-typescript` and `/language:python` only, property not set). The organization has no open CodeQL
alert of any `githubsecuritylab/*` rule, which is the baseline of zero. **Checked** (after the pilot of section 4): `gap`
reports `COVERED` for the same alert, with the new alert on lines 39 to 59, and the command exits 0.

## 6. Read the result

**Checked** (2026-11-20, the 56 finished scans of the `synthetics.yml` rollout): 3,338 new alerts in 49 repositories,
from 136 rules. Stock CodeQL rules of high precision gave 527 alerts (34 rules), medium 55 (16 rules), low 895
(23 rules) and no declared precision 447 (17 rules). Community Packs rules gave 1,413 and Trail of Bits 1. So the
low-precision and unrated CodeQL queries that `synthetics.yml` adds do find things: 40 rules and 1,342 alerts, about
40% of the new ones, in Java (851), JavaScript and TypeScript (265), Python (110), C and C++ (70), C# (19), Go (17) and
Ruby (10). Only 4% of them are in vendored or minified paths. Low precision means many false positives, so these
numbers say that the queries fire, not that the alerts are right.

A rollout can also make a planned query redundant. `gap_overlap.py report --org <org> --since <time> --planned <file>`
matches the triaged AI findings to the alerts created since a time, by file, lines and CWE, with the rules of the first
AI-versus-CodeQL comparison: exact (lines overlap, same CWE), near (5 lines or less, same CWE or family), possible
(40 lines or less) and same-spot-other-cwe, which is not coverage. **Checked** (2026-11-20, 516 findings with a planned
query, in 117 gap issues): 14 findings in 10 issues are now exact or near duplicates of new alerts and 11 more are
possible. Ten of the 14 come from Community Packs rules and four from stock rules of high or medium precision. None
comes from the low-precision CodeQL queries. Two issues (one finding each) are fully covered. The other 452 findings
have no match, so those queries are still needed.
- `COVERED` for every linked alert: the gap is closed. Say so on the tracker.
- `NOT_ANALYZED`: fix section 3 or 4. The query has not been tested yet.
- `NOT_COVERED` although section 2 predicted a hit: the live scan differs from the local one. Compare the CodeQL
  version (the analysis list shows it), the resolved pack version, and whether the config applied (section 4).
- Alerts that are not the original finding: classify each as true or false positive. A class of false positives is a
  follow-up pull request for the query, with a negative test, as in the guide's quality bar.

## 7. Record it

One batch comment on the tracker issue: the rule, the pack version, the alerts (count and forks), and how many linked
findings are covered. The Action cell may carry a short note (`tracker_action.py set <issue> "..." --apply`).
Keep the `--snapshot` history if the numbers are to be tracked over time.
