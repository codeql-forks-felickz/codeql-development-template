# Verify the detection after the release

A migrated query is only useful if it finds what it was written for. This step closes the
loop: after a release contains the query, show that the original AI scan finding is now
reported by CodeQL, count how many alerts the query raises on the synthetic forks, and
check that the scans did not get much slower.

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
  first queries. **Rust was missed the same way** (2026-11-23: neither config named `githubsecuritylab/codeql-rust-queries`
  or `githubsecuritylab/codeql-rust-extensions`, and the CORS audit query had no suite). A Community Packs pull request
  added the Rust packs to `default.yml`, `synthetics.yml` and `audit.yml`, and `rust-audit.qls`
  (merged 2026-11-24), and `scripts/community_packs_onboard.py` now checks every language, so run it on a fresh
  `origin/main` after each release. **A line that names a suite is safe only after the release that holds the suite**:
  that pull request put `suites/rust-audit.qls` into `audit.yml` while the published `0.9.2` pack has no such file
  (`codeql resolve queries` against the pack fails with `Could not read ...\suites\rust-audit.qls`, checked
  2026-11-24; a scan that uses the config would resolve the same way, not tried). `--published` finds those lines.
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
`scripts/trigger_scans.py` does exactly that, for the repositories that have a property value and, with `--language`,
a default setup that lists the language. It prints the plan and writes nothing until `--apply`; it fast-forwards the
branch and never forces it, so a branch that moved fails that repository only; and it prints the time of the first
commit, which is the cutoff for section 7. **Checked** (2026-11-23): `--property Synthetic=true --language rust` found
the two Rust repositories of the 61 (one lists Actions, C/C++ and Rust, the other Rust only), and `--apply` started
both scans within 10 seconds. Add the trailers that your environment requires with `--trailer "Key: value"`.

```powershell
python scripts/trigger_scans.py --property Synthetic=true --language rust            # the plan
python scripts/trigger_scans.py --property Synthetic=true --language rust --apply    # start the scans
```

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
- `NOT_COVERED` although the query ran (its evaluation is in the job log) and its tests pass: the scan's database may
  not resolve what the query matches, and the fixture may not have the imports of the real code (a default setup scan
  builds the real code with `buildMode: none`). `scripts/scan_database.py download` fetches the database of the newest
  scan of the language (`gh api` has no `--output` and PowerShell redirection corrupts a zip, so the script writes the
  bytes itself), and `calls` lists the calls of the files that match a pattern, each with the canonical path of its
  target or `<unresolved>` (Rust only). A call that has no target is unresolved, and a model or a query that matches
  a canonical path cannot see it. Then run the query on that database with the pack under test and the ext pack as a
  model pack.

  ```powershell
  python scripts/scan_database.py download --repo <owner>/<repo> --language rust --out <work>\scan-db
  python scripts/scan_database.py calls --db <work>\scan-db\db\rust --codeql <cli> --file "%<file>%" --unresolved
  codeql query run --database <work>\scan-db\db\rust --additional-packs <checkout>\rust --model-packs githubsecuritylab/codeql-rust-extensions --output <work>\r.bqrs <query.ql>
  ```

  The first query on a fresh scan database computes the shared libraries and takes minutes (**checked** 2026-11-24:
  3.5 minutes on a database of 60 crates), the next ones take seconds (11 s and 17 s for the Iron query before and
  after its fix), so compare warm runs. Two runs cannot use one database at the same time (the evaluator cache is
  locked: `Error initializing the IMB disk cache`).
- Alerts that are not the original finding: classify each as true or false positive. A class of false positives is a
  follow-up pull request for the query, with a negative test, as in the guide's quality bar.

**Checked** (2026-11-24, the first scan with the Rust packs named in `synthetics.yml`, on the Rust only synthetic
repository; the alerts were matched to the AI scan alerts of the gap issues by file and line). The four Community Packs
Rust rules raised 15 alerts, and nothing else changed (17 open alerts, 2 of them stock and old).

| Gap issue | AI scan alerts | Result |
| --- | --- | --- |
| SSRF through reflection (`ssrf-reflection-injection`) | 2 | 2 of 2, on the same lines. |
| Hard-coded key or passphrase (`hardcoded-cryptographic-key`) | 7 | 7 of 7 covered: 6 by the rule on the same lines and 1 by the stock `rust/hard-coded-cryptographic-value` (an untyped integer array passed to `new_from_slice`), which the test file leaves to the stock query on purpose. The rule also raised 6 alerts on samples that the AI scan did not flag, all in `bad` directories. |
| Key printed to the log (`cleartext-logging-of-key-material`) | 1 | 1 of 1, on the same line (in a `good` sample of the hard-coded key theme, which the AI scan flagged for the log line). |
| Iron response XSS (`iron-response-xss`) and the Iron models | 4 CWE-79 alerts (Iron, warp, a reqwest response, sqlx); the Iron one is the target of the query and the models | **0 of 4.** No CodeQL alert on any of the four lines. See below. |
| CORS (the audit query) | 3 | Not in the scan, by design: it is an audit query, `synthetics.yml` excludes the audit tag, and the audit suite is in the next release. |

**Why the Iron rule found nothing.** The rule ran (it is in the job log), and the same query run locally on the downloaded
database of that scan, with the ext pack as a model pack, finds nothing either. In that database the calls that go through
names from `use iron::prelude::*` have no target: `Iron::new`, `.http`, `Response::with` and `Url::path` (reached through
`req: &mut Request`, whose `Request` comes from the glob). The one Iron sample that also imports `iron::Request` by name
resolves `req.url.query()` to `<iron::request::url::Url>::query`, which is why the SSRF rule alerts on it. The Iron source,
sink and summary models match canonical paths, so none of them applies; the Rust extension pack was installed and, unlike
the C#, Go, Java and Python ones, not reported as unused. All four Iron samples of the synthetic repository use the glob.

**Reproduced locally** (CLI 2.27.5, `--build-mode none`, `iron = "0.6.1"`, edition 2021, a crate of about 10 lines, the
call targets listed with `getStaticTarget().getCanonicalPath()`):

| Imports | Iron calls (`Iron::new`, `.http`, `Response::with`, `.path()`) |
| --- | --- |
| `use iron::prelude::*;` at the crate root, in `main.rs` or in `lib.rs` | no target |
| `use iron::prelude::*;` inside a module, nothing else imported | no target |
| `use iron::prelude::{IronResult, Request, Response};` | no target |
| `use iron::{Iron, IronResult, Request, Response};` | all resolve (`<iron::response::Response>::with`, ...) |
| the same explicit import at the crate root and `use iron::prelude::*;` inside a module | all resolve, in the module too |
| `use std::io::prelude::*;` (control) | resolves (`<& as alloc::io::read::Read>::read_to_string`) |

The crate of the first row (`Cargo.toml` has only `iron = "0.6.1"` under `[dependencies]`, edition 2021):

```rust
use iron::prelude::*;
use iron::status;

fn handler(req: &mut Request) -> IronResult<Response> {
    let res = req.url.path();
    let response = format!("<h1>{:?}</h1>", res);
    Ok(Response::with((status::Ok, response)))
}

pub fn main() {
    Iron::new(handler).http("localhost:3000").unwrap();
}
```

The cause is not determined: both the glob and the by-name import of the prelude fail, the std prelude does not, and the
prelude glob works once the same names are imported explicitly elsewhere in the crate, so what resolves seems to depend
on what else the crate uses. The `iron` crate is edition 2015 (its manifest has no `edition`) and its prelude is
`pub use {Set, Plugin, Chain, Request, Response, IronResult, IronError, Iron};`, which may be relevant; nothing here
confirms it.

**The Community Packs test harness shows the same thing, and the pull request's fixture hides it.** A test directory
with only the root level glob (the shape of the samples) extracts with unresolved calls, and the rule returns no result
there (checked 2026-11-24 with `codeql test run` on a copy of `main`, no `.expected`, the actual result was empty). The
fixture of the pull request has a handler that imports the prelude with a glob inside a module, and that passes because
the same file imports the same names explicitly at its root (the fifth row). So a fixture that proves a library model must
copy the imports of the real code and nothing more.

Options that were open: add the root level glob fixture (it fails first) and a syntactic fallback in the rule for the
unresolved `Iron::new`, `Response::with` and the handler parameter (the way `keyMaterialConversionStep` handles an
unresolved `From`); report the resolution to github/codeql with the 10 line crate; or accept it and say so under
"Known limitations" in the query help.

**Fixed in a pull request** (2026-11-24, [CCP 264](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/264),
draft): the fallback, tested as in the guide's
[A fallback for calls that have no target](./migration-guide.md#a-fallback-for-calls-that-have-no-target). On the
downloaded scan database of the 2026-11-24 scan the released rule reports 0 alerts and the changed rule 3:
the Iron XSS of the gap issue (the sink is the `Response::with` line, one line below the AI alert, so the match is
near and not exact), a second AI alert of the same CWE that no gap issue listed (the same line), and the same flow in
a sample that is safe for another weakness (the body is the text of a response to an outbound request, a remote
source of the standard query, so it is a finding of the rule and not a mistake of the fallback). The sample that
sanitizes the body with `ammonia::clean` reports nothing, because `clean` resolves there and no taint comes out of
its body. The measure on both Rust corpora is `low` (the whole run 11 s and 30 s, own predicates 0.12 s and
0.45 s). The alerts show up live after a release that carries the pull request and a new scan.

## 7. Time the scan, before and after

The last check before recording. A release adds queries to every scan that uses the pack, the pack's CI runs queries
only on tiny databases and has no time limit (the guide's
[Performance risk](./migration-guide.md#performance-risk-and-what-to-do-with-it)), and `measure` ran on public
corpora, not on these repositories. So compare how long the code scanning jobs of the synthetic repositories take
before and after the release. Expect no massive change. When there is one, read the logs to see whether the new
queries caused it, or other queries of the same release, or something that has nothing to do with queries.

`scripts/scan_timing.py` does it with the gh CLI and writes nothing to GitHub:

```powershell
# before the release: save the baseline (Actions keeps runs and their logs for 90 days by default)
python scripts/scan_timing.py collect --out <work>\scan-before.json
# the release is published; its time is
#   gh release view <tag> --repo GitHubSecurityLab/CodeQL-Community-Packs --json publishedAt --jq .publishedAt
# scan every repository again (section 5; --apply prints the time of the first commit), wait for the jobs, then:
python scripts/trigger_scans.py --property Synthetic=true [--language <language>] --apply
python scripts/scan_timing.py collect --out <work>\scan-after.json
python scripts/scan_timing.py packs   --jobs <work>\scan-after.json --version <release> --since <published at> --ours <rule id>
python scripts/scan_timing.py compare --jobs <work>\scan-before.json --jobs <work>\scan-after.json --cutoff <published at> --version <release> --since <last config change>
python scripts/scan_timing.py explain --jobs <work>\scan-before.json --jobs <work>\scan-after.json --cutoff <published at> --version <release> --since <last config change> --ours <rule id>
```

**`packs`: do the repositories use the new pack?** It reads the log of the newest successful job of every
repository and language: the Community Packs version that the job installed and recorded, whether the configuration
file applied, and with `--ours` whether the new query was evaluated and for how long. It exits 1 for every pair that is
not on the version, with the reason: an older version (the configuration pins one, or the scan ran before the pack was
published), no scan since `--since` (not scanned yet: push again), the configuration ignored, or a newest scan that
failed. A language that the repository's default setup no longer has cannot be scanned, so such a pair is listed as
ignored and does not fail the check (the script reads the current default setup for the pairs that are not on the
version). The version is the same for every pack because a release sets them all. A pack that the configuration does
not name is not run (section 4), so for the first release of a language check the `--ours` line as well.

**`compare`: is there a massive change?** For every repository and language it takes the median job time of up to
three jobs before the cutoff and of the first three jobs after it that used the version, and flags a pair that takes
at least 1.5 times as long and at least 60 seconds longer (`--ratio`, `--min-delta`). It needs both limits because
the same job varies from run to run: one small repository took 37, 49 and 47 seconds on three scans with the same
configuration. The job time runs from the start of the job to its end, so waiting for a runner is not in it. Pass
`--since` with the time the configuration last changed, so that the jobs before the release ran with the same
configuration. It exits 1 when a pair is flagged. A scan that was started by an empty commit changes the commit and
not the tree, so the comparison looks at the tree and the number of files scanned to tell whether the code changed.

**`explain`: where did the time go?** For the flagged pairs, or one you name with `--repo` and `--language`, it reads
the log of the newest job before the cutoff and of the first one after it (it downloads a log that the file does not
hold) and prints: the Community Packs version, the CodeQL bundle and the number of packs installed on each side; the
tree and files scanned; the time of each phase (setup is tools, packs and checkout, database is autobuild, extraction
and finalizing, then queries, then results is upload and processing); how many queries ran and how many are new; the
Community Packs queries before and after with their share of the evaluation time; the new and the slower queries with
their evaluation time; and a verdict.

| Verdict | Meaning | What to do |
| --- | --- | --- |
| `new_queries` | The query phase grew and new queries are most of the extra evaluation time. The text says whether they are yours (`--ours`), other new Community Packs queries, or stock queries. | Yours: the guide's ladder (fix, narrow, audit only if it is audit-grade, a maintainer suite change, withhold). Other Community Packs queries: tell the maintainer which ones, it is not the cost of this query. |
| `slower_queries` | Queries that were already there got slower. | Look at the bundle on the first line. A CodeQL upgrade changes the stock queries, which is not the release. A bigger repository does too. |
| `repository` | The database build got longer and the tree or the number of files changed. | The code grew, not the queries. |
| `database_variance` | The database build got longer and nothing changed. | Runner variance. Scan again and compare again. |
| `setup` | Tools, packs and checkout got longer. | More packs in the configuration cost every language job one download each, and the full CodeQL bundle takes longer than a per-language one. Not a query cost. |
| `results` | Uploading and processing the results got longer. | GitHub's side. |
| `spread` | No phase is half of the increase. | Several small changes or runner variance. Scan again and compare again. |

Queries run on several threads and many wait for the same shared computation, so the summed evaluation time of a job
can be many times its query phase. The verdict says **Caution** when it is more than 5 times. Then a long time says
that a query needed the shared computation, not that it is expensive, and the phase time is the figure to judge by.

If nothing is flagged, record "no massive change" with the numbers: pairs compared and the median ratio per language
(section 8). If a pair is flagged and the cause is a new query of yours, the release is not clean: go to the guide's
ladder, and say so on the tracker.

**Checked** (2026-11-23, on the rollout of `synthetics.yml` of section 4: a configuration change, not a release, but the
only before and after that the organization has). `collect` read the 61 repositories in 88 seconds: 545 jobs of 144
repository and language pairs, and the log of the newest successful job of 134 of them (the other 10 never had a
successful scan). `packs --since` the rollout found 129 pairs on `0.9.1` and 15 that default setup no longer has (none
of the 14 that were not scanned again still lists its language, and the 15th is the JavaScript repository whose scan
fails with `could not process any of it`). `compare` across the rollout took 129 pairs. The median ratio per language
was 1.09 (Swift) to 1.55 (C/C++): Java 109 to 129 s, JavaScript and TypeScript 60 to 79 s, Python 48 to 69 s, C# 97 to
119 s, Go 80 to 107 s, Ruby 45 to 69 s and Actions 38 to 56 s. One pair was flagged (a Java repository, 91 to 159 s).
With the limits lowered to 1.3 times and 20 seconds, `explain` read the 25 largest increases: 16 were `setup`, 7
`spread`, 1 `slower_queries` and 1 `new_queries`. The `setup` cause is in the logs: in one repository the bundle that the
action downloaded was a per-language CodeQL bundle (0.9 s) before and the full bundle (3.9 s) after, and the scans with
the file install the 16 packs of the file in every language job. Setup was 19 to 35 seconds longer in those 16 pairs.
The `new_queries` pair was a C# repository with 46,597 files, where the summed evaluation time is 41 times the query
phase and the verdict says so.

The times to compare a release against are the ones after the rollout (the median job): Actions 56 s, C/C++ 104 s, C#
119 s, Go 107 s, Java 129 s, JavaScript and TypeScript 79 s, Python 69 s, Ruby 69 s, Rust 392 s and Swift 859 s.
Where any Community Packs `0.9.1` query ran, they are 0.2% (Go) to 3.2% (Java) of the summed evaluation time of a job
(median per language), and the slowest evaluation of one of them outside that C# repository was 7.2 s. No Community
Packs query ran in any C/C++, Rust or Swift job. Rust has no Community Packs query yet and the file names no Rust
pack, so the first Rust release needs the configuration change of section 4 before `--ours` can show the query.

**Checked** (2026-11-23, the first Rust release, `0.9.2`). The organization property `github-codeql-config-file` was now
required with the `synthetics.yml@main` address as its default, so every repository of the organization uses that
file unless it sets another one. `synthetics.yml@main` (last changed 2026-11-20) named no Rust pack, neither
`githubsecuritylab/codeql-rust-queries` nor `githubsecuritylab/codeql-rust-extensions` (the Iron and Diesel models are
data extensions that only apply when that pack is loaded), and no pull request had proposed it yet (one merged on
2026-11-24, see the next paragraph). So merging the Rust queries
changes no scan until a configuration change names the pack, as the Actions pack needed one (section 4). Three more
facts from the day: **a publish is progressive**. The `0.9.2` publish run started at 23:00:49Z and was still
running at 23:21Z, but the Rust packs, and the Ruby, Python and Actions ones, already downloaded with
`codeql pack download githubsecuritylab/codeql-rust-queries@0.9.2`, and scans that started at 23:09:40Z had already
installed the other `0.9.2` packs. The `0.9.1` publish took 43 minutes. So a clean before has to start before the publish
run does, or you read the versions in the log (`explain` prints the Community Packs version on each side), and a Rust job
does not evaluate the other packs, so its baseline stays valid. **Check that the pack downloads before a
configuration change names it**: a pack in the file that cannot be downloaded fails the job at its initialize step (not
tried), and with the property on every repository that is every scan of the organization. **The Rust baseline** (the
synthetics configuration, no Community Packs Rust query, 40 stock Rust queries): the Rust job took 287 and 304 s in the
repository that also analyzes C/C++ and Actions (2026-11-20 and 2026-11-23), and 498 and 614 s in the Rust only
repository, a spread of 6% and 23% between two scans of unchanged code. Most of the time is extraction (105 s and
365 s) and the 40 queries take 103 s and 158 s. The Rust query rules that a default suite selects are the security ones
(`githubsecuritylab/rust/...`); the CORS query is an audit query and runs only in the audit suite, so `--ours` for it
finds nothing in a scan with the default configuration.

**Checked** (2026-11-24, the second Rust measurement). A Community Packs pull request had named the Rust queries and
extensions packs in `default.yml`, `synthetics.yml` and `audit.yml`, and the same `synthetics.yml` now also lists the
stock `codeql/rust-queries:.`. `trigger_scans.py --property Synthetic=true --language rust --apply` started both Rust
scans at 18:42:50Z (the plan found the same two of 61 repositories, 59 skipped because their default setup lists no
Rust), and they ended green after 5 and 9 minutes. `packs` finds all four pairs (the two Rust ones and the Actions and
C/C++ jobs of the first repository) on `0.9.2`. `compare` with the limits lowered to 1.2 times and 20 seconds: the Rust
median went from 459 to 409 s (ratio 0.91, nothing flagged). Per job, 304 to 286 s in the repository that also analyzes
C/C++ and Actions, and 614 to 532 s in the Rust only one, so the two scans of unchanged code of the baseline (a spread of
6% and 23%) are wider than the change. `explain` reads both: 16 to 18 packs installed (the two Rust packs), setup
+3.2 s and +3.0 s, the database phase 15 s and 62 s shorter (variance, because extraction dominates), and the query
phase 103 to 98 s and 158 to 132 s while 40 queries became 44. **The four new queries are the four Community Packs Rust
security queries, and the stock `codeql/rust-queries:.` line added no stock query** (the same 40 ran before and
after: the stock Rust pack has, probably, no security query outside what default setup's own suite already ran; not
checked). Their
summed evaluation time is 328 s and 469 s (11% of the job's summed time), and it is the shared computation that the
first query to need it pays, so each of the four shows 82 s in one repository and 115 to 119 s in the other: judge by
the phase. The one flagged pair is the C/C++ job of the first repository (85 to 124 s). It is not the release: the same
182 queries ran in it, none of them new and none of Community Packs, their summed evaluation time rose from 69 s to
107 s (the slowest increases were stock queries: 7.2 to 11 s, 1.9 to 4.4 s, 2.2 to 4.4 s), and the same job took 123 s
on 2026-11-20, 85 s on 2026-11-23 and 124 s on 2026-11-24 with those same 182 queries each time, so it moves by that
much with the runner. The `explain` verdict for it is `spread` and it says the same. **No massive change.**

## 8. Record it

One batch comment on the tracker issue: the rule, the pack version, the alerts (count and forks), how many linked
findings are covered, and the result of section 7 (pairs compared, the median ratio, and the flagged pairs with their
cause). The Action cell may carry a short note (`tracker_action.py set <issue> "..." --apply`).
Keep the `--snapshot` history if the numbers are to be tracked over time, and keep the `scan-*.json` files: they hold
the log summaries, and GitHub deletes the logs.
