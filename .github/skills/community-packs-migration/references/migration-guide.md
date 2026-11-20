# Moving a template fix into Community Packs

This is the playbook for turning a prototype fix from the synthetic-app pipeline
into a contribution to
[GitHubSecurityLab/CodeQL-Community-Packs](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs)
(Community Packs, CP). It covers mechanics and the quality bar. Whether an item
belongs in CP at all is decided by the triage on the gap issue (its destination
and assessed precision), and
[section 4](#4-security-grade-or-audit-grade-and-what-a-suite-does-with-it) says how
an audit query is framed.

The input is a gap issue in the template repo and its Copilot draft pull
request. Template pull requests keep their work under
`languages/<language>/custom/{src,test,models}`. They are prototypes: they have
passed their own small tests, nothing more. Two other records come with each
item. The **triage** holds the assessed precision, the destination and the
readiness items. The **tracker** is the template repo's tracking issue, whose
per-language tables have an Action column.

Everything in CP is public. Read [Disclosure](#disclosure) before you copy a
file.

Commands run from the skill directory (`.github/skills/community-packs-migration`).
Locations on your machine are written as `<work-root>`, `<wt-root>`, `<corpus-root>`,
`<stubs>` and `<cli>`: keep them short and outside every repository.

## The pipeline

| Step | Command | What it does |
| --- | --- | --- |
| Size the backlog | `plan-all` | A spec for every triaged pull request, and a tally of what needs a person. |
| Plan one item | `plan` | The spec for one pull request. Change a flag and plan again, do not hand edit the spec. |
| Port | `apply` | Copies files into a CP worktree, rewrites `@id`, `@precision` and `@tags`. It leaves pack versions alone. |
| Hand edit | | Readiness items, neutral fixtures, negative tests. |
| Gate 1 | `check` | The CP rules, formatting, compile with `--warnings=error`, tests. |
| Corpus | `community_packs_corpus.py sample` or `targeted` | A database of real public code, built once per language and shared, read only. |
| Gate 2 | `measure` | Runs the query on a corpus, profiles it, keeps every row for triage. |
| Evidence | `community_packs_corpus.py links` | Commit pinned permalinks and repository metadata for the rows. |
| Packet | | A package for the human to review and publish. |
| Track | `tracker_action.py` | Records the pull request and its state in the tracker's Action column (see [Tracker](#tracker)). |
| Verify | `verify_alerts.py` | After the release: does the query find the original finding, and how many alerts does it raise. See [verify-detection.md](./verify-detection.md). |

The commands live in [`scripts/community_packs_migrate.py`](../scripts/community_packs_migrate.py),
[`scripts/community_packs_corpus.py`](../scripts/community_packs_corpus.py),
[`scripts/tracker_action.py`](../scripts/tracker_action.py) and
[`scripts/verify_alerts.py`](../scripts/verify_alerts.py).
Nothing in the pipeline pushes, opens a pull request or comments. The one script that can write
to GitHub is `tracker_action.py` (the tracker's comments), and only with `--apply`;
`verify_alerts.py` only reads. Publishing is a
public write and needs a human ([Human gate](#human-gate)). A worker that
migrates one issue follows [`worker-brief.md`](./worker-brief.md).

## Decisions taken

These were open after the pilot and are settled as below. If the maintainers decide
differently, change this table and the affected packets, not one pull request at a
time.

| Question | Decision | Why |
| --- | --- | --- |
| Suite posture | Ship security-grade with the `experimental` tag and leave the query in the default suite: experimental is what Community Packs is for, and a non-experimental query belongs in `github/codeql`. **Do not edit suites in a query pull request.** The packet records what `<lang>.qls` selects. | Confirmed by the maintainer (2026-11-18). The existing experimental queries in CP are in the default suites, so the tag is informational there. |
| Language segment of `@id` | Always, following the stock prefixes in section 3. | Matches the requested `githubsecuritylab/java/...` form. Shipped ids stay as they are. |
| Pull request granularity | One pull request per tracker issue (confirmed by the maintainer, 2026-11-18). A worker builds one branch per **unit**: a query with its help and tests, or the model files with the tests no query owns. `plan-all` splits a template pull request into units (and a multi-language one by language), and the units of one issue are combined into one pull request when it is published. | Independent units can be reviewed or reworked alone, a worker's scope stays small, and the tracker Action cell holds one link per issue. |
| `decision_needed` items | Proceed when the recommended destination is CP. | CP is the conservative default for anything doubtful, and a later move to `github/codeql` stays possible. |
| Model rows for a language without an ext pack | A separate pull request adds the data extension pack first (confirmed by the maintainer, 2026-11-18). [GitHubSecurityLab/CodeQL-Community-Packs#254](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/254) added the empty packs for JavaScript, Ruby and C++ (the languages with pending model rows) and merged on 2026-11-18, so those languages now take model rows. Swift and Actions have no ext pack and no pending model rows. | Creating an ext pack is its own change. |
| Example to cite | None by default. A pull request does not cite a live project. | A true positive on a live project is an unpatched vulnerability or a leak. The packet keeps the evidence for the maintainer. |
| Evidence per unit | Two tiers (section 7): a true positive on a real project for precision high and above, the shared corpus measure with every row classified for the rest. | The true positive search took 1 to 3 hours per unit in the first batch. The maintainer can still require it for any unit. |
| CodeQL config for gates | Empty (`CODEQL_CONFIG_FILE`, no user config) for `check`, `measure` and every test run. | A user config can enable every threat model, which CI does not. |
| A language whose tests cannot run on your platform (Swift has no extractor on Windows) | Migrate the files, record "tests not run locally", and let CI run them. | The gate cannot be met locally, so the packet says so instead of pretending. |

## 1. Go or no-go

Stop and send the item back if any of these hold:

- The triage destination is not Community Packs. An item with `decision_needed`
  proceeds when the recommended destination is Community Packs. Record the
  alternative in the packet.
- It is a data extension **edit** or a straightforward unambiguous **add**.
  Those belong in `github/codeql`.
- The pull request touches more than one language. Split it first
  (`plan` refuses to continue).
- It is a bundle and you were given the whole of it. Migrate one unit at a time
  (`plan-all` names them). The triage `split_note` says which parts are
  separable and which could go to `github/codeql` instead; record that in the
  unit's packet.
- A readiness item in the triage cannot be met. Record it as accepted by a
  human, with a reason, or do not migrate.

## 2. Where each file goes

`<lang>` is the pack directory (`actions`, `cpp`, `csharp`, `go`, `java`,
`javascript`, `python`, `ruby`, `rust`, `swift`). The template language `html`
migrates into `javascript`.

| Template pull request | Community Packs |
| --- | --- |
| Query `.ql` | `<lang>/src/<group>/CWE-NNN/<Name>.ql`, where `<group>` is `security` or `audit` |
| Query help `.md` or `.qhelp` | same directory and stem as the query |
| Query tests | `<lang>/test/<group>/CWE-NNN/<Name>/` with `<Name>.qlref`, `<Name>.expected` and the fixtures |
| Model rows `.model.yml` | `<lang>/ext/manual/<library>.model.yml` |
| Model tests | `<lang>/test/security/CWE-NNN/<library>/` with a test `.ql` that imports the real flow module |
| Query library `.qll` | `<lang>/lib/...` |
| Pack version | not changed: a release sets every version (see the note below the table) |
| Change notes | not applicable, CP has none |

**A pull request does not change any pack version** (decision of 2026-11-18: the
maintainer cuts a release when everything is ready to publish). Merging never publishes
or cuts a release: `publish.yml` runs only when `.release.yml` changes, and that happens
through the maintainer-run `update-release.yml` or `update-codeql-version.yml` pull
request. Those run `patch-release-me`, whose `{version}` placeholder expands to any
semver, so it rewrites **every** `qlpack.yml` `version:` to the new release version,
whatever it was (precedent: the Java query pull request bumped `java/src` to 0.8.0, and
the next release pull request set it back to 0.7.6 with every other pack). A bump in a
pull request would therefore only make the pack differ from the rest until then, and a
manual one-off `publish.yml` run would publish the higher number. `check` fails when an
existing `qlpack.yml` version changes. A new pack starts at the repository's current
release version (0.9.0 for the JavaScript, Ruby and C++ ext packs).

Do not reuse `github/codeql` paths such as `<lang>/ql/...`. A `.qlref` points at
the query relative to the `src` pack: `query: security/CWE-NNN/<Name>.ql`.

## 3. Query identity and metadata

### `@id`

```text
githubsecuritylab/<lang>/<kebab-name>             security-grade
githubsecuritylab/audit/<lang>/<kebab-name>       audit-grade
```

Example: `githubsecuritylab/java/uncontrolled-file-decompression`.

| Pack directory | `<lang>` in the id |
| --- | --- |
| `actions` | `actions` |
| `cpp` | `cpp` |
| `csharp` | `cs` |
| `go` | `go` |
| `java` | `java` |
| `javascript` | `js` |
| `python` | `py` |
| `ruby` | `rb` |
| `rust` | `rust` |
| `swift` | `swift` |

The language segment follows the stock CodeQL id prefixes. Existing ids in CP
are mixed (62 of 95 Java queries have a `java/` segment, Python, Ruby and C++
queries have none, and CP's audit ids omit the language). The rule applies to
new queries. Do not rename shipped ids: an id is part of a published pack.

The name describes the weakness. It never carries the gap key, an issue number or
an application name. The id must not clash with any id in CP. `check` tests this.

### The rest of the header

| Tag | Rule |
| --- | --- |
| `@name`, `@description`, `@kind`, `@problem.severity` | Required. The description says what is reported, not how. |
| `@precision` | The **assessed** precision from the triage, never the value the prototype declared. Never raise it to reach a suite. |
| `@tags` | `security`, `external/cwe/cwe-NNN`, and `experimental` for every item the tracker labels `tags:experimental`. Audit queries add `audit`. |

## 4. Security-grade or audit-grade, and what a suite does with it

Decide first. Complete this table before you implement or migrate:

| Question | Security query | Audit query |
| --- | --- | --- |
| Requires an attacker-controlled source to reach a sensitive sink | Yes | No |
| Acceptable in default suites | Yes | Usually not |
| Precision expectation | High | Explicitly lower |
| Alert framing | "This is exploitable" | "Review this construct" |

Detection without provable reachability is often a legitimate audit query. Say so
plainly and label it as such rather than lowering the precision of a default security
query. A conclusion that a precise query is impossible is not a conclusion that nothing
can be done: before reporting that CodeQL cannot help, evaluate an audit query against
the audit bar (a warning that asks for review, `@precision very-low`, tag `audit`). A
measurement that disqualifies a security query, such as a candidate sink firing on both
the safe and the unsafe route, is often exactly the intended behavior for an audit
query, because it honestly reports what the database cannot distinguish.

Then check what CP's suites will do with the result, because that is what users get.

| Posture | Placement | Metadata | Selected by |
| --- | --- | --- | --- |
| Security-grade | `src/security/CWE-NNN/` | `@precision` very-high to low | `<lang>.qls` |
| Audit-grade | `src/audit/CWE-NNN/` | `@precision very-low`, tag `audit` | `<lang>-audit.qls` only (cpp, csharp, go, java, javascript, python have one) |

**The `experimental` tag does not keep a query out of the default suite.** The
`<lang>.qls` suites select by kind and precision (very-high, high, medium, low)
and exclude only the `audit` and `debugging` tags. A medium-precision query
tagged `experimental` is part of `actions.qls`, `java.qls` and the rest from the
moment it ships. `codeql resolve queries --additional-packs <lang> <lang>/src/suites/<lang>.qls`
shows it. If a query must not run by default, make it audit-grade, or raise a separate
suite change, and say which in the packet. Do not assume the tag does it.

## 5. Data extensions by language

Only `cpp`, `csharp`, `go`, `java`, `javascript`, `python`, `ruby` and `rust` have an
`ext` pack (`EXT_LANGUAGES` in the script). `plan` warns when model rows target any
other language.

| Language | Options for model rows |
| --- | --- |
| `cpp`, `csharp`, `go`, `java`, `javascript`, `python`, `ruby`, `rust` | `<lang>/ext/manual/<library>.model.yml`. Keep `extensionTargets` as `'*'`. The test pack must depend on the ext pack. Do not run `codeql pack install` on an ext pack. |
| `swift`, `actions` | Model the API in QL inside the query pack or `lib`, or ask the maintainers to create an ext pack first. This is a maintainer decision, not a worker's. |

A model-only change has no query to measure, so Gate 2 for it is different
(see [Gate 2 for model-only units](#gate-2-for-model-only-units)).

## 6. Tests

- Positive and negative controls for every behavior. A negative control for every
  false positive class found in [Gate 2](#7-quality-bar).
- Neutral identifiers only: no application names, no domain vocabulary from the
  synthetic app. Use `--replace OLD=NEW` when you plan and `--deny` when you check.
- Learn `.expected` only after you have read the diff. Never commit an `.actual`
  file.
- Small fixtures. Tests that need stubs use the stubs CI makes available (see
  [Tooling](#9-tooling)).

## 7. Quality bar

A migrated query is done when all of these hold.

1. `check` passes. It runs the CP rules (metadata, help file present, forbidden
   constructs, id uniqueness, denied names in every changed file and file name,
   no `postprocess:` line) and the same commands CI does: a format check on the
   LF content (a Windows checkout may have CRLF), `codeql pack install
   --additional-packs <lang> <lang>/{lib,src,test}`, `codeql query compile
   --check-only --warnings=error` over the queries **and the test queries**, the
   help renders, `codeql test run --additional-packs <lang>`, and for model rows
   `codeql pack create` on the ext pack and a test pack that depends on it. It also
   fails on lock file churn, and reports which of the language's suites select the
   query. It runs with the user CodeQL config hidden (see [Tooling](#9-tooling)).
2. The query meets `CONTRIBUTING.md`: no internal libraries, no `getAQlClass`, no
   regexp matching on `toString`, resilient to later library changes.
3. Evidence on a real project, by tier (below).
4. `measure` passes on a public corpus (below).
5. Every result on that corpus has been read and classified.
6. No pack version changed (a release sets them). `check` fails when an existing
   `qlpack.yml` version changes.
7. `scan` passes on the committed branch and on the drafted pull request text.

### Evidence tiers

The true positive on a real project is the slowest step (it needs a database of
the right project, and building one took 1 to 3 hours in the first batch). Spend
it where it matters.

| Tier | Units | Evidence required |
| --- | --- | --- |
| 1 | Assessed precision very-high or high | A true positive on a real project, from the shared corpus or one small targeted database (at most 3 repositories, at most 45 minutes of build time). |
| 2 | Medium, low, or audit-grade | The measure on the shared corpus with every row classified. A true positive is welcome. If there is none after that, the packet says "no true positive found in <N> repositories" and the maintainer decides. |

Never exceed the build budget for a targeted database. Stop and report instead.

### Gate 2: measure on a real corpus

A query that passes its tests can still be unusable. The tests run on a
database of three files, where a join over every expression is invisible. On a
real corpus the same join is unbounded.

The pilot query (an Actions query, 329 public workflow files, about 84,000
lines) shows it:

| | Original port | After the fix |
| --- | --- | --- |
| 40 workflow files | 8 min 15 s | 30 s |
| 329 workflow files | did not finish in 20 min, 8 GB | about 2 min, of which the query's own predicates are about 3 s |

The cause was a predicate with a free variable that the compiler inlined into a
cartesian product of every statement with every expression (6.3 million tuples)
and then ran regular expressions on each row. The fix was to materialize the
small relation first (`pragma[nomagic]`, a predicate of its own). The test
database could not show it.

```text
measure --spec S --cp <worktree> --codeql <cli> --db <corpus database> --out <dir>
```

`measure` runs the query with an evaluator log, then reports the wall time, the
time spent in the query's own predicates (library cost excluded, shown but not
judged), the top predicates, and writes `rows.json` for triage and `measure.json`.
It **passes when the query's own predicates take at most 60 s** (`--budget`) and
the evaluation finishes within `--max-wall` (2 hours, then it is killed). Read the
top predicates even when it passes.

- **It does not count tuples by default.** Counting changes how the evaluator runs:
  one Java corpus took 23 minutes counted and 36 seconds plain. Add
  `--tuple-counting` to diagnose a failure, and then a cartesian product of a
  million tuples or more in the query's own predicates fails the gate.
- **`--timeout` is per evaluation layer**, not a total limit. `--max-wall` is the
  total limit.
- **Own cost** is every predicate with the query's name in it, including data flow
  instantiations such as `MakeImpl<...>::DefaultState<<Query>::Config>::isSource`.
  A data flow query on a very large database can spend most of its own cost in
  those instantiations. If it is over budget there, report it and let the
  maintainer decide, do not hide it.
- At most 3 heavy evaluations run at once on the machine (`--slots`). `measure`
  waits for a slot, so start it early and write the packet while it runs.

Corpus rules:

- One database per language, built once with `community_packs_corpus.py sample`
  (a seeded random sample, 25 to 30 public repositories, 300 KB to 10 MB each),
  kept outside the repository (`<corpus-root>/<lang>`) and read only. Workers wait
  for `READY` in that directory. A random sample measures cost and the base rate
  of false positives.
- Add a targeted database for the construct with
  `community_packs_corpus.py targeted --code-search "<terms>"` or
  `--repo owner/name@sha`. A niche framework is not in a random sample.
- The corpus script uses build mode `none` for Python, JavaScript, Ruby, Java and
  C#. Go needs a build, so its corpus is a few small modules built with a manual
  command. C/C++ and Swift cannot get a corpus on Windows (see
  Tooling).
- Actions databases need the workflow files flattened to `.github/workflows` at
  the source root.
- Corpora and results stay local. Never commit them.

### Choose the true positive

CONTRIBUTING asks for a true positive on a real project. A true positive of a
security query is an unpatched vulnerability or a live leak unless you choose
carefully. In order of preference: a revision where the bug is already fixed (a
published advisory or a later commit), an archived project, a deliberately
vulnerable application, a test repository that exists to show the pattern. Never a
live project with the bug. Keep every permalink in the local packet and let the
maintainer choose what the pull request cites.

### Triage every row

Classify each result as true positive, false positive or unclear.

- For each systematic false positive class, fix the query and add a negative test
  that has the same shape as the real case.
- Accept a class only when it cannot be separated cheaply, and then write it under
  "Known limitations" in the query help.
- Record the counts (rows, true positives, false positives, classes fixed) in the
  packet.

The pilot found 14 rows. Eight were decode-to-file steps (`base64 --decode -o`,
process substitution). The six others were real leaks (one duplicate). After the
fixes the corpus gives five alerts and every one is a true positive.

### Gate 2 for model-only units

There is no query to measure. The evidence is different, and the first model-only
migration (Java summary models for a JSON library) set the bar:

- **Every row is real.** Each signature resolves against the real library (for
  example `javap` on the released jar, and a database built against that jar).
  A row that does not resolve is dropped or fixed, never shipped.
- **A test that proves each row.** A custom test `.ql` that imports the real flow
  module, one positive expectation per row, negative controls (nothing tainted,
  another package with the same class name), known gaps written as `MISSING`
  expectations, and a leave-one-out run showing that removing any single row
  fails the test. A test that three of thirty-one rows satisfy is not coverage.
- **Before and after on a real project** (a safe example, see above): the stock
  query without the rows, then with them. Record the alert counts, check that
  every new alert is a true positive and that no alert is lost.
- **Pack checks the CI extensions job runs**: `codeql pack create` on the ext pack,
  the test pack depends on the ext pack, no lock file for the ext pack.
  `codeql resolve queries <lang>/src/suites/<lang>.qls` must resolve exactly what
  it did before.
- Say in the pull request that the rows apply to every taint tracking query for
  users who load the extensions pack.

## 8. Versions, branches and pull requests

- Do not change any pack `version:` (see section 2). A release sets every version.
  Never hand edit a value a release tool derives as a delta.
- **One branch per unit** (see "Decisions taken"). `plan-all` writes one spec per
  unit, `<issue>.spec.json` or `<issue>.<unit>.spec.json`. Queries that share a
  template directory cannot be told apart by path and stay together (the "several
  queries" warning), and a worker may still split them by hand with
  `plan --only <file name>` (repeatable, matches a path segment).
- Branch: `<lang>/<id-name>` (for example `actions/encoded-secret-in-log`).
- Title in the repository's style: `Add Actions encoded secret in log query`.
- Open it as a draft. Then wait for automated review, check each comment against
  evidence, and reply on every thread, resolving the ones you fixed.

## Disclosure

This is the rule that cannot be traded for speed.

- The public text (commit, branch, pull request, comments, query help, fixtures)
  never mentions the template repo, its issues or pull requests, the tracker, any
  internal repository, any customer, or the synthetic applications the weakness
  was first seen in. The pull request stands on the weakness, the tests and the
  real-project evidence. The origin stays in the tracker Action column.
- Replace application identifiers at plan time and deny them at check time. A
  renamed fixture that is still recognizable is not neutral.
- Evidence from public repositories can still hurt the people it names. A true
  positive is often a live leak. Keep the permalinks in the local packet. Prefer
  a repository that shows the pattern on purpose (a test repository or a proof of
  concept) or an archived revision, and let the human choose what is cited. Never
  paste a secret or a log excerpt.
- Review the complete diff and every outbound string (commit message, trailers,
  title, body, links) immediately before any public write.
- If you are not sure a detail is safe, stop and ask.

## Human gate

Approval authorizes a write. It does not perform one. Signing may need the human at
the keyboard (a signing agent that asks for approval), so the human approves each
public write, and the session performs it while they are present. The packet is what
makes that quick.

An `Upstream publication packet` for CP contains:

- Destination, branch name and the exact files and test location (no pack version change).
- Change note: not applicable.
- Suite behavior: what `<lang>.qls` does with the query, and the decision taken.
- Evidence: corpus, size, wall time, own-predicate time, row counts, true and
  false positive classes, and the permalinks (local only).
- The readiness items from the triage, each marked resolved or accepted.
- The drafted public title and body, checked against [Disclosure](#disclosure).
- A note that local commits may be unsigned and need signing before they are
  pushed.
- The commands that publish it, as run for the pilot: sign
  (`git commit --amend -S --no-edit`, which may prompt the signing agent), push the
  branch to `origin` (a maintainer with push access needs no fork), then
  `gh pr create --draft`. The pilot's 27 CI checks, including the language's
  `compile-and-test`, ran on the draft pull request and finished in about 3 minutes.

After the pull request exists, expect Copilot's code review within minutes of the push
and of every later push. The repository ruleset turns it on for every push, drafts
included, which is why `reviewRequests` stays empty and says nothing. Poll
`gh api repos/GitHubSecurityLab/CodeQL-Community-Packs/pulls/<n>/reviews` for
`copilot-pull-request-reviewer[bot]` and read **both** its threads (`reviewThreads` in
GraphQL) **and the review body**: findings in code that did not change since the last
round are listed there as "previously missed issues" and get no thread, so checking only
the threads misses them. Triage each finding, prove the real ones with a failing test
first (one statement per fixture step, because alerts are per script), fix them, and
reply once to each thread with the fix and resolve it. For a finding that has no thread,
reply with one pull request comment. Prove that the new negative fixtures can fail by
mutating the query (make the new rule accept everything) and that the new fixtures fail on
the previous query, then say so in the reply. If the signing agent does not answer (it
needs the maintainer at the machine), a fix can be pushed as a GitHub-verified commit
with the `createCommitOnBranch` GraphQL mutation, after which the local branch is reset
to it. Rounds keep finding small things in a heuristic query, so stop when a review lists
no open issue. The merge itself needs a code-owner review (the ruleset requires it from the
`codeql-community-packs-admin` team) and the required checks.

## Tracker

Record the pull request link in the Action column of the tracker with
`python scripts/tracker_action.py set <issue> "<link>" --apply`. That column belongs to
the maintainer: the script changes only that cell and leaves every other character of
the comment alone. When a pull request merges or closes,
`python scripts/tracker_action.py refresh --apply` adds its state after each link
(`draft`, `open`, `merged <date>`, `closed <date>`). The maintainer's standing rule is one
batch comment on the tracker issue that lists what was created, merged or changed, with
full links. Without `--apply` both commands print what would change and write nothing.

## 9. Tooling

- Pin the CLI to the version in `.codeqlversion` of the CP checkout. A different
  CLI resolves different library versions and makes results incomparable.
- Use short paths and one git worktree per issue (for example
  `<wt-root>\<issue>`). Windows long paths break pack resolution.
- CI also clones `github/codeql` at the CLI branch (`codeql-cli-<version>`) into
  the repository root so tests can use its stubs (C# and Java tests reference
  `codeql/csharp/ql/test/resources/stubs` and `codeql/java/ql/test/stubs`). Keep
  one sparse clone outside the worktrees and give each worktree a junction
  (the path is gitignored):

  ```powershell
  $env:GIT_CONFIG_GLOBAL = '<a gitconfig without the https to ssh rewrite>'
  git clone --depth 1 --filter=blob:none --sparse --branch codeql-cli-<version> https://github.com/github/codeql.git <stubs>
  git -C <stubs> sparse-checkout set --cone csharp/ql/test/resources/stubs java/ql/test/stubs
  cmd /c mklink /J <wt-root>\<issue>\codeql <stubs>   # Linux or macOS: ln -s <stubs> <wt-root>/<issue>/codeql
  ```

  Add a directory with `git -C <stubs> sparse-checkout add <path>`. `prepare --stubs <stubs>`
  makes the junction for you.
- Warm the pack cache once per language (`codeql pack install` for `lib`, `src`
  and `test` in a throwaway worktree) before starting workers. Concurrent first
  installs race on the shared cache.
- If git over SSH fails (an unavailable signing or key agent), clone public
  repositories over HTTPS with a `GIT_CONFIG_GLOBAL` that has no `insteadOf`
  rewrite, and commit local work with `git -c commit.gpgsign=false`. Sign before
  anything is pushed.
- Local diagnostics leave lock file churn. `check` fails on it. Revert it.
- **A user level CodeQL config changes results.** `~/.config/codeql/config` with
  `--threat-model all` applies to `codeql test run` and
  `codeql query run`, so local sources (files, environment, standard input) become
  active and results differ from CI. The scripts run every gate with
  `CODEQL_CONFIG_FILE` pointing at an empty config file
  (created under the temp directory, or `CPM_EMPTY_CONFIG`), which replaces the user config and leaves
  the user profile alone. Overriding `USERPROFILE` instead also hides it but
  breaks the Python extractor (the `py` launcher then finds no Python), and
  `HOME`, `XDG_CONFIG_HOME` and JVM properties do nothing. If you run `codeql`
  by hand, set `CODEQL_CONFIG_FILE` the same way. `check` fails when a user
  config still applies. By hand, `codeql resolve extensions <query>` lists a
  `threatModelConfiguration` row in `threatModels` exactly when one does.
- Line endings: the CodeQL formatter flags CRLF in `.ql` files and the editor
  tool may write CRLF. `check` compares the LF content, as CI sees it. Fix with
  `codeql query format --in-place` on every `.ql` and `.qll` you touch.
  `apply` keeps the line endings of `qlpack.yml`.
- `apply` drops a `postprocess: utils/test/InlineExpectationsTestQuery.ql` line
  from a `.qlref`: CP's test packs cannot compile it, so the `.expected` file is the
  only oracle. Re-learn it and read the diff. `apply` also renames every file that
  carries the query name (`.qlref`, `.expected`, `.ext.yml`), applies `--replace`
  to file names and every text file in every casing, converts Markdown help to
  `.qhelp` for C# and Java, and sets the audit metadata for an audit query.
- **CI compiles the whole language when any non-`.ql` file changes**
  (`pr-compile.sh`: any non-`.ql` change in the language runs a strict full
  compile). `baseline` runs that compile on `main`. A language that is red there
  makes every unit in it red for a reason that is not its own. Read
  `<work-root>\baseline\<lang>.json` before you blame a unit.
- The Python test pack does not list `githubsecuritylab/codeql-python-extensions`
  as a dependency, so a Python model unit has to add it (`check` says so).
- `codeql test run` deletes the `*.testproj` databases after a pass. Add
  `--keep-databases` to query a test database.
- Build modes in CLI 2.27.4: `none` exists only for C#, Java, JavaScript and
  TypeScript, Python and Ruby. Go, C/C++ and Swift need `autobuild` or a manual
  build command, which is slow on a multi-module tree and needs a toolchain
  (a compiler for C/C++, macOS or Linux for Swift). Corpora for those
  languages are built from a few small repositories, or on a Linux machine.
  Even `none` runs Maven or NuGet restore for Java and C#: 7 repositories took
  99 minutes and 8 took 82. Budget for it, build the shared corpus once, and do
  not build a targeted database in a worker unless the tier asks for it.
- A strict warnings mode stops at the first failure. Run a full sweep before you
  trust a single report as the whole list.

```powershell
python scripts/community_packs_migrate.py plan-all --template <template clone> --triage <triage.json> --out-dir <specs>
python scripts/community_packs_migrate.py next-batch --specs-dir <specs> --work-root <work-root> --corpus-root <corpus-root> --size 8
python scripts/community_packs_migrate.py prepare --spec <specs>\<unit>.spec.json --cp <cp-checkout> --wt-root <wt-root> --work-root <work-root> --stubs <stubs> --deny-source <deny-by-pr.json> [--extra-deny NAME]
python scripts/community_packs_migrate.py status --specs-dir <specs> --work-root <work-root>
python scripts/community_packs_migrate.py plan <pr> --template <template clone> --triage <triage.json> --out <spec> --replace OLD=NEW [--only NAME] [--test-name NAME]
python scripts/community_packs_migrate.py apply --spec <spec> --cp <worktree> --codeql <cli>
python scripts/community_packs_migrate.py check --spec <spec> --cp <worktree> --codeql <cli> --deny-file <work>\deny.txt
python scripts/community_packs_migrate.py measure --spec <spec> --cp <worktree> --codeql <cli> --db <db> --out <work>\measure
python scripts/community_packs_migrate.py scan --cp <worktree> --deny-file <work>\deny.txt --pr-body <work>\pr-body.md
python scripts/community_packs_migrate.py baseline --cp <main worktree> --codeql <cli> --out <work-root>\baseline
```

`next-batch` skips units that need a decision first (model rows for a language
without an ext pack, nothing to migrate, no tests), and orders the rest by
assessed precision, clean units first, queries before model rows. `prepare` makes
the worktree on `wip/<unit>`, the `codeql` stubs junction, the work directory and a
`deny.txt` from the app names of the pull request. `status` reads the
`report.json` each worker leaves in `<work-root>\<unit>`. `scan` is the last gate:
it reads the commit messages, the branch name, every changed file and file name,
and the drafted pull request text for denied names, template and pipeline
references, local paths, tokens, placeholders and dashes, and lists links to check.

Run `apply` once on a clean worktree. It refuses to overwrite existing files, so
it never destroys hand edits. Edit by hand, then run `check` again.

## 10. Working in bulk

One session can run a single pilot. The backlog is large: `plan-all` splits the issues
sent to CP into units, and `summary.json` shows which of them carry a warning that needs
a person (most of them did at the start).

### What the first batch cost

Six units (Ruby, Go, C#, Java query, Python, Java model rows) ran in parallel on
a machine shared with other sessions. Each took 3.7 to 6.3 hours, and almost all of
it was waiting for the machine, not thinking:

| Cost | Examples |
| --- | --- |
| Corpus builds | Java 3 h 28, C# 79 min, Go autobuild 36 min for one module, Maven resolution 99 min for 7 repositories |
| Evaluations on large databases | Ruby 55 and 82 minutes, a Java run of 23 minutes that took 36 seconds without tuple counting |
| Every worker hit the same script gaps | user CodeQL config applied, `postprocess:` in qlrefs, `--threads=0`, fixtures not scanned for app names, library blowups failing the gate, audit metadata, `.md` to `.qhelp`, CRLF |

The scripts now fix those once. The shared corpora exist, `measure` is plain and
capped, and the evidence tiers limit the true positive search. Plan for 1 to 2
hours per unit on a quiet machine.

| Role | Does |
| --- | --- |
| Coordinator | Owns this guide and the scripts, picks and orders batches, builds the corpora and the shared stubs clone, creates the worktrees, reviews every packet (and has the diffs reviewed independently), fixes script bugs centrally, keeps the tally. |
| Worker (one background agent per tracker issue) | Follows the [worker brief](./worker-brief.md): `plan`, `apply`, hand edits, `check` and `measure`, row triage, the evidence for its tier, and the packet. |
| Human | Decides what the guide leaves open, approves, signs and publishes. |

A worker must:

- Work only in its own worktree and branch. Make one local commit.
- Never push, open a pull request or comment, and never touch another worktree.
- Stop and report instead of improvising when [Go or no-go](#1-go-or-no-go) fails.
- Return the spec, the `check`, `measure` and `scan` reports, the rows with their
  classification, the diff, and the packet.
- Not edit the scripts. A script bug is reported and worked around by hand, and
  the coordinator fixes it once for everyone.

The coordinator rejects a packet that lacks any of those, that has an unexplained
warning from `plan`, a `.expected` change nobody read, an unclassified row, or a
fixture that is not neutral. It re-runs `check` and `scan` on every worker branch
before it accepts the report.

Order batches by language, so corpora and caches are shared, and
by precision, highest first. Do query-only items before model-only items, and
leave the languages without an ext pack to last. Run 8 workers at a time at most:
`measure` takes a slot and at most 3 heavy evaluations run at once, so the others
work on the packet meanwhile.

## 11. Worked example

The first migration,
[GitHubSecurityLab/CodeQL-Community-Packs#253](https://github.com/GitHubSecurityLab/CodeQL-Community-Packs/pull/253),
is the Actions query that reports a secret printed after an encoding command. It was
ported mechanically (`plan`, `apply`), then needed work that no tool does:

- The help text said Base64 is not masked. The runner masks it at three
  alignments, so the text was wrong. It now explains the two real leaks (newline
  and line wrapping) and lists what is not masked.
- Tests lacked negative controls: hash or encrypt then encode, `exec` redirection,
  here-document bodies, decoding, output options, process substitution.
- The query had the join blowup in [Gate 2](#gate-2-measure-on-a-real-corpus).
- The same expression text twice in one script reported the same alert twice.

Every one of those passed the prototype's own tests.

Copilot code review then raised six further findings on the pull request, three as
threads and three only in a review body. All were gaps in the heuristic shell parsing
(redirections, environment assignments, conditionals), and each was reproduced with a
failing test before it was fixed.
