# Whole-package coverage verification — 10 October 2026

## Status and scope

VERIFIED: the clean local suite exceeded the requested **95% statement coverage**
target for the entire `vulnassess` package. This is not a project-completion
percentage, vulnerability-detection accuracy, branch coverage, or proof that all
scanners and providers are available.

This increment serves PROJECT.md stages 1-8 and its cross-cutting evaluation and
reproducibility component. It strengthens evidence integrity and failure handling
without altering authorization, canonical scoring, or the AI validation rules.

Branch: `codex/coverage-95`, based on `fee43cd`. Implementation/test commits run
from `6219cb5` through `da46bea`; the accompanying tooling/documentation commit
records the raised gate. No push, merge or deployment was performed.

## Measured delta

VERIFIED local results (Windows, Python 3.12.10):

| Measure | Baseline, 9 October | Clean final run, 10 October |
|---|---:|---:|
| Tests passed | 731 | 1,315 |
| Subtests passed | 510 | 510 |
| Package statements | 9,779 | 9,781 |
| Missing statements | 1,337 | 472 |
| Statement coverage | 86.33% | 95.17% |

Delta: **584 additional test cases**, **8.84 percentage points** of coverage, and
**865 fewer uncovered statements**. Twenty focused test files were added. No
package modules were excluded, no coverage pragmas added, and no existing test
assertions or safety checks were removed. Final result: zero failures and zero
skipped tests. The statement denominator increased because the timestamp fix adds
a guard; it did not shrink to improve the percentage.

## What changed

TESTED WITH MOCKS: provider adapters now have explicit tests for HTTP errors,
timeouts, missing or separate credentials, invalid JSON, response/token limits,
stream truncation, audit bytes and untrusted-evidence system instructions.
Cloud transports and Ollama are replaced at the transport boundary. Scanner
availability and execution tests replace subprocesses; no scanner is launched.

VERIFIED: temporary SQLite tests exercise finding/CVE/CWE relationships, asset
links, role predictions, context signals, comments, filtering, read-only failures,
and persistence of prior intelligence when a refresh is invalid. CLI tests process
checked-in synthetic evidence through enrichment, context and ranking, assert
canonical scores remain unchanged by shadow model predictions, and exercise
small deterministic evaluation jobs. These are local code-path results, not real
target or expert-study results.

TESTED WITH MOCKS: PostgreSQL tests check SQL parameterization, read-only setup,
driver/connection errors, rollback and cleanup using a fake transport. They are
**not PostgreSQL integration tests**.

VERIFIED: artifact tests reject malformed schemas, unknown identifiers,
unsupported claim metadata, invalid hashes, dangling references, incompatible
snapshots and unjustified remediation conclusions. UI tests check escaped
payloads, explicit HTTP failure responses, and refusal to publish an offline
export when required assets are missing or unreadable. No visual redesign or
new browser acceptance test is claimed.

VERIFIED bug fix: `intel_status._fresh()` previously subtracted an aware clock
from a timezone-naive timestamp before checking `tzinfo`, raising `TypeError`.
The regression was reproduced first. The guard now returns `False` before the
subtraction, so malformed freshness metadata is not considered current.

VERIFIED source changes: the required floor is now 95% in the GitHub workflow,
Makefile and `scripts/check.py`. Current quality instructions and contracts point
to decision QA-95-01. Historical verification reports were not rewritten.

## Commands and observed output

VERIFIED: the final coverage run did **not** use `--cov-append` or reuse earlier
incremental coverage. From the repository root, using the installed Python:

```text
python -m pytest -q -p no:hypothesispytest --cov=vulnassess --cov-fail-under=95 --durations=5

TOTAL                                  9781    472    95%
Required test coverage of 95% reached. Total coverage: 95.17%
1315 passed, 510 subtests passed in 319.98s (0:05:19)
```

The report's integer column rounds the percentage; the gate uses the actual
95.17% value. The local output is retained in the ignored
`data/verification/capture-history/coverage-95-full.log` file.

VERIFIED static gates:

```text
python -m ruff check .
All checks passed!

python -m ruff format --check .
222 files already formatted

python -m pyright
0 errors, 0 warnings, 0 informations
```

The optional `hypothesispytest` plugin installed on this workstation is blocked
by Windows App Control. `-p no:hypothesispytest` disables that unrelated plugin,
not any project test. The normal CI command remains `python -m pytest
--cov=vulnassess --cov-fail-under=95` without the workstation-specific option.
No tool or dependency was downloaded to obtain these results.

## Limits and remaining work

- NOT RUN: remote Ubuntu/Python 3.11 and 3.12 CI matrix. The local result does
  not certify that matrix; run it on the review branch before merge.
- NOT RUN: live cloud/Ollama provider calls, scanner execution, publisher refresh,
  or real PostgreSQL integration. This task intentionally used offline tests.
- NOT RUN: model accuracy, expert ranking agreement, false-positive/negative
  rates, or independent lab validation. Code coverage cannot replace those studies.
- VERIFIED: 472 package statements remain uncovered. Major remaining groups are
  UI server (63), CLI (56), live assessment (48), analyst (38), and portions of
  audit/intelligence/model governance. The 95% requirement is aggregate, not a
  claim that every module has 95% coverage.
- NOT RUN: branch coverage and mutation testing. Statement execution alone
  cannot demonstrate that every meaningful branch or wrong result is detected.

Next: run the remote matrix and review these focused commits before merge;
then continue with independently supplied lab and expert-evaluation evidence.
Do not loosen scope or validators to make a live demonstration look complete.

## Increment handoff

- STATUS: locally verified; remote verification and merge pending.
- BRANCH / COMMIT: `codex/coverage-95`; focused commits listed above.
- GATE: 1,315 tests + 510 subtests; 95.17%; Ruff and Pyright passing.
- BUILT: twenty boundary/contract test files, one freshness regression fix.
- CHANGED: tests, `vulnassess/intel_status.py`, quality tooling and documentation.
- DECIDED / DECISIONS: preserve whole-package scope and raise the floor only
  after clean verification; QA-95-01 rejects percentage inflation shortcuts.
- EVIDENCE: local commands/output above; external integrations tested with mocks.
- DEFERRED: real-service and expert validation require separate evidence; not
  represented as completed by this engineering-quality increment.
- NEXT: remote CI and human review; no automatic merge or push.
