# Phase 0: type-gate and remediation correctness

Date: 7 October 2026. Base revision: `366188f`.
Branch: `codex/phase-zero-correctness`.

Implementation commits: `9c2a291` (self-defence payload) and `f988259`
(remediation boundaries and AI-case metadata).

## Scope

This increment repairs the two baseline defects recorded in the implementation
audit. It does not implement the later persistence or reasoning-agent phases.
No target scans, model requests, scope changes, dependency upgrades or remote
pushes are required for these fixes.

## Self-defence payload

Pyright 1.1.411 reproduced an optional-subscript error at the device-check
coverage assignment in `live_assessment.py`. The collected device payload starts
as `None`, and the separate self-defence flag did not narrow that value.

The write path now checks the actual collected value and reads its limitations
directly. The existing self-defence integration regression additionally checks
the saved case, scanner-coverage limitations and device-check artifact. This
preserves evidence when the AI provider is unavailable. No diagnostic suppression
or reduced quality gate was added.

## Vulnerable boundaries are not fixed-release claims

Previously, both `versionEndIncluding` and `versionEndExcluding` became the same
`version_end` string. The report then told users to upgrade to that version or
later. Two regression cases reproduced this defect through the real matcher:
one scanner-explicit CVE and one CPE-range match.

The enrichment JSON now includes `version_end_inclusive`:

- `true`: the selected upper bound includes that version.
- `false`: the selected upper bound excludes that version.
- `null`: semantics are absent, ambiguous or unavailable in a legacy record.

Both matching paths retain this metadata, and the AI case includes it alongside
the version boundary. Existing JSON without the field remains readable. Invalid
non-boolean metadata is treated as unknown, not coerced to a boolean. The field
was appended to the dataclass to retain existing positional-argument order.

The report states the observed product, boundary and boundary semantics and asks
the user to verify the vendor-fixed release before upgrading. Available patch
references remain attached. An exclusive end is not, by itself, enough to claim
that every later release or another release branch fixes the issue; therefore
the previous unconditional "or later" recommendation is removed for both kinds
of bound. No next version is fabricated.

This is an additive JSON change; no database migration or historical record
rewrite is performed. Previously generated reports are not retroactively edited.
Regenerating advice from older enrichment JSON explicitly reports unknown
boundary semantics until evidence is re-enriched.

## Verification

The focused inclusive-bound regressions failed before the fix and passed after
it. Additional regressions cover exclusive, absent and ambiguous boundaries,
legacy JSON, malformed metadata, JSON round trips, AI-case propagation and
canonical score invariance. Score comparisons exclude only the changed human
remediation text; all remaining score fields must remain identical.

Final local verification at application/test revision `f988259`:

- Windows, Python 3.12.10.
- Ruff 0.16.6 lint: passed; formatting: 192 files already formatted.
- Pyright 1.1.411: zero errors, zero warnings.
- pytest 9.1.1 / pytest-cov 7.1.0: **692 tests and 495 subtests passed**.
- Statement coverage: **86.21%**, above the unchanged 75% gate.
- Full test runtime: 343.93 seconds. The two slowest existing feature-ablation
  tests took approximately 54 seconds each under coverage.
- Added 19 regression cases: 16 remediation/matching/compatibility/scoring cases
  and three AI-case propagation cases. Existing self-defence assertions were
  strengthened as well.

Commands (using the project's Python interpreter):

```text
python -m ruff check .
python -m ruff format --check .
python -m pyright
python -m pytest -q -p no:hypothesispytest --cov=vulnassess --cov-fail-under=75 --durations=5
```

The unrelated auto-discovered Hypothesis plugin was disabled because Windows
App Control blocks it in this environment. No project tests were excluded.
The gate-tool versions above match the repository's CI pins.

There is no freshly measured pre-change coverage baseline for the original
revision, so no before/after percentage-point improvement is claimed. An
intermediate run passed 689 tests and 495 subtests, but the final run above is
the authoritative result after all changes.

Status: implemented, regression-tested and committed locally; not pushed,
merged, deployed or independently verified by GitHub CI. The planning and
verification documentation is committed separately from application changes.

## Remaining limitations

- Only Python 3.12 is installed locally. The Python 3.11/Linux CI matrix must
  still run against the final revision; local success is not a CI result.
- This change does not extract vendor-fixed releases from advisory prose.
- Historical finding/enrichment isolation is the next planned phase, not a
  capability delivered by this increment.
- No new live end-to-end scan or external AI-provider verification is claimed.
