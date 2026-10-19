# Coverage follow-up: saved intelligence integrity — 11 October 2026

## Design and scope

Serves PROJECT.md stages 4 (preserved canonical evidence), 6 (intelligence) and
7 (reporting), plus evaluation reproducibility. A later report must not accept a
corrupt or incorrectly bound saved snapshot merely because its hash is valid.

Added seventeen synthetic regression cases in
`tests/synthetic/test_synthetic_history_integrity.py`. They exercise the real
history implementation with an isolated in-memory SQLite database, not a mocked
history reader. No real scanner/feed/model evidence is manufactured or claimed.

The tests cover:

- Malformed JSON and non-object snapshots, even with matching content hashes.
- Unknown schema versions, incorrect run IDs and invalid snapshot fields.
- Rejection of a corrupt latest revision without fallback to a valid older one.
- Refusal to append over invalid history, preserving existing stored rows.
- Explicit disclosure when a native run has not captured intelligence.
- Canonical key ordering and new revisions for genuinely changed matching state.

All tested contracts already passed. No new behavior or runtime bug fix is
claimed. Authorization, raw evidence, deterministic scores, AI validation,
public interfaces, dependencies and the whole-package 95% floor are unchanged.

Decision: QA-95-02 in `decisions.md`. Rejected alternatives are trusting the
hash alone, silently using an older revision, or excluding code to raise coverage.

## Verification

VERIFIED focused command, using the installed Python 3.12 interpreter:

```text
python -m pytest -q -p no:hypothesispytest tests/synthetic/test_synthetic_history_integrity.py tests/test_run_history.py
29 passed in 4.40s
```

VERIFIED static checks:

```text
python -m ruff check .
All checks passed!
python -m ruff format --check .
223 files already formatted
python -m pyright
0 errors, 0 warnings, 0 informations
```

The workstation-specific `-p no:hypothesispytest` disables the optional plugin
blocked by Windows App Control, not project tests. No dependency was downloaded.

VERIFIED clean whole-package run (no `--cov-append`):

```text
python -m pytest -q -p no:hypothesispytest --cov=vulnassess --cov-fail-under=95 --durations=5
TOTAL                                  9781    466    95%
Required test coverage of 95% reached. Total coverage: 95.24%
1332 passed, 510 subtests passed in 238.96s (0:03:58)
```

VERIFIED delta from the saved baseline: seventeen additional test cases,
unchanged 9,781-statement denominator, six fewer missing statements (472 to 466),
and 95.17% to 95.24% aggregate statement coverage. `run_history.py` increased
from 60/66 to 66/66 covered statements, or 100% statement coverage. This is not
a claim of full branch coverage or tamper resistance against an attacker who
can replace both data and hashes with different valid content.

## Limits

NOT RUN: live scanners, publisher feeds, providers and remote CI. This increment
checks saved-state contracts locally; it does not certify those integrations or
measure model accuracy, ranking quality or project completeness. No real fixture
is required for these pure history tests; independently captured lab and expert
evidence remains necessary for the research claims.

Next useful verification targets are failure recovery in the live-assessment
pipeline and actual branch coverage, without weakening any fail-closed checks.

## Increment handoff

- STATUS: VERIFIED locally; no remote verification or push in this increment.
- BRANCH / COMMIT: `codex/coverage-95`; local history-integrity test increment.
- GATE: 1,332 passed, 510 subtests passed, zero failures/skips, 95.24%; static
  check outputs quoted above.
- BUILT: seventeen saved-history regression cases.
- CHANGED: `tests/synthetic/` and `docs/`; no runtime changes.
- DECIDED / DECISIONS: test existing fail-closed semantics rather than change
  contracts or inflate coverage; QA-95-02.
- EVIDENCE: real local SQLite/code execution with synthetic contract inputs.
- DEFERRED: lab accuracy and expert studies need independent real evidence;
  their absence does not block testing this saved-state contract.
- NEXT: live-assessment failure recovery and branch-level verification.
