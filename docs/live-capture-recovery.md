# Live capture recovery

## Contract (8 October 2026)

Task 1.3 adds read-only reopening of new live captures, including zero-findings
and self-defence cases. It does not replay scanners, refresh intelligence, restore
approval registries or replace the existing explicit Redis reanalysis action.

The current unique raw-evidence directory remains the storage boundary. Before
calling AI, save a hash-verified evidence-only review. After optional analysis,
append a final review referring to that exact baseline. Keep the case, manifest,
configuration hash, recorded intelligence metadata and canonical scores unchanged.
Publish files atomically and never overwrite an existing review. A crash before
the final review leaves the baseline usable; a corrupt final review must be
reported, not silently replaced by a successful-looking baseline.

New same-origin loopback GET routes:

- `/api/captures?page=1`: at most 20 records; integrity failures are explicit.
- `/api/captures/{id}`: verified schema-v1 record, `read_only: true`.
- `/captures` and `/captures/{id}`: accessible history and printable review pages.

Capture IDs are server-issued directory names, never caller-provided paths.
Readers reject traversal, symlinks, oversized files, unknown schemas and hash
mismatches. Reads perform no network requests or database writes. Existing local
workbench Host/Origin protections remain. A saved observation is not authority:
new scans still require current scope checks and new approvals.

Dates distinguish collection completion, intelligence recorded with the capture
(including publisher feed dates), and the AI analysis attempt. Opening a record
must not label any of them fresh. Existing captures without review metadata are
not silently backfilled from today's configuration or current feed cache.

`analysis_attempted_at` records final-review publication time, not the start of
the provider request. A baseline-only record displays "No completed analysis
recorded": an interrupted request may have reached the provider before the
process stopped. `intelligence_recorded_at` is receipt time, not a claim that a
fresh retrieval succeeded; individual publisher dates remain in `feeds_meta`.

## Implementation and usage

New live runs write `review-evidence.json` next to the existing `case.json` and
`manifest.json`, then append `review-final.json` when optional analysis returns.
The final receipt links to the baseline hash. Neither receipt modifies raw
scanner files or canonical scores. A save failure leaves scanning results intact
and exposes a persistence warning; a final-save failure retains the baseline.

After starting this branch's workbench, choose **Saved assessments** in the
workflow navigation, or **Open saved assessment · read-only** in a newly completed
live summary. The review shows context, coverage, recorded priorities, feed dates,
AI status, evidence and hashes. It is a separate read-only page, not a restored
live canvas. The API returns the same frozen result and payload after restart.

History is paginated at 20 records, with page numbers 1–500 and a maximum of
10,000 indexed captures. Ordering is explicitly by capture ID, not chronology.
Each record/file is limited to 8 MiB; a manifest can reference at most 20 files
with a combined 64 MiB read budget. Listing validates metadata; opening verifies
the raw evidence hashes. Invalid query shapes return 400; unavailable, oversized
or inconsistent records return 409 without exposing arbitrary filesystem paths.
The JSON detail endpoint deliberately exposes local evidence to the workbench
user; it is not a public share URL.

## Privacy and limits

Use existing local raw-capture retention; no new external service or telemetry.
Do not persist API keys, provider credentials, environment variables, plan approval
tokens or request registries. Preserve existing evidence until the owner removes
the capture directory; no automatic deletion is introduced. Files inherit the
local workbench directory's access controls; they are not encrypted backups.
Hashes detect accidental changes, not a local attacker replacing data and hashes.
The directory must be owner-controlled (concurrent hostile filesystem replacement
is outside the local-workbench trust model).

Application rollback leaves additive review files intact. Existing case/manifest
readers continue to work. PostgreSQL and core stored-run imports are unchanged.
Atomic publication uses hard links within the capture directory; NTFS was tested.
Other filesystems and power-loss durability have not been verified. No dependency
was added. Explicit Redis replay and recent-memory reanalysis remain separate;
this increment does not automatically persist their subsequent analysis results.

## Acceptance

1. Scan with mocked external tools, destroy application state, reopen the exact
   capture through a fresh application; evidence/intelligence/configuration hashes,
   scores and report content remain identical after later captures/cache changes.
2. Provider failure or interruption retains an evidence-only record. Traversal,
   tampering, malformed records and attempted overwrite fail closed. Reopening
   cannot restore approvals or invoke a scanner/provider.
3. UI lists saved records and renders dates, coverage, context, findings, priorities
   and recorded AI output without interpreting evidence as HTML. Verify real
   browser navigation, keyboard use and narrow layout on synthetic data only.

## Verification

Implemented locally at `6037960` on `codex/live-capture-recovery`. No real scan or deployment
is implied. The scanner and provider are mocked in integration tests; synthetic
records exercise the actual persistence, routes and browser rendering.

Twenty-three focused tests pass, covering restart reads, provider unavailability,
needs-review AI outcomes, interruption, save failure, immutable baseline/final receipts,
cross-capture score/intelligence isolation, unknown schema, hash mismatch,
traversal, symlink rejection, read budgets, HTML escaping and approval exclusion.
The final review found and corrected two regression cases: persistence warnings
were lost when the final summary was rebuilt; interrupted AI requests were
ambiguously labeled as never attempted.

Ruff lint and formatting pass (200 files); pinned Pyright reports zero errors and
warnings. An isolated headless Edge session verifies navigation, keyboard focus,
expandable evidence and no horizontal overflow at 320, 768, 1024 and 1440 pixels.
No browser console warnings/errors occurred; the screenshot was visually checked.
No existing browser profile or production server was used. Print CSS is included,
but print-preview/PDF output has not been manually verified.

Reproduction commands, from this repository:

```powershell
python -m pytest tests/test_capture_history.py -q -p no:hypothesispytest
python -m pytest -q -p no:hypothesispytest --cov=vulnassess --cov-fail-under=75 --durations=5
python -m ruff check .
python -m ruff format --check .
python -m pyright
# Use an isolated workbench serving synthetic captures, not a real scanner run:
python scripts/verify_capture_history_ui.py http://127.0.0.1:PORT data/verification/capture-history --channel msedge
```

Final full gate on 8 October 2026: **727 tests and 510 subtests passed in 369.10
seconds; 86.33% statement coverage**. Compared with the preceding SQLite slice:
23 additional tests, 10 additional executed subtests, and coverage increased from
86.28% by 0.05 percentage points. The 75% coverage requirement is unchanged.
The capture-history module has 89% statement coverage and its renderer 92%.

Runtime: Python 3.12.10, pytest 9.1.1, pytest-cov 7.1.0, Ruff 0.16.6 and Pyright
1.1.411. `no:hypothesispytest` disables an unrelated locally installed plugin
blocked by Windows App Control, not any project test. The first full-suite process
lost its tool session; its completion was not counted. These results come from a
fresh completed run, with the log and synthetic browser screenshot retained under
ignored `data/verification/capture-history/`. No evidence, credentials or generated
artifacts are included in the commits.

Python 3.12/Windows verification does not establish Python 3.11/Linux CI or live
provider acceptance. PostgreSQL history, reanalysis revisions and real approved
planner/follow-up acceptance remain separate tasks; no new agent was introduced.

## Follow-up: explicit replay intelligence provenance

The saved-CVE replay path intentionally attempts fresh intelligence and computes
new deterministic derivatives without changing its original capture. Its payload
must describe the intelligence actually used for those derivatives, not preserve
feed metadata copied from the historical input.

Review found two defects in that path:

- Copied `feeds_meta` survived both successful and failed refreshes. New scores
  could therefore be accompanied by old publisher dates/hashes.
- If matching failed after one finding succeeded, the partially assembled
  enrichment list survived the failure handler and could influence scoring even
  though the result said intelligence was unavailable.

The refresh now clears inherited metadata before attempting retrieval, records
the retrieved metadata only after matching succeeds, and discards partial matches
on the existing handled failure path. The scoring formula, explicit refresh
request, scope gate and original capture are unchanged. Failure still returns
native-severity priorities; it does not reuse old CVE enrichment as fresh data.

Regression tests reproduced all three failing cases before the fix: stale metadata
on success, stale metadata on outage, and a partial matching batch surviving an
error. Additional tests inject outages separately at NVD, EPSS and KEV using the
real synchronization/parsing/cache code with synthetic HTTP responses. They check
that the old cache is not partially replaced, the returned metadata is empty on
failure, and the input payload remains unchanged. The targeted replay, history
and online-intelligence suites pass **37 tests**. No publisher endpoint or target
was contacted; no browser layout changed.

Verification recovered and recorded on 9 October 2026: **731 tests and 510
subtests passed in 401.12 seconds; 86.33% coverage**. This adds four test cases
over the preceding increment and preserves its rounded coverage percentage and
the unchanged 75% gate. Ruff lint/format and pinned Pyright also pass. The durable
log is `data/verification/capture-history/replay-provenance-tests.log` (ignored by
Git); recovering the completed log avoided rerunning an unchanged suite after
the tool session ended. Verification remains Windows/Python 3.12, with synthetic
publisher responses rather than real provider or target calls.

This follow-up does not
implement PostgreSQL history or persist subsequent reanalysis revisions. A local
PostgreSQL/Docker runtime was not found during discovery; no remote database was
opened or migrated to substitute for an isolated verification environment.
