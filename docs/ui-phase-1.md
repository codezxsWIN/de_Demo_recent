# UI phase 1 evidence - 2026-09-09

Privacy redaction (2026-10-19): personal usernames in historical local paths below are replaced with [redacted-user]. This does not claim those commands were rerun or change the original capture evidence.

Stage 7 (Report); cross-cutting ranking/evaluation auditability. Only G1, G3,
G4, G5 and G8 were implemented. No goal is declared accepted while the required
quality gate remains incomplete. The approvals are UI-ADR-03 in decisions.md.

## Part 1 - Foundations

G1 VERIFIED - the separate approved smoke script served the index and API on
ephemeral loopback; unittest socket behavior is mocked, not live network evidence.

FILES: `vulnassess/ui/server.py`, `vulnassess/ui/static/index.html`,
`vulnassess/cli.py`, `scripts/check_ui_server.py`, `tests/test_ui.py`.

TESTED WITH MOCKS: `python -m unittest -v tests.test_ui`

```text
test_serves_index_and_api_on_loopback (tests.test_ui.TestUiServer.test_serves_index_and_api_on_loopback) ... ok
test_refuses_non_loopback_bind (tests.test_ui.TestUiServer.test_refuses_non_loopback_bind) ... ok
test_cli_selects_run_and_closes_on_interrupt (tests.test_ui.TestUiServer.test_cli_selects_run_and_closes_on_interrupt) ... ok
```

G3 TESTED WITH MOCKS - all requested route contracts are pinned against existing
stored demo records; unpersisted evaluation/diff/refusal results are explicitly
MISSING, not recalculated or silently replaced with empty successful records.

FILES: `vulnassess/ui/reader.py`, `vulnassess/ui/server.py`,
`docs/ui-contract.md`, `tests/test_ui.py`.

TESTED WITH MOCKS: `python -m unittest -v tests.test_ui`

```text
test_top_level_keys_are_pinned (tests.test_ui.TestUiContract.test_top_level_keys_are_pinned) ... ok
test_every_host_and_finding_key_is_pinned (tests.test_ui.TestUiContract.test_every_host_and_finding_key_is_pinned) ... ok
test_api_routes_have_explicit_contracts (tests.test_ui.TestUiContract.test_api_routes_have_explicit_contracts) ... ok
test_unknown_record_keys_are_rejected (tests.test_ui.TestUiContract.test_unknown_record_keys_are_rejected) ... ok
```

G4 TESTED WITH MOCKS - HTTP method rejection, prohibited-import checks and
write-denial tests passed; the real smoke also exercised POST/PUT/DELETE below.

FILES: `vulnassess/ui/reader.py`, `vulnassess/ui/server.py`, `tests/test_ui.py`.

TESTED WITH MOCKS: `python -m unittest -v tests.test_ui`

```text
test_only_get_is_served (tests.test_ui.TestUiServer.test_only_get_is_served) ... ok
test_ui_imports_no_network_or_subprocess (tests.test_ui.TestWalls.test_ui_imports_no_network_or_subprocess) ... ok
test_connection_is_read_only_and_never_creates_database (tests.test_ui.TestUiContract.test_connection_is_read_only_and_never_creates_database) ... ok
```

G5 TESTED WITH MOCKS - traversal, directory exposure, CSP, Host rebinding and
cross-origin rejection checks passed. Live traversal rejection is recorded below.

FILES: `vulnassess/ui/server.py`, `vulnassess/ui/static/index.html`, `tests/test_ui.py`.

TESTED WITH MOCKS: `python -m unittest -v tests.test_ui`

```text
test_traversal_is_refused (tests.test_ui.TestUiServer.test_traversal_is_refused) ... ok
test_csp_header_present (tests.test_ui.TestUiServer.test_csp_header_present) ... ok
test_rebinding_and_cross_origin_requests_are_refused (tests.test_ui.TestUiServer.test_rebinding_and_cross_origin_requests_are_refused) ... ok
```

G8 VERIFIED - the live API's six score objects equalled existing SQLite JSON;
no new scoring calculation was invoked. This does not establish research merit.

FILES: `vulnassess/ui/reader.py`, `tests/test_ui.py`, `scripts/check_ui_server.py`.

TESTED WITH MOCKS: `python -m unittest -v tests.test_ui`

```text
test_every_score_matches_sqlite (tests.test_ui.TestUiContract.test_every_score_matches_sqlite) ... ok
Ran 19 tests in 1.976s
OK
```

## Live read-only check

VERIFIED: `python scripts/check_ui_server.py`

```text
BOUND: 127.0.0.1:56930
GET / -> 200
GET /api/runs -> 200
GET /api/run/verify -> 200
SCORES: 6 API records equal stored JSON
GET /static/../../config/scope.yaml -> 404
POST /api/runs -> 405
PUT /api/runs -> 405
DELETE /api/runs -> 405
DATABASE: SHA-256 unchanged
SERVER: stopped
UI LOOPBACK SMOKE PASSED
```

VERIFIED: `python -m vulnassess ui --run verify --port 8765` subsequently started
the persistent viewer and printed:

```text
Doors: http://127.0.0.1:8765/
Read-only viewer. Press Ctrl-C to stop.
```

## Regression and gate

VERIFIED: the first `python -m unittest -v` run encountered an existing
visual-simulation report-write error, not a UI assertion:

```text
OSError: [Errno 22] Invalid argument: 'C:\Users\[redacted-user]\Downloads\fragmented\reports\visual-simulation-report.html'
Ran 205 tests in 19.847s
FAILED (errors=1, skipped=2)
```

VERIFIED: `python -m unittest -v tests.test_visual_simulation.TestVisualSimulation.test_repeated_visual_builds_are_byte_identical`

```text
test_repeated_visual_builds_are_byte_identical (tests.test_visual_simulation.TestVisualSimulation.test_repeated_visual_builds_are_byte_identical) ... ok
Ran 1 test in 6.920s
OK
```

VERIFIED: the unchanged full-suite rerun, `python -m unittest -v`, ended:

```text
OK (skipped=2)
```

VERIFIED: `python -m pytest -q`

```text
SKIPPED [1] tests\test_all.py:1035: fixture not provided: tests/fixtures/nmap/*.xml
SKIPPED [1] tests\test_all.py:1044: fixture not provided: tests/fixtures/zap/*.json
203 passed, 2 skipped, 309 subtests passed in 20.56s
```

VERIFIED: `python scripts/check.py` exited 1 and printed:

```text
MISSING ruff lint: ruff is not installed; a human must provision it
MISSING ruff format: ruff is not installed; a human must provision it
MISSING pyright: pyright is not installed; a human must provision it
MISSING pytest + coverage: pytest_cov is not installed; a human must provision it

GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright, pytest + coverage
```

MISSING: the selected Python environment needs reviewed/provisioned `ruff`,
`pyright` and `pytest_cov` before lint, format, typechecking and source coverage
can be accepted. No tool was installed; the 75% source-coverage floor is unchanged.

MISSING: genuine human-captured Nmap XML at `tests/fixtures/nmap/*.xml` and ZAP
JSON at `tests/fixtures/zap/*.json`, with capture provenance. Existing
`EXAMPLE-synthetic-*` files do not satisfy those capture gates. Genuine Nikto
captures in `tests/fixtures/nikto/` and `data/feeds/` remain absent; the viewer does
not fabricate or require fresh feeds to display the already-stored demo.

## Increment close

STATUS: MISSING - phase-1 acceptance blocked by gate prerequisites; later phases
have not started.

BRANCH / COMMIT: `audit-no-assumptions` / `e89252e`; phase-1 edits are uncommitted.

GATE: VERIFIED unittest rerun and pytest results above; MISSING Ruff lint/format,
Pyright and source coverage.

BUILT: read-only SQLite access, GET-only server and API, approved additive `ui`
command, socket-free tests, local input probe and real-loopback smoke script.

CHANGED: `vulnassess/` (additive CLI and new `ui/`); `tests/` (UI tests and suite
discovery); `scripts/` (two read-only checks); `docs/` (contract, decisions, report).

DECIDED: separate read-only connection over writable Store reuse; unavailable
stored results over invented metrics; separate live smoke over network unittests.
DECISIONS: UI-01 through UI-04 and UI-ADR-01 through UI-ADR-03 in decisions.md.

EVIDENCE: the commands and exact output excerpts above; synthetic-backed stored
records establish read-path fidelity, not parser accuracy or research improvement.

DEFERRED: all work after phase 1, including export, visual design and G40 storage,
per the requested phase stop. Existing missing captures/feeds do not prevent
read-only record-fidelity testing, but block genuine integration claims.

NEXT: human-provision the reviewed missing gate tools, rerun `python scripts/check.py`,
and obtain the user's reply before phase 2 (G10, G11, G9).

```text
OK (skipped=2)
```
