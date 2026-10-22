# VulnAssess UI

Privacy redaction (2026-10-19): personal usernames in historical local paths below are replaced with [redacted-user]. This does not claim those commands were rerun or change the original capture evidence.

## Helpy: evidence-linked report assistance - 2026-10-23

PROJECT.md stage 7 (Report), supporting evidence traceability rather than new
scoring, scans or model-authored report facts.

Helpy is opened with **Ask Helpy on a saved assessment report**, not on the
HarborDesk target site. It selects up to three existing source excerpts from the
saved capture. It cannot run scans, change a device or compute priorities.
Opening an HTML download does not enable the live assistant.

Select an available provider before asking. Cloud providers require explicit
sharing consent for the question and bounded report excerpts; changing provider
resets that consent. Dictation has separate consent because a browser speech
service may send audio externally. Text input works without microphone access.
No microphone or provider is contacted by the offline tests.

**Clear conversation**, **Close**, switching provider and leaving the page stop
waiting for the current reply. Late responses cannot refill a cleared transcript,
overwrite a newer request or speak after closing. A provider may still finish
work already accepted server-side; client cancellation is not proof that model
computation stopped. Invalid or mismatched responses are withheld as errors.

The source catalog keeps details for at most the first 12 findings and 12
priorities, and explicitly discloses this limit for larger captures. Whole-capture
counts and CVE availability are checked against every retained finding, not
just those first 12. Known HarborDesk verifier cases retain their reviewed
verification guidance and are not described as comprehensive DAST or generic
Nmap/Nikto detections. No unrecorded tool coverage is assumed.

The current checkout's runtime prerequisites and executed checks are recorded
under HELPY-CHECK-01 in [decisions.md](decisions.md). Offline unit/browser mocks
do not establish that a configured provider or microphone works in a real session.

## Publication checkpoint - 2026-09-22

PROJECT.md Stage 7. The user requested publication of the current work as-is
after rejecting the all-in-one page structure. This request is not acceptance
of that layout. The proposed Home, Explore, Workflow, Run Analysis and Assessment
page split has not been implemented; no further redesign is part of this push.
The quality-gate and real-model limitations recorded below still apply.

## Doors and local analysis - 2026-09-22

PROJECT.md Stage 7 (Report), supporting context and ranking auditability.
Decisions UI-27 through UI-29 record the latest request to restore parts of Doors
as a focused section and connect an explicit model-running section. This builds
on the explanatory website below; it does not restore the old Doors interface.

VERIFIED: the current preview was started with the existing read-only UI command:

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' -u -m vulnassess ui --config 'C:\Users\[redacted-user]\Downloads\fragmented\config' --db 'C:\Users\[redacted-user]\Downloads\fragmented\data\vulnassess.db' --run demo --port 0
VulnAssess: http://127.0.0.1:60133/
Read-only viewer. Press Ctrl-C to stop.
```

The review entry is `http://127.0.0.1:60133/?run=demo#project-doors`.
The new run section is `#project-run`. It runs the existing local analyst over
one or all recorded systems, not scanners, feed refresh, model training or score
recalculation. It requires an explicit target-list confirmation, uses sequential
requests and retains each response only in this tab. Stop after current prevents
later requests; it does not cancel ongoing inference. Source evidence, recorded
priority and synthetic/missing-data labels remain visible in the doors section.

### Section Verification

TESTED WITH MOCKS: focused UI checks and the full available suite completed:

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' -m pytest -q tests/test_ui.py::TestUiExport tests/test_ui.py::TestUiAssets tests/test_ui.py::TestUiContract::test_workflow_graph_is_grounded_and_read_only
33 passed in 7.38s
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' -m pytest -q -ra
270 passed, 353 subtests passed in 22.04s
```

Full-suite counts: 0 failed, 0 skipped; no skip reasons. The synthetic Node check
covers sequential requests, duplicates, stop, failure, mismatched identities and
unknown citations. It does not establish real model or scanner integration.

VERIFIED: Playwright selection/click checks opened a finding's workflow record
and restored the exact host/finding on return. An actual `page.evaluate()` probe
returned this scoped result, without requesting analysis:

```json
{"host":"172.28.0.10","finding":"5bd0e6e7-fbc5-5ecd-b39a-ab87c7ea191a","returned":"5bd0e6e7-fbc5-5ecd-b39a-ab87c7ea191a","inspectorOpen":false}
```

VERIFIED: browser layout inspection measured `width:1440, height:900,
scrollWidth:1421`, with `overflow:[]` for both `project-doors` and `project-run`.
Live section screenshots were inspected. Empty `verify` records returned
`runDisabled:true`, `doorCount:0`, and
`"A stored assessment with recorded systems is required."` A direct-link count
defect was repaired: after reloading, host `172.28.0.11` had
`findings:4, expected:4, previewHost:"172.28.0.11"`.

TESTED WITH MOCKS: the browser batch check replaced `window.fetch` before any
start action; the replacement never forwarded requests. It awaited DOM changes
with a MutationObserver, not animation-frame polling. Exact result excerpts:

```json
{"reviewed":3,"success":"3 responses received / 0 failed / 0 not started","failure":"0 responses received / 1 failed / 2 not started","stopped":"1 responses received / 0 failed / 2 not started","escaped":true,"scoresUnchanged":true}
{"canceledCalls":0,"confirmedCalls":1,"dialogClosed":true}
```

The success case made three fake requests, the failure case one, and the stopped
case one. Double-clicking start did not duplicate a request. Markup-like model
text remained text. After the final confirmation-open guard, a canceled dialog
made zero fake requests and a confirmed double click made exactly one. The shared
workflow client separately returned the fake error
`"Synthetic unavailable response; endpoint not contacted."`, with
`calls:1, retryEnabled:true, target:"172.28.0.11"`.

### Browser Interception Incident

VERIFIED: an earlier browser test used `page.route('**/api/analyst/**', ...)`,
clicked the confirmation control, then timed out waiting for completed states.
That interception did not protect the request. The subsequent queue inspection
returned `"0 responses received / 1 failed / 2 not started"` and the actual error:

```text
Ollama did not answer at http://127.0.0.1:11434/api/tags: URLError. A human must run: ollama serve   and   ollama pull llama3.2:3b
```

This was an unintended real local endpoint request, not a mocked test. No
inference result was produced. Endpoint-based execution tests were stopped;
later browser checks used the non-forwarding fetch fake described above.
The error's suggested download command was **not run by the agent**.

MISSING: a responding approved local Ollama service at
`http://127.0.0.1:11434`; a human must start the approved service before trying
real analysis. Model installation was not inferred from this connection error.
NOT RUN: further live model checks, model downloads or scanner execution.
No successful model-integration claim is made for this increment.

### Offline and Read-Only Checks

VERIFIED: the existing ignored review export was regenerated:

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' -m vulnassess ui --config 'C:\Users\[redacted-user]\Downloads\fragmented\config' --db 'C:\Users\[redacted-user]\Downloads\fragmented\data\vulnassess.db' --run demo --export 'reports/ui-project-review.html'
UI export: C:\Users\[redacted-user]\Downloads\fragmented\reports\ui-project-review.html
```

VERIFIED: opening that local file, selecting a door and dispatching submit/start
events returned `offline:true, runDisabled:true, confirmationOpen:false,
visibleWorkflowLinks:0, blockedFetch:[]`. No HTTP(S) request or JavaScript error
was observed. The selected offline host was `172.28.0.11`; model actions stayed
disabled while recorded doors remained inspectable.

VERIFIED: a fresh loopback smoke preserved actual stored scores and database bytes:

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' scripts/check_ui_server.py --run demo
SCORES: 6 API records equal stored JSON
DATABASE: SHA-256 unchanged
SERVER: stopped
UI LOOPBACK SMOKE PASSED
```

VERIFIED: `git diff --name-only -- vulnassess/analyst.py vulnassess/scoring.py
vulnassess/context.py vulnassess/schema.py config models requirements.txt pyproject.toml`
returned no output. No backend model, scoring, schema, configuration or dependency
file was changed. Editor diagnostics for touched source/test files reported
`No errors found`; Pylance syntax checks for presentation and export also passed.

### Section Increment Status

STATUS: implemented for desktop review, not formally gate-certified.
BRANCH / COMMIT: VERIFIED by `git status --short --branch` and
`git rev-parse --short HEAD`: `audit-no-assumptions`, base `8e3d81c`, uncommitted.
GATE: MISSING prerequisites; the existing gate command returned exit 1:

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' scripts/check.py
MISSING ruff lint: ruff is not installed; a human must provision it
MISSING ruff format: ruff is not installed; a human must provision it
MISSING pyright: pyright is not installed; a human must provision it
MISSING pytest + coverage: pytest_cov is not installed; a human must provision it
GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright, pytest + coverage
```

Source coverage remains unmeasured; the 75% floor is not certified. MISSING:
human-captured Nikto JSON under `tests/fixtures/nikto/` with capture date, command,
authorized target and provenance row; its README still lists `_(none yet)_`.

BUILT: recorded doors, exact workflow round trips, reviewed selected/all-system
analyst queue, per-system responses and failure/stop states. CHANGED:
`vulnassess/ui/`, `tests/test_ui.py`, `tests/synthetic/`, and existing `docs/`.
DECIDED: a contained evidence depiction and reuse of the explicit AI-01 endpoint,
not the former Doors interface or new model/pipeline execution APIs.
DECISIONS: UI-27, UI-28, UI-29. EVIDENCE: quoted commands and browser results above.
DEFERRED: the globe and unrelated execution capabilities are not required to
inspect context or test ranking; missing fixtures and expert judgments are not
substituted by interface demonstrations. NEXT: desktop review, approved local
Ollama service for real inference, and reviewed quality tools for formal acceptance.

## Project explanation website - 2026-09-22

Stage ownership: PROJECT.md Stage 7 (Report), supporting context and ranking
auditability. Decisions UI-23 through UI-26 record the user-directed change from
technical-first entry to understanding and exploring the project. Earlier UI
sections below are historical; the accepted independent workflow is retained.

VERIFIED: the current live preview is `http://127.0.0.1:55291/?run=demo`.
Playwright navigation and `page.evaluate()` returned the six project sections
`["hero","project-story","project-workflow","project-analyst","project-outcomes","project-questions"]`,
three stored target options, five FAQ disclosures, `technicalDisplay: "none"`,
`faults: []` and `analystCalls: []`. The new sections explain the optional local
analyst, the priority/reason/source outputs and the project's limits. Target
selection links into the existing workflow; it does not request analysis.

### Regression and Safety

TESTED WITH MOCKS: the focused renderer/export/boundary checks and then the full
available suite passed. Full-suite counts: 267 passed, 0 failed, 0 skipped, with
353 passing subtests and no skip reasons. Synthetic and mocked cases establish
only their tested logic, not real scanner, intelligence or model integrations.

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' -m pytest -q tests/test_ui.py::TestUiExport tests/test_ui.py::TestUiAssets tests/test_ui.py::TestUiModel::test_loading_page_does_not_run_local_analyst
30 passed in 8.43s
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' -m pytest -q -ra
267 passed, 353 subtests passed in 23.94s
```

TESTED WITH MOCKS: Playwright intercepted `**/api/analyst/**` before the explicit
Analyze action. Selecting a recorded host, navigating to its analyst node,
opening/closing the FAQ with Enter, requesting the mocked failure, changing host
and returning to the project produced this output. No real Ollama request was
made by this check.

```json
{"faqOpen":true,"faqClosed":true,"target":"172.28.0.10","passiveModelCalls":0,"explicitMockedCalls":1,"error":"Model unavailable in this mocked check. No result substituted.","retryEnabled":true,"hostIsolated":true,"scoresUnchanged":true}
```

VERIFIED: the fresh loopback smoke compared the actual API scores and database
bytes, without contacting a scanner or model. Selected output:

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' scripts/check_ui_server.py --run demo
GET / -> 200
GET /workflow -> 200
SCORES: 6 API records equal stored JSON
DATABASE: SHA-256 unchanged
SERVER: stopped
UI LOOPBACK SMOKE PASSED
```

VERIFIED: the offline export was opened as a local file in the browser; an HTTP(S)
route guard recorded no requests. The actual export command and browser output:

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' -m vulnassess ui --config 'C:\Users\[redacted-user]\Downloads\fragmented\config' --db 'C:\Users\[redacted-user]\Downloads\fragmented\data\vulnassess.db' --run demo --export 'reports/ui-project-review.html'
UI export: C:\Users\[redacted-user]\Downloads\fragmented\reports\ui-project-review.html
```

```json
{"initial":{"offline":true,"disabledTarget":true,"visibleWorkflowLinks":0,"artEmbedded":true,"step":"0","faqCount":5},"final":{"step":"2","analystNote":"Offline snapshot. Local model requests are unavailable here."},"network":[],"faults":[]}
```

VERIFIED: desktop browser probes found no horizontal text overflow in the new
outcomes/FAQ sections. Keyboard Tab focused `project-analyst-open` with
`focusVisible: true` and `outline: "solid"`; reduced-motion emulation returned
`transition: "0s"`. The measured wide-desktop viewport was 2548x1591 with
`scrollWidth: 2529`; the earlier main-page check measured 1440x900 with
`scrollWidth: 1421`. These are scoped checks, not a complete accessibility audit.

VERIFIED: the existing local Edge capture helper now supports the desktop project
opening. The saved [project introduction](ui/screenshots/project-introduction.png)
was opened and inspected; it is presentation of the labelled synthetic run, not
real scan or model evidence.

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' scripts/capture_ui_phase2.py --project --run demo
CAPTURED: docs/ui/screenshots/project-introduction.png (1600x1000; 290066 bytes)
SCREENSHOT SERVER: stopped
```

NOT RUN: acceptance of saved scrolled-section screenshots. Both headless and
direct browser capture attempts produced blank artifacts despite live DOM and
interaction checks. Those two newly generated blank files were removed; only
the inspected opening-page capture is retained. Mobile-specific review is outside
this increment at the user's request.

### Remaining Gate

MISSING: Ruff lint/format, Pyright and pytest-cov. Source coverage is unmeasured;
the 75% floor and full quality acceptance are not certified. The required Windows
gate entry point returned exit 1, without provisioning anything:

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' scripts/check.py
MISSING ruff lint: ruff is not installed; a human must provision it
MISSING ruff format: ruff is not installed; a human must provision it
MISSING pyright: pyright is not installed; a human must provision it
MISSING pytest + coverage: pytest_cov is not installed; a human must provision it
GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright, pytest + coverage
```

MISSING: human-captured Nikto JSON under `tests/fixtures/nikto/`, with a capture
date, command, target and authorization row in its README; that table still says
`_(none yet)_`. The synthetic example is not a real fixture. MISSING: approved
local `cobe` renderer and its reviewed dependency artifacts. The user deferred
the globe only, not the explanatory website.

NOT RUN: live scanners, real Ollama inference or expert evaluation for this UI
increment. Examples cannot establish the ranking-quality research claim.

### Project Increment Status

STATUS / BUILT: VERIFIED by the quoted browser checks: explanatory entry, guided
stored-record comparison, workflow links, target chooser, outputs and FAQ are
available for review. BRANCH / COMMIT: VERIFIED by `git status --short --branch`
and `git rev-parse --short HEAD`: `audit-no-assumptions`, base `8e3d81c`, uncommitted.
GATE: MISSING as listed above; pytest results are TESTED WITH MOCKS, not a green
complete gate. CHANGED: VERIFIED by `git diff --stat` and `git status --short`:
`vulnassess/ui/`, `tests/`, the existing capture helper under `scripts/`, and
`docs/` including screenshots. `git diff --name-only -- vulnassess config models requirements.txt pyproject.toml`
returned only `vulnassess/ui/` paths; scoring, model, configuration and dependency
files were not changed.

DECIDED: project-first explanation with a native offline adaptation, not another
technical dashboard or unapproved React migration; preserve the explicit analyst
boundary and defer only the missing globe. DECISIONS: UI-23, UI-24, UI-25, UI-26.
EVIDENCE: commands, outputs and scoped browser results above. DEFERRED: the globe
is decorative; real fixtures and expert outcomes remain separate research
prerequisites, so no substitutes are needed to review this presentation.
NEXT: user review of the desktop sections; a human must provide reviewed Ruff,
Pyright and pytest-cov before formal quality acceptance.

## Palette refinement - 2026-09-22

PROJECT.md Stage 7; decision WF-04. The user accepted the workflow layout and
requested a less dark background. This follow-up changes only workflow palette
tokens: neutral charcoal surfaces, brighter tiles and connectors, softer shadows.
The graph, filters, inspector, responsive views and assessment theme stay as-is.

TESTED WITH MOCKS: the focused palette/asset suite passed, with zero failures and
zero skips (no skip reasons); these tests do not validate real integrations.

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' -m pytest -q tests/test_ui.py::TestUiAssets
9 passed in 2.38s
```

VERIFIED: `page.reload()` followed by `page.evaluate()` returned workflow background
`#24262b` and surface `#2c2f35`, with 18 nodes at 1600x1000 and `scrollWidth: 1600`.
Computed token contrast ratios (primary/secondary text) were `13.52/7.79` on the
canvas, `11.98/6.91` on the panel, and `10.18/5.87` on the soft surface. These
measurements cover those token pairs, not a complete accessibility audit.
`page.setViewportSize({width:312,height:675})` under the calibrated browser zoom
then returned `width:390, height:844, scrollWidth:390, mode:stages, nodes:18`.

VERIFIED: existing captures were refreshed using the installed local browser:

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' scripts/capture_ui_phase2.py --workflow --run demo
CAPTURED: docs/ui/screenshots/workflow-overview.png (1600x1000; 284864 bytes)
CAPTURED: docs/ui/screenshots/workflow-inspector.png (1440x1000; 230572 bytes)
CAPTURED: docs/ui/screenshots/workflow-analyst.png (1440x1000; 222408 bytes)
CAPTURED: docs/ui/screenshots/workflow-narrow.png (500x900; 96779 bytes)
SCREENSHOT SERVER: stopped
```

MISSING: Ruff lint/format, Pyright and pytest-cov; coverage remains unmeasured.
The required Windows gate equivalent was rerun and returned exit 1:

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' scripts/check.py
GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright, pytest + coverage
```

MISSING: human-captured Nikto JSON under `tests/fixtures/nikto/` with a provenance
row in its README. NOT RUN: another full-suite run, scanner/model execution, or
template exploration; this follow-up is limited to palette values.

STATUS: lighter preview available; formal gate incomplete. BRANCH / COMMIT:
`audit-no-assumptions` / base `8e3d81c`, uncommitted. GATE: results above.
BUILT: no new functionality. CHANGED: `vulnassess/ui/static/tokens.css`, `docs/`
and existing `docs/ui/screenshots/`. DECIDED: lighten the accepted dark design,
not switch themes or alter layout. DECISIONS: WF-04. EVIDENCE: commands and browser
measurements above. DEFERRED: missing real inputs and full gate tooling do not
prevent this visual review or justify inventing research evidence. NEXT: review
the refreshed workflow; approved tool provisioning is required for gate acceptance.

## Integration Card workflow review - 2026-09-22

Stage ownership: PROJECT.md Stage 7 (Report), supporting context and risk-ranking
auditability. Decision WF-03 records the user's selection of
[Integration Card by ShadcnSpace](https://21st.dev/@shadcnspace/components/integration-card)
and dark appearance after a design comparison. Only this reference is approved;
the remaining gallery is a separate, user-led review.

The chosen adaptation preserves the directional graph instead of copying the
reference's central marketing hub. Dark raised icon tiles, selected dependency
traces, a compact toolbar and a Canvas / Stages switch are presentation only.
Narrow screens default to the stage list; an explicit choice persists across
resizing within the page. All 18 stages remain available. State labels still
distinguish stored records from missing outputs, and the synthetic label remains
visible. The assessment pages and their offline export are not redesigned.
No package or template installation is part of this increment; reference install
commands were **not run by the agent**.

### Redesign Verification

TESTED WITH MOCKS: the full available suite completed with zero failures and zero
skips (no skip reasons). Synthetic geometry assertions cover tile bounds and
non-overlap; existing tests retain stored-score fidelity and analyst isolation.
This does not verify real scanner, feed or model integration.

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' -m pytest -q -ra
259 passed, 353 subtests passed in 9.80s
```

VERIFIED: the actual loopback smoke kept the database and score records unchanged.
Selected output from the executed command:

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' scripts/check_ui_server.py --run demo
GET /workflow -> 200
GET /static/workflow.css -> 200
GET /static/workflow.js -> 200
GET /static/workflow-data.js -> 200
SCORES: 6 API records equal stored JSON
DATABASE: SHA-256 unchanged
SERVER: stopped
UI LOOPBACK SMOKE PASSED
```

VERIFIED: Playwright browser checks on the existing loopback viewer used
`page.setViewportSize`, `page.reload`, `page.evaluate`, `page.selectOption`,
`page.keyboard.press('Escape')`, and `page.emulateMedia`. The browser's 80% zoom
was calibrated before measuring CSS viewport dimensions. Returned probe output:

```json
{"desktop":{"width":1440,"height":900,"scrollWidth":1440,"scrollHeight":900,"overlaps":[]},"mobile":{"width":390,"height":844,"scrollWidth":390,"mode":"stages","nodes":18,"titleSize":"14px","listCanScroll":true}}
{"mobileInspector":{"open":true,"title":"Calculate risk","withinViewport":true,"filter":"172.28.0.10"},"returnFocus":"score","listScroll":{"before":1169.3333740234375,"after":1169.3333740234375},"canvasSwitch":"canvas","chosenModePreserved":true,"zoom":{"before":"69%","after":"82%"},"reducedMotion":"none","scoresUnchanged":true,"analystRequests":[]}
```

VERIFIED: `node --check vulnassess/ui/static/workflow.js` and `git diff --check`
each returned no output and exit 0. Editor diagnostics reported no errors for
the edited HTML, CSS and JavaScript files.

VERIFIED: existing screenshot artifacts were refreshed with local Edge. These
captures show the labelled synthetic demo, not real scan or model evidence.

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' scripts/capture_ui_phase2.py --workflow --run demo
CAPTURED: docs/ui/screenshots/workflow-overview.png (1600x1000; 259105 bytes)
CAPTURED: docs/ui/screenshots/workflow-inspector.png (1440x1000; 214805 bytes)
CAPTURED: docs/ui/screenshots/workflow-analyst.png (1440x1000; 209947 bytes)
CAPTURED: docs/ui/screenshots/workflow-narrow.png (500x900; 93619 bytes)
SCREENSHOT SERVER: stopped
```

MISSING: Ruff lint and format, Pyright, and pytest-cov. Source coverage is
unmeasured; the 75% gate is not certified. GNU Make is absent, so the existing
Windows gate equivalent was used. A human must provision the reviewed tooling;
no installation was attempted.

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' scripts/check.py
MISSING ruff lint: ruff is not installed; a human must provision it
MISSING ruff format: ruff is not installed; a human must provision it
MISSING pyright: pyright is not installed; a human must provision it
MISSING pytest + coverage: pytest_cov is not installed; a human must provision it
GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright, pytest + coverage
```

MISSING: a human-captured Nikto JSON artifact under `tests/fixtures/nikto/` and
its capture/authorization row in that directory's README. Its current provenance
table lists no real report; the synthetic example is not an integration fixture.
NOT RUN: live scanner/model execution and physical pointer-drag testing; the
redesign does not require executing a scan or analyst request, and pointer-pan
handlers are unchanged.

### Increment Status

STATUS: workflow implementation ready for user review; required gate incomplete.
BRANCH / COMMIT: `audit-no-assumptions`, based on `8e3d81c`, uncommitted.
GATE: results and missing prerequisites quoted above; no complete-gate claim.
BUILT: dark connected tiles, responsive stage list, selected-path motion and zoom
readout. CHANGED: `vulnassess/ui/static/`, `tests/synthetic/`, `docs/` and
`docs/ui/screenshots/`. DECIDED: retain directed dependencies rather than a literal
integration hub; reuse the local stack rather than add template dependencies.
DECISIONS: WF-03. EVIDENCE: regression, browser, smoke and capture output above.
DEFERRED: other templates and assessment-page redesign pending user review; real
Nikto capture and expert outcomes remain independent research prerequisites and
are not fabricated to style existing evidence. NEXT: review the workflow at
`http://127.0.0.1:8766/workflow?run=demo`; provision missing gate tools through the
approved process before formal acceptance.

## Workflow canvas - 2026-09-21

The user requested a separate Make-style visualization of the entire project,
not a restyle of the four-stage notebook. This serves PROJECT.md Stage 7 and
cross-cutting context/ranking/evaluation auditability. The workflow is a second
view of the existing records, not a second pipeline or a new scoring model.

```text
python -m vulnassess ui --run demo --port 8766
```

Open `http://127.0.0.1:8766/workflow?run=demo`. The assessment header also has an
Open workflow canvas link; Open assessment returns to the original view with the
same run. Existing offline exports remain unchanged and do not show the live link.

The canvas connects target/scope, Nmap/ZAP/Nikto imports, canonical records,
NVD/EPSS/KEV enrichment, context, optional role classification, deterministic risk,
priorities, recorded explanations, reporting, local analysis, expert evaluation
and re-scan comparison. Click a node for input, operation, output and source
records. Choose a target or a single finding to follow only its evidence.
The diagram supports pan, zoom, Fit, keyboard panning and an Escape-close inspector.

Node states mean exactly what they say: import recorded, stored output, current
configuration, output not attached, or local request status. Edges are data
dependencies, never execution evidence. Missing report/evaluation/re-scan artifacts
are not called completed. No queue metrics or synthetic scanner results are invented.
The current demo remains visibly labelled synthetic.

The Local AI analyst node reuses the already-existing `/api/analyst/<run>/<host>`
route. It requires an explicit Analyze target click and uses the whole selected
host, even when the diagram traces one finding. Merely opening the page, selecting
a node, filtering or refreshing does not invoke a model. The returned advisory
confidence is separate from deterministic risk. There is no analyst-to-scoring
edge, no timer-driven stage completion and no scanner action on this page.

The workflow has its own HTML, stylesheet and JavaScript modules, with neutral
circle nodes, local SVG icons and curved dependency lines. Its palette is scoped
in the common tokens file. It loads no framework, CDN or new dependency. It is a
live visualization; it is not included in the existing single-file export.

### Verification

VERIFIED: existing system Python was used for the full test suites because the
project venv lacks pytest. No dependency was installed or copied.

```text
& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' -m unittest -v
Ran 254 tests in 17.142s
OK

& 'C:\Users\[redacted-user]\AppData\Local\Microsoft\WindowsApps\python.exe' -m pytest -q
259 passed, 353 subtests passed in 15.47s
```

There were no test failures or fixture skips in those completed runs. The initial
venv unittest attempt had a missing-pytest import error, not a workflow assertion
failure. The available system interpreter resolved that test-execution blocker.

TESTED WITH MOCKS: new focused checks:

```text
& '.\.venv\Scripts\python.exe' -m unittest -v tests.test_ui.TestUiContract.test_workflow_graph_is_grounded_and_read_only tests.test_ui.TestUiContract.test_workflow_is_independent_and_does_not_run_analyst
test_workflow_graph_is_grounded_and_read_only (tests.test_ui.TestUiContract.test_workflow_graph_is_grounded_and_read_only) ... ok
test_workflow_is_independent_and_does_not_run_analyst (tests.test_ui.TestUiContract.test_workflow_is_independent_and_does_not_run_analyst) ... ok
Ran 2 tests in 0.277s
OK
```

The graph test checks every node and edge, preserves stored score values, narrows
context to the traced host, marks missing outputs and isolates analyst state by
run/host. It executes only pure JavaScript through the already-installed Node.

VERIFIED: live loopback smoke, `& '.\.venv\Scripts\python.exe' scripts/check_ui_server.py --run demo`:

```text
GET /workflow -> 200
GET /static/workflow.css -> 200
GET /static/workflow.js -> 200
GET /static/workflow-data.js -> 200
SCORES: 6 API records equal stored JSON
DATABASE: SHA-256 unchanged
SERVER: stopped
UI LOOPBACK SMOKE PASSED
```

VERIFIED: browser checks exercised node selection, stored risk inspection, zoom/Fit,
keyboard panning and the inspector at a device-emulated 390px width. Browsing
made no analyst request. `page.goto('/workflow?run=verify')` showed
`No stored output` and no host options beyond the empty selector;
`page.goto('/workflow?run=__workflow_missing_run__')` showed
`Records unavailable` after the expected HTTP 409. Both checks used the local
`http://127.0.0.1:8766` origin and restored the demo afterward.
TESTED WITH MOCKS: an intercepted analyst failure was
rendered as text, did not execute HTML-like content, permitted retry and did not
leak to another host. Pointer-pan logic was tested with synthetic pointer events
and mocked pointer capture. The integrated hidden tab delivered pointer moves but
not pointer-down through its mouse harness; physical dragging was not established
by that harness. NOT RUN: real Ollama inference and scanner execution in this change.

MISSING: the venv's pytest; Ruff lint/format, Pyright and pytest-cov in the checked
environments. Source coverage is unmeasured. The existing gate script reported:

```text
GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright, pytest + coverage
```

The blocked gate commands are `python -m ruff check .`,
`python -m ruff format --check .`, `python -m pyright`, and
`python -m pytest --cov=vulnassess --cov-fail-under=75`. Human-approved provisioning
is required before rerunning `python scripts/check.py`; no installation command
was run. VERIFIED: `git diff --check` returned no output (exit 0).

MISSING: a human-captured Nikto JSON file under `tests/fixtures/nikto/` with a
provenance row in [its README](../tests/fixtures/nikto/README.md), which currently
lists no real capture. Existing synthetic examples are not real-tool evidence.
The completed test run reported zero skips; that is not a Nikto integration claim.

### Screenshots

VERIFIED: `& '.\.venv\Scripts\python.exe' scripts/capture_ui_phase2.py --workflow --run demo`
uses installed Edge and an ephemeral loopback viewer. It only reads records and
opens node inspectors; it never clicks Analyze target.

| View | Image | Size |
| --- | --- | --- |
| Entire workflow | [Workflow overview](ui/screenshots/workflow-overview.png) | 1600x1000 |
| Stored risk inputs | [Score inspector](ui/screenshots/workflow-inspector.png) | 1440x1000 |
| Optional local analysis | [Analyst inspector](ui/screenshots/workflow-analyst.png) | 1440x1000 |
| Narrow inspector | [Narrow workflow](ui/screenshots/workflow-narrow.png) | 500x900 |

### Increment status

STATUS: visualization implemented and left running locally; no model-quality or
fully green quality-gate claim. BRANCH / COMMIT: `audit-no-assumptions` based on
`33f1293`; changes uncommitted. GATE: available tests pass as quoted above;
lint/type/coverage prerequisites remain MISSING.

BUILT: independent workflow canvas, evidence inspector, target/finding tracing
and a clearly separate existing analyst action. CHANGED: `vulnassess/ui/`,
`tests/`, `scripts/`, `docs/`. DECIDED: data dependencies and recorded states over
animated progress theatre; reuse backend contracts over new pipeline execution.
DECISIONS: WF-01 and WF-02 below in the decision log. EVIDENCE: commands and
captures above. DEFERRED: real-model/scanner verification and attachment of
persisted report/evaluation/re-scan results; these do not prevent inspection of
stored context and ranking evidence. NEXT: user review of the new canvas.

## One-interface consolidation - 2026-09-19

This section records the earlier consolidation, before the later workflow request.
The four-stage workbench remains the assessment renderer. The synthetic
simulation now builds a labelled assessment and exports this same renderer; the
`visualize` command is a compatibility alias for the same export path. The historical
eight-stage replay remains unreferenced source history, not a second product. The
printable assessment report remains a report, not a second UI.

The active Evidence stage uses explicit finding cards (scanner, stored band, title,
CVE/native identity and endpoint) rather than the rejected door metaphor. The guided
action is "Trace one finding." Offline analytics use no inline style attributes or
JavaScript style mutation, so the hash-pinned CSP remains strict and animations work
without `unsafe-inline`.

The Risk stage uses a proof-first hierarchy inspired by TypeSafe AI's sequencing, not
its branding: a large thesis, oversized stored metrics, sparse technical framing and
one mechanism at a time. VulnAssess retains its own palette, typography, evidence
density and analyst navigation; no external visual assets or marketing copy are used.

## Resume checkpoint - 2026-09-13

The user requested a commit/push checkpoint and a pause. This is a work-in-progress
four-stage interface, not an accepted reference-parity release. Ownership remains
PROJECT.md Stage 7 (Report), supporting evidence auditability for context and risk.
The old [phase 1](ui-phase-1.md) and [phase 2](ui-phase-2.md) reports are historical.

The current UI is in the `vulnassess/ui/` package. `reports/visual-simulation.html`
is now a synthetic export of that same workbench.

## Run and export

```text
python -m vulnassess ui --run demo --port 8765
python -m vulnassess ui --run demo --export reports/ui-demo.html
```

The live address is `http://127.0.0.1:8765/`; Ctrl-C stops it. Use an unused port
if occupied. `--run-id` aliases `--run`. `--db` and `--config` accept existing
local inputs. With no selected run, the page provides a stored-run selector.
The single-file HTML opens directly from disk and has no external assets.

The local `demo` run is rebuilt from the existing labelled synthetic demo
fixtures when absent or stale; it is not recovered historical timing or real lab
evidence. The local database and generated assessment reports remain ignored and
are not included in the source checkpoint. A clean checkout needs its actual
local input artifacts; the UI never creates substitute records.

## What is built

| Surface | What it teaches | Current behavior |
| --- | --- | --- |
| Evidence | Facts start with observations | Stored hosts, explicit finding cards, scanner quotes, scope configuration and feed provenance |
| Context | Every inference needs a clue | Role, exposure, controls, confidence, source, manual tags and evidence |
| Risk | Same weakness can have different urgency | Shared-CVE comparison using stored scores, differing inputs, weights and a labelled browser-only sandbox |
| Priorities | Each priority can be inspected | Stored risk order, facets and an inspector retaining source identity |
| Inspector | Trace the result to its inputs | Recorded reason, score chain, context, supported fix references and provenance |
| Tour | Follow one finding across the stages | Six captions pinned to the lower-risk host of the first shared CVE |

The demo comparison displays stored 79.0/High and 100.0/Critical scores. This is
record fidelity, not evidence of improved triage. Palatino/system serif identifies
headings and inferred values; monospace identifies quoted data; sans identifies
labels. Severity uses the existing token colours. The live page loads
`workbench.css` and external `app.js`, not the retained phase-2 `entry.css`.

Hash state restores stages, filters and finding selection. Examples:

```text
#stage-priorities?band=High
#stage-risk?theme=dark
#stage-evidence?theme=light&tour=1
```

The inspector has explicit Escape handling and synchronizes with Back/Forward.
The tour only scrolls a target when needed. A missing model is irrelevant to
viewing the stored assessment: both temporary model routes remain withdrawn.

## Read-only boundary

Only GET is accepted. SQLite is opened with `mode=ro`, and the viewer does not
scan, enrich, score, evaluate or train. Stored-record routes do not invoke a
model; the later AI-01 analyst action is the explicit local-inference exception.
The old runtime helper is retained but not imported by the HTTP server.
All recorded scores stay separate
from sandbox output. A future shadow prediction must remain beside rule context
and be labelled as having no effect on scores.

The sandbox recomputes locally under its fixed banner: "Sandbox. Nothing stored
changes." It uses current configuration, not an invented historical weight set.
Its fixture lives under `tests/synthetic/`, not among real-capture fixtures.
The export embeds its data, stylesheet, JavaScript and arithmetic fixture, with
hash-based CSP and `connect-src 'none'`. Refresh is disabled for offline exports.

## Verified checks

VERIFIED: `python scripts/check_ui_cvss.py --generate` returned:

```text
PYTHON CVSS: 211 of 211 match
JAVASCRIPT CVSS: 211 of 211 match Python
SANDBOX FORMULA: 144 of 144 context/threat cases match Python
```

The 211 vectors are eleven fixed regression cases and 200 seeded valid vectors.
This establishes parity with the repository's Python implementation, not an
independent certification of CVSS. The 144 cases cover context/threat combinations.

VERIFIED: `python scripts/check_ui_server.py` returned:

```text
SCORES: 6 API records equal stored JSON
GET /api/model -> 404
GET /api/model/run -> 404
POST /api/model/run -> 405
DATABASE: SHA-256 unchanged
SERVER: stopped
UI LOOPBACK SMOKE PASSED
```

Browser checks exercised stage navigation, filtered reloads, the inspector,
Back/Forward, Escape handling, the six-step tour and sandbox reset/isolation.
The export was exercised from `file://` with HTTP(S) blocked; no request was
attempted. Simulated physical keypress delivery in the integrated browser was
inconsistent; the explicit Escape handler and native button click were checked.

VERIFIED: final checkpoint run, `python -m unittest -v`:

```text
Ran 235 tests in 13.327s
OK (skipped=2)
```

VERIFIED: final checkpoint run, `python -m pytest -q`:

```text
SKIPPED [1] tests\test_all.py:1035: fixture not provided: tests/fixtures/nmap/*.xml
SKIPPED [1] tests\test_all.py:1044: fixture not provided: tests/fixtures/zap/*.json
233 passed, 2 skipped, 342 subtests passed in 16.52s
```

VERIFIED: `python scripts/check.py` reported:

```text
GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright, pytest + coverage
```

Repeat the local checks with:

```text
python -m unittest -v tests.test_ui
python -m unittest -v
python scripts/check_ui_server.py
python scripts/check_ui_cvss.py
python scripts/check.py
```

MISSING at the last gate check: Ruff lint/format, Pyright and pytest-cov. A human
will provision them; do not install or download them. The UI's temporary
behavioral acceptance criterion does not claim a green full quality gate or
measured source coverage. Real Nmap and ZAP capture tests remain the two skips;
synthetic examples do not satisfy those capture requirements.

## Current screenshots

VERIFIED: `python scripts/capture_ui_phase2.py --workbench` created these local
Edge PNGs. Each linked file was opened for visual inspection. No images were
downloaded. The script name is retained from phase 2; `--workbench` selects the
current interface.

| View | Image | Capture dimensions |
| --- | --- | --- |
| Evidence | [Evidence screenshot](ui/screenshots/workbench-evidence.png) | 1280x900 |
| Context | [Context screenshot](ui/screenshots/workbench-context.png) | 1280x900 |
| Risk | [Risk screenshot](ui/screenshots/workbench-risk.png) | 1280x900 |
| Priorities | [Priorities screenshot](ui/screenshots/workbench-priorities.png) | 1280x900 |
| Inspector | [Inspector screenshot](ui/screenshots/workbench-inspector.png) | 1280x900 |
| Dark theme | [Dark screenshot](ui/screenshots/workbench-dark.png) | 1280x900 |
| Narrow layout | [Narrow screenshot](ui/screenshots/workbench-mobile.png) | 500x844 |

The 390px window-size capture was clipped because the browser reported a wider
viewport. The narrow PNG is therefore honestly labelled 500px; a separate device
emulation check used an actual 390px viewport with no page overflow.

NOT RUN: an accepted tour screenshot. Edge produced `workbench-tour.png`, but its
caption was clipped in the saved image even though live tour bounds fit. That
attempt is retained for diagnosis and is not a visual acceptance result. Recheck
the saved tour image after resuming; do not claim it passed or replace it with a
fabricated screenshot.

## Resume next

Review the current live UI with the user before another design change.

Refresh `reports/ui-verify.html` after the final JavaScript changes; the local
export generated earlier may predate the last tour/navigation fixes.

Resolve the tour capture framing and rerun the browser interactions. Do not
fix the known unrelated visual-simulation flake during UI work; report its
traceback if it recurs.

Obtain the authoritative reference before claiming exact text/visual parity:

```text
C:\Users\[redacted-user]\Downloads\fragmented\doors-reference.html
```

Keep missing data explicit. Feed ages, most stage totals, per-file import
timestamps/scanner versions, refusal history, modification rule names and
persisted evaluation/critical-queue metrics are not all stored. Do not derive
or copy them from reference placeholders to make a screen look complete.

The G25 Self-check is under the sandbox disclosure. A dedicated `#selfcheck`
screen, the score-travel scale/animation, and an existing report-of-record
link in the export still need a requirements review before claiming full
parity. UI-UPGRADE steps 2-6 have not been started as separate increments.

MISSING: exact reference parity, real `tests/fixtures/nmap/*.xml` and
`tests/fixtures/zap/*.json` with provenance, real Nikto captures and `data/feeds/`.
No research improvement or validated model accuracy is asserted by this UI.
