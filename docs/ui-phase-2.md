# UI phase 2 evidence - 2026-09-09

Stage 7 (Report): distinguish inference from evidence and make stored host roles
and finding bands legible. This increment is G10, G11, then G9 only. Behavioural
acceptance follows the human direction recorded in UI-05; the quality gate is
still MISSING, not silently treated as passed.

## Part 2 - Identity

G10 VERIFIED - token palette, local colour simulations and text-contrast guards
passed. Simulations are reproducible design checks, not universal perception evidence.

FILES: [tokens.css](../vulnassess/ui/static/tokens.css),
[generate_ui_swatches.py](../scripts/generate_ui_swatches.py),
[test_ui.py](../tests/test_ui.py), and the three
[colour-check SVGs](ui/colour-check/reference.svg).

VERIFIED: `python -m unittest -v tests.test_ui.TestUiAssets`

```text
test_no_hardcoded_colours_outside_tokens (tests.test_ui.TestUiAssets.test_no_hardcoded_colours_outside_tokens) ... ok
test_severity_colours_survive_simulations_and_text_contrast (tests.test_ui.TestUiAssets.test_severity_colours_survive_simulations_and_text_contrast) ... ok
test_simulated_swatches_are_reproducible_svg (tests.test_ui.TestUiAssets.test_simulated_swatches_are_reproducible_svg) ... ok
```

VERIFIED: `python scripts/generate_ui_swatches.py`

```text
GENERATED: docs/ui/colour-check/reference.svg
GENERATED: docs/ui/colour-check/protanopia.svg
GENERATED: docs/ui/colour-check/deuteranopia.svg
TEXT CONTRAST: all declared text/surface pairs >= 4.5:1
reference: minimum pairwise CIELAB distance 36.05 >= 15
protanopia: minimum pairwise CIELAB distance 18.34 >= 15
deuteranopia: minimum pairwise CIELAB distance 21.19 >= 15
```

G11 TESTED WITH MOCKS - selected-run entry markup contains every stored evidence
string in a source-labelled monospace block, separate from inferred-value styling.

FILES: [entry.py](../vulnassess/ui/entry.py),
[entry.css](../vulnassess/ui/static/entry.css),
[index.html](../vulnassess/ui/static/index.html),
[server.py](../vulnassess/ui/server.py), [test_ui.py](../tests/test_ui.py).

TESTED WITH MOCKS: `python -m unittest -v tests.test_ui`

```text
test_evidence_and_inference_have_distinct_typefaces (tests.test_ui.TestUiAssets.test_evidence_and_inference_have_distinct_typefaces) ... ok
test_evidence_is_escaped_and_not_interpreted_as_markup (tests.test_ui.TestUiExport.test_evidence_is_escaped_and_not_interpreted_as_markup) ... ok
test_evidence_strings_are_in_evidence_blocks (tests.test_ui.TestUiExport.test_evidence_strings_are_in_evidence_blocks) ... ok
```

NOT RUN: one-file export; it belongs to the later export phase. The named G11 test
uses the shared server-rendered markup, not a fabricated export implementation.

G9 VERIFIED - every configured role maps to one of four parseable local line
drawings; compact/large dimensions and stored-band door fidelity tests passed.

FILES: [drawings.py](../vulnassess/ui/drawings.py),
[shed.svg](../vulnassess/ui/static/buildings/shed.svg),
[office.svg](../vulnassess/ui/static/buildings/office.svg),
[vault.svg](../vulnassess/ui/static/buildings/vault.svg),
[cabinet.svg](../vulnassess/ui/static/buildings/cabinet.svg),
[door.svg](../vulnassess/ui/static/buildings/door.svg),
[entry.py](../vulnassess/ui/entry.py), [test_ui.py](../tests/test_ui.py).

VERIFIED: `python -m unittest -v tests.test_ui`

```text
test_buildings_and_doors_have_small_and_large_dimensions (tests.test_ui.TestUiAssets.test_buildings_and_doors_have_small_and_large_dimensions) ... ok
test_every_finding_door_uses_its_stored_band (tests.test_ui.TestUiAssets.test_every_finding_door_uses_its_stored_band) ... ok
test_every_role_has_a_building (tests.test_ui.TestUiAssets.test_every_role_has_a_building) ... ok
Ran 28 tests in 3.538s
OK
```

## Smoke evidence

VERIFIED: `python scripts/check_ui_server.py`

```text
BOUND: 127.0.0.1:54113
GET / -> 200
GET /static/tokens.css -> 200
GET /static/entry.css -> 200
GET /static/buildings/door.svg -> 200
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

## Screenshots

NOT RUN: saved PNGs from installed Edge. `python scripts/capture_ui_phase2.py`
was attempted and returned:

```text
NOT RUN: phase-2-desktop.png; Edge exit 0; PNG not captured
NOT RUN: phase-2-drawings.png; Edge exit 0; PNG not captured
NOT RUN: phase-2-mobile.png; Edge exit 0; PNG not captured
SCREENSHOT SERVER: stopped
```

The screen has a paper/ink notebook, a white masthead, system-sans inferred values,
monospace source-labelled quotes, actual host drawings with individual band-labelled
doors, a collapsible evidence ledger and one large drawing legend. Mobile stacks
the records. No screenshot is claimed to exist on disk. Live integrated-browser
inspection was supplementary, not proof of those absent PNG artifacts.

## Full suite and gate

VERIFIED: `python -m unittest -v`

```text
test_repeated_visual_builds_are_byte_identical (tests.test_visual_simulation.TestVisualSimulation.test_repeated_visual_builds_are_byte_identical) ... ok
Ran 214 tests in 26.421s
OK (skipped=2)
```

The known visual-simulation flake did not recur in this run and was not edited.

VERIFIED: `python -m pytest -q`

```text
212 passed, 2 skipped, 319 subtests passed in 24.64s
```

MISSING: genuine Nmap `tests/fixtures/nmap/*.xml` and ZAP
`tests/fixtures/zap/*.json` captures with human provenance, the two reported skip
reasons. Synthetic examples do not satisfy them. Real Nikto captures and
`data/feeds/` also remain missing; no new scan/feed evidence was generated here.

VERIFIED: `python scripts/check.py` exited 1 and printed:

```text
MISSING ruff lint: ruff is not installed; a human must provision it
MISSING ruff format: ruff is not installed; a human must provision it
MISSING pyright: pyright is not installed; a human must provision it
MISSING pytest + coverage: pytest_cov is not installed; a human must provision it

GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright, pytest + coverage
```

## Increment close

STATUS: VERIFIED - phase-2 behavioural acceptance criteria met; no full quality-gate claim.

BRANCH / COMMIT: `audit-no-assumptions` / `e89252e`; changes remain uncommitted.

GATE: MISSING Ruff lint/format, Pyright and pytest-cov; source coverage unmeasured.
VERIFIED unittest, live smoke and pytest outputs are pasted above.

BUILT: G10 tokens/simulated swatches, G11 evidence typography, G9 local role and
door drawings with one legend; no later-phase workflow.

CHANGED: `vulnassess/ui/` (entry renderer, drawings, styles and entry routing),
`tests/` (named checks), `scripts/` (swatches/capture and expanded smoke),
`docs/` (decision entries, UI guidance, contract clarification and this report).

DECIDED: central tokens and simulated separation over colour-only guesswork;
escaped server rendering over inline executable markup; one door per recorded
finding over a manufactured host severity.

DECISIONS: UI-05 through UI-09 in [decisions.md](decisions.md).

EVIDENCE: the executed commands and pasted output above. Synthetic-backed demo
checks show display fidelity and code paths, not real integration or research merit.

DEFERRED: Edge PNGs have the explicit NOT RUN alternative requested by the user;
quality tools await human provisioning. Later UI phases remain unstarted, so no
additional scoring, comparison, export, tour or evaluation claim is made.

NEXT: wait for the user's reply before phase 3 (G7, G15, G29, G30, G23).

```text
OK (skipped=2)
```
