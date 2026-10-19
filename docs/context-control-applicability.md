# Finding-scoped context controls

## Purpose and scope

This increment repairs a context-ranking defect, not the scanner topology. A
host can expose several unrelated services. Seeing a Cloudflare or login signal
on its HTTP service does not establish protection for an SSH, Redis, or different
HTTP-port finding. The old host-wide Environmental mapping could grant that
unrelated finding a lower priority.

A synthetic pure-logic regression reproduced a risk change from 73.5 to 56.2
solely by adding an unrelated HTTP banner. The corrected score stays 73.5. Those
numbers are test outputs, not results of an external assessment or expert study.

The existing scanner paths, intelligence joins, role/exposure rules, formula,
weights, model validation, and original records are retained. No authorization,
dependency, database layout, public command, or fixed model signature changes.
No live scan, provider call, dependency download, or Git push is part of this
increment.

## Decision path

`context.detect_controls` retains its host observations. `scoring.score` creates
a separate finding-scoped view before applying the existing Environmental rules:

1. Only rule/manual context can enter canonical scoring, as before.
2. The profile host must match the finding host before any control credit.
3. Web controls need the finding's TCP port and an HTTP service fingerprint.
   If no fingerprint exists, an imported URL must identify the literal recorded
   IP and port; DNS aliases, credentials, malformed URLs, or other endpoints do
   not establish binding. This is a pure predicate, not a fetch or scope decision.
4. The control quote must be present in that finding's raw evidence. Another
   port's banner, another path's challenge absent from the finding record, or
   scanner title wording cannot supply the quote.
5. Confidence must meet the already configured threshold.
6. Authentication credit additionally requires a 401 status line and a
   `WWW-Authenticate:` signal in the finding record. A login keyword or 403 alone
   is insufficient. This is still a heuristic, not proof of CVE reachability.
7. TLS observations are scoped to the matching service, with that service's
   supporting banner in the derived view; the original host quote is retained
   separately in `observed_controls`. TLS and rate-limiting
   do not acquire new scoring weights in this increment.

The original profile is never modified. Pure counterfactual comparisons against
another host profile remain possible, but cannot borrow that host's controls.

## Persisted audit and output

The existing extensible `ScoreBreakdown.inputs` field now records:

- `context_policy`: `finding-scoped-controls-v1`;
- `observed_controls`: unchanged host-level observations;
- `controls`: the effective finding-scoped scoring view;
- `control_applicability`: status, reason code, supporting quote, source,
  confidence, host/port/protocol/URL, limitation, and applied metric when relevant.

Statuses distinguish `unknown`, `withheld`, `observed`, `eligible`, and `applied`.
Eligible does not mean applied: a native-severity fallback or a mapping without
that metric can retain an observation without using it to change a score.

The deterministic reason and model-facing rationale facts disclose withheld
controls. A scoped WAF signal is described as *mitigation unverified*, not proof
that the vulnerability is blocked. Offline HTML reports show a separate control
applicability table while preserving the raw host-context section. All table
content is HTML-escaped.

Historical scores without the new audit remain readable and are not silently
rescored. The original weights hash still identifies the weight configuration;
the added policy identifier identifies this applicability rule separately. A
new ranking execution is required to populate the audit on existing evidence.

## Verification

Tests are deliberately synthetic and network-free. They cover SSH/Redis
cross-service leakage, HTTP cross-port leakage, finding-bound versus unrelated
401 challenges, generic 403/login denial, title-only signals, confidence gating,
TLS scope, imported endpoint binding, profile immutability, explanation facts,
report escaping, and rejection of model-derived canonical controls. Adversarial
tests live in `tests/adversarial/test_control_boundary.py`.

The initial baseline passed Ruff lint but failed Ruff format on 18 files and Pyright on eight
existing errors in `analyst.py` and `live_assessment.py`. Existing recorded source
coverage was approximately 85.40%; the verification run uses an 85% floor rather
than reducing the project's required 75% floor.

**VERIFIED — initial regression gate execution:**

```text
python -m pytest -q -p no:hypothesispytest --cov=vulnassess --cov-report=term --cov-fail-under=85
551 passed, 480 subtests passed in 353.40s (0:05:53)
Required test coverage of 85% reached. Total coverage: 85.45%
python -m ruff check .
All checks passed!
```

The unrelated auto-loaded Hypothesis plugin is excluded because Windows App
Control blocks its native dependency; project tests and assertions are not
excluded. This initial execution is not a merge approval: the eight pre-existing
type errors and 18 formatting failures still need a separate gate-repair increment.
The final integrated gate is recorded after that repair.

**VERIFIED — gate-repair checks:**

```text
python -m pytest -q -p no:hypothesispytest tests/test_live_assessment.py tests/test_analyst.py tests/adversarial
139 passed, 15 subtests passed in 3.22s
python -m pyright
0 errors, 0 warnings, 0 informations
python -m ruff format --check .
169 files already formatted
```

The separate formatting cleanup touches 18 tracked Python files. Old source is
read with `git show HEAD:<path>`, new source with PowerShell `Get-Content`, and
both are parsed from stdin using Python's `ast.parse`/`ast.dump` (no Python file
reads or writes). Actual comparison output:

```text
{'files_compared': 18, 'semantic_AST_differences': []}
```

This establishes that those formatting-only diffs preserve the Python syntax
tree; runtime correctness is separately checked by the test suite. The coverage
guard rejects missing/non-dictionary metadata, boolean or negative counts, and
counts beyond the collected findings. Existing valid batch paths still pass.

**VERIFIED — final integrated gate, after the TLS provenance follow-up:**

```text
python -m ruff check .
All checks passed!
python -m ruff format --check .
169 files already formatted
python -m pyright
0 errors, 0 warnings, 0 informations
python -m pytest -q -p no:hypothesispytest --cov=vulnassess --cov-report=term --cov-fail-under=85 --durations=10
561 passed, 480 subtests passed in 372.53s (0:06:12)
Required test coverage of 85% reached. Total coverage: 85.59%
vulnassess/control_applicability.py: 45 statements, 0 missed, 100%
python -m vulnassess --help
usage: vulnassess ... {ui,import,scan,intel,research,enrich,context,rank,report,eval,two-machine,unify,rescan,explain,diff,model,visualize,demo}
```

No test failed or skipped in the final run. There are 38 additional regression
cases versus the prior 523-test suite. Coverage increased from the previously
recorded approximately 85.40% to 85.59%; this is coverage, not proof of expert
ranking quality. The measured slow tests are role-training/ablation tests, not
live scanners or provider calls; performance work remains a separate increment.

STATUS: this correctness/readiness increment is locally verified, not merged,
pushed, or a verified end-to-end assessment. BRANCH: `codex/context-control-applicability`.
BUILT: finding-scoped control decisions and a printable applicability audit.
CHANGED: context/scoring/explanation/report modules, pure/adversarial tests,
analysis metadata guards, design/decision docs, and separate mechanical formatting.
DECIDED: preserve immutable observations and capabilities, reject unsupported
control credit and coverage claims, retain existing formula and safety gates.
DECISIONS: CONTEXT-CONTROL-01/02/03 and CONTEXT-GATE-01/02.
EVIDENCE: commands and actual outputs above; synthetic/mock limits below.
DEFERRED: real mitigation validation, fresh independent scanner captures,
expert-ranking evaluation, canonical evidence fusion and additional AI agents.
These are not claimed as solved by this increment.
NEXT: review the human-approved scan-plan contract before implementing the next
AI increment; obtain the required real Nikto capture and independent labels.

**VERIFIED — local runtime smoke:** the task-owned loopback server on port 8770
was restarted from this checkout after checking that it had no established
connections. The separate port-8769 server was not stopped. Stored assessments
were not rescored or rewritten. An HTTP-only page request checks startup and
routing, not JavaScript rendering, scanner execution, or model inference.

```text
Invoke-WebRequest http://127.0.0.1:8770/workflow?run=scanme-2026-09-24
HTTP status: 200; Assessment workflow heading present: true
```

**TESTED WITH MOCKS:** scanner/provider/report integration paths in the suite.
**NOT RUN:** live scanner, live AI inference, browser walkthrough, expert-ranking
benchmark, and real parser verification against fresh independent captures. No
new real fixture was supplied for this increment; synthetic tests do not replace
the capture requirements documented in `tests/fixtures/nmap/README.md`,
`tests/fixtures/nikto/README.md`, and `tests/fixtures/zap/README.md`. In particular,
**MISSING:** an independently captured real Nikto JSON report with a completed
provenance row under `tests/fixtures/nikto/`; its README currently lists none.

## Known limits and next increments

- A same-finding header can still be spoofed. Quote alignment establishes
  provenance, not semantic mitigation or exploitability. Existing configured
  WAF/auth Environmental mappings remain explicitly heuristic.
- A host profile retains one detected quote per control; this can conservatively
  withhold another service's valid observation. A richer service-evidence graph
  should be a separately reviewed contract increment, not a silent schema change.
- Role and exposure remain rule-based; stale signals and contradictions need
  the approved context-reasoning increment.
- Multi-scanner unification remains available in its current preview path; this
  change does not silently promote AI candidates or merged groups to scored
  confirmed findings.
- No independent critic, additional agent, or model-derived scoring is added.
  Human-approved planning and bounded evidence requests must retain the requested
  incremental order and safety foundation.
- Expert-ranking accuracy, real parser fixtures, and local/cloud model comparison
  require independent authorized captures and human labels. Passing synthetic
  tests does not establish those research results.
