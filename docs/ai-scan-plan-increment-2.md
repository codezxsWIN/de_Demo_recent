# Increment 2 — AI-assisted scan planning

Date: 2026-10-02. Serves PROJECT.md stages 1-2 and evidence coverage for RQ1/RQ2.

## What changed and why

The AI now has a pre-scan job: propose an ordered scanner path from server-held
prior evidence and user intent. It is no longer restricted to explaining the
finished run. A human can review each reason, aligned citation, confidence,
profile and timeout, remove the proposed web step, adjust timeouts, approve the
exact revision and execute it. Existing quick/manual runs, imports, intelligence,
context, scoring, analyst validation and reports remain available.

With no history, the allowed proposal is light Nmap discovery. On an exact
environment:test asset with prior observed HTTP evidence, bounded Nikto may
follow Nmap. A hint alone cannot establish an HTTP endpoint. Discovery can
motivate another proposal later; this increment does not silently adapt the plan
mid-run. Nessus remains imported evidence, not a newly automated Nessus API.

This does not force NVD/EPSS/KEV or scoring to execute with no CVE/findings.
It improves evidence selection, not the appearance of module completion.

## Interfaces and authority

- `POST /api/scan-plans/propose`: target, run_id, hints, provider, share_evidence.
  Returns a validated scan_plan.v1 draft; no scanner is launched.
- `POST /api/scan-plans/edit`: plan_id, expected plan_hash, plan. A validated edit
  resets authority to draft and creates a hash for changed content.
- `POST /api/scan-plans/approve`: plan_id and current plan_hash. Explicit approval
  is required; client-supplied approval fields are rejected.
- Existing live-run POST accepts plan_id and plan_hash together for a new scan.
  Reusing/replaying old capture data cannot consume a fresh scan approval.
- Exact loopback Origin and `X-VulnAssess-Action: scan-plan` guard the plan POSTs;
  reads never generate proposals. This is not remote or multi-user authentication.

The approval hash binds plan JSON, pinned literal IP, submitted target, current
scope configuration, evidence snapshot and versioned fixed profile mapping.
The registry holds at most 32 drafts for 30 minutes. Restart invalidates every
approval; approval consumption is atomic and one-use. A tool-order, target,
scope or budget deviation invalidates authority. Discovery and a requested-port
Nmap subprocess share the approved Nmap time limit. Each subprocess rechecks
the current scope binding. A changed observed protocol cannot authorize an
unlisted Redis probe. Missing/skipped/failed approved tools produce an explicit
needs_reapproval plan outcome, not a completed plan.

AI output never sets scope, approval, a command line, raw evidence or canonical
numbers. Fixed profiles remain server-owned. Prompts reuse escaped, bounded
untrusted-data envelopes and sticky raw canary detection. Reasons require
server-issued IDs, labels, confidence and aligned quotes; hypotheses require a
verification action. Model calls and approval decisions use the existing
hash-only audit mechanism. The immutable inputs and deterministic scoring
remain outside this planner's authority.

## Inputs actually consumed

The server selects recent in-process evidence and up to three matching stored
runs from a ten-run search, including the explicitly selected assessment. It
includes up to twelve services and six recorded signals per history, their
capture timestamp, and at most 1,000 characters of intent. DNS resolution for
scope authorization is the existing deterministic target check. No certificate,
DNS enrichment, HTTP probe or scanner fetch is launched by planning. Missing
metadata is explicitly limited; older observations are labeled as prior evidence.
An oversized prompt fails closed at 16,000 characters rather than secretly
discarding evidence or launching another request.

The original contract proposed local-only inference. This implementation reuses
the already existing provider selector: local is default; a cloud proposal needs
explicit evidence-sharing consent. No new provider, credential or automatic
planner fallback is introduced. No model or external API was called by the agent
while building/verifying this increment. See AI-PLAN-02 for the scope decision.

## Verification and limitations

TESTED WITH MOCKS: proposal, editing, approval, execution binding and provider
failure tests use synthetic canonical objects/fake providers and processes.
They prove the tested boundary/orchestration behavior, not scanner efficacy,
model planning quality or a network integration. Adversarial tests first failed
for missing planning/HTTP/client interfaces, then for stale authority restoration,
scope rechecks and missing schema-size enforcement before those behaviors were
implemented. Every rejection asserts that invalid output grants no authority.

VERIFIED: the local app was started with
`python -m vulnassess ui --db data/vulnassess.db --config config --run scanme-2026-09-24 --port 8772`.
The browser displayed the preserved canvas, existing Run live target button and
new AI-assisted scan planning section. Clicking Propose with an empty target
showed `Enter an authorised target first.` without a model/scan request. Browser
error/warning log inspection returned `[]`. This checks runtime rendering and
the empty-input path, not a real AI proposal or approved scan.

NOT RUN: live model generation and scanner execution. Implementation direction
does not provide a new lab capture, model artifact approval or network execution
authorization. Feed downloads, installs, scope edits, credential changes and
remote Git writes were not performed.

MISSING: a human-captured Nikto report with a completed provenance row under
`tests/fixtures/nikto/`; its README still records `none yet`. Synthetic tests are
not a replacement for this parser/integration evidence.

Quote alignment is mechanical content verification, not proof of semantic
entailment. Identifier checks fence typed target/endpoint/evidence references
and common CVE/IP/port mentions; they are not a complete semantic verifier of
arbitrary free prose or a calibrated confidence measure. Hypothesis verification
actions are text suggestions, never tool commands. Durable multi-user approvals,
automatic plan reapproval, certificate collection, later reasoning agents and
model quality evaluation are not delivered by this increment.

## Gate and handoff

The prior foundation had 569 passed tests, 480 subtests and 85.62% source coverage.
The first integrated planner run produced `604 passed, 485 subtests passed`
and `Total coverage: 85.38%`; the 85% gate passed. Subsequent focused tests verify
cooldown preservation and prior web endpoint selection before the final gate.

VERIFIED final gate (Python 3.12.10 on this Windows machine):

| Command | Actual output |
| --- | --- |
| `python -m ruff check .` | `All checks passed!` |
| `python -m ruff format --check .` | `174 files already formatted` |
| `python -m pyright` | `0 errors, 0 warnings, 0 informations` |
| `python -m pytest -q -p no:hypothesispytest --cov=vulnassess --cov-report=term --cov-fail-under=85 --durations=10` | `607 passed, 485 subtests passed in 364.21s`; `Total coverage: 85.80%` |

No project tests were skipped or failed. The unrelated Windows-blocked Hypothesis
plugin was disabled, not a project test or coverage requirement. Planner source
coverage is 93%; full source coverage increased by 0.18 percentage points from
the foundation. The suite gained 38 tests and five subtests. A changed-file
credential-pattern scan reported `Credential-pattern matches in changed files: 0`;
this is a limited pattern check, not a proof that arbitrary text contains no secrets.

STATUS: implemented on a review branch; mocked orchestration and local UI verified,
real planner/scanner integration not run. BRANCH / COMMIT: codex/ai-assessment-foundation;
local implementation commits are acb8d42 and c38df8b; documentation is saved
separately. GATE: final results recorded above.
BUILT: bounded planner, editable review panel, one-use approval and runner binding.
CHANGED: scan_plans core; live runner and UI API/static files; adversarial/UI tests;
contract and decision documentation. DECIDED: propose/review/approve before scan,
without AI authorization or scores. DECISIONS: AI-PLAN-02 and AI-PLAN-03.
EVIDENCE: commands/results above and final gate below. DEFERRED: increments 3-10,
which are needed to measure the larger verification/fusion research questions
but are not prerequisites for the planning boundary. NEXT: human review and
authorized local-model/lab integration, then typed bounded evidence requests;
do not claim the entire AI roadmap is verified or merged.
