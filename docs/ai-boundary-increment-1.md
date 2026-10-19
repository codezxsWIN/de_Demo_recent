# Increment 1: AI boundary

This change hardens the existing analyst and CLI explanation calls. It does **not** add a
planner, scanner tool use, CVE ranking, or any later-increment agent.

## Design

- The scope engine and stored scoring records remain outside the model boundary. Models
  receive bounded, escaped evidence envelopes and server-issued IDs. A separate system
  message explicitly denies authority to anything inside those envelopes.
- The analyst now requests `analyst.v2` JSON. Every model-authored prose field has one claim
  metadata entry keyed by its field path. Entries include a label, confidence, finding
  and evidence IDs, at least one quote, an optional verification action, and an optional
  score. The smaller CLI rewriter uses `rationale.v1` JSON with one such claim.
- Validation is all-or-nothing: schema and identifier checks, content-aligned quotes,
  citation scoping to each finding, allowed CVEs and numbers, and exact equality for
  any model-stated canonical score. Hypotheses need a verification action. A validator
  for multiple samples rejects disagreement; this increment does not request extra
  samples. No partially validated analyst result is returned.
- A model sentinel, if returned, rejects the run and flags evidence IDs containing
  recognized instruction-breakout syntax. The prompt strips recognized role/control
  tokens and escapes markup, but these are defense-in-depth, not a proof that prompt
  injection is impossible.
- Every attempted model generation appends a hash-only audit record to
  `data/ai_audit.jsonl` (ignored by Git). It records model, stage, prompt/input/output
  hashes where a response exists, decision, and outcome. No prompt or evidence body is
  stored in the audit file. A transport failure before a response has a null output
  hash, not a fictional one.
- Rejected analyst output becomes **Needs review** in the workflow. Rejected CLI
  rewording records `needs_review` and displays only the deterministic sentence.

## Compatibility and limits

The model response format is intentionally incompatible with legacy `analyst.v1`
responses and existing hand-authored supervision files. Those files must be upgraded
and revalidated before fine-tuning; the corpus builder now rejects the old format.
No live provider call or attack-site scan is used as evidence of this increment's
correctness. Quote alignment proves text appears in the bounded server evidence record;
it does not prove the model's interpretation is true. Multi-sample generation,
independent critic review, and agents belong to later increments.

## Verification

`tests/adversarial/` covers prompt breakouts, canary rejection, fabricated quotes,
invented CVEs and finding IDs, score mismatch, malformed or unknown schemas,
hypotheses without verification actions, and conflicting samples. The full test suite,
lint, type check, and coverage gate must pass before this increment is considered
verified. No later increment is included in this change.

## Safety-foundation follow-up — 2026-10-02

This follow-up serves PROJECT.md stage 5 and input-safety invariant I2. It
repairs the existing boundary before any planning agent is introduced. The
current shared schema version is `analyst.v4`; the `analyst.v2` description
above records the original increment, not the current provider contract.

### What changed and why

1. The analyst recorded a raw-response canary but consulted it only when an
   exception occurred. A provider returning otherwise valid parsed JSON could
   therefore hide the warning and have that answer accepted. The analyst now
   rejects the response immediately after generation if raw capture detected
   the canary, before publishing a validation-complete event or analysis.
2. Canary detection is sticky within one generation attempt, in both the
   analyst and the CLI rationale rewriter. A later clean raw capture cannot
   erase an earlier warning. A separately audited bounded correction remains
   a separate attempt; a canary response cannot request that correction.
3. Malformed evidence IDs could trigger an unhashable-object exception while
   formatting a rejection message. The shared validator now rejects these
   values explicitly with the claim path, without displaying the supplied
   model object or accepting a partial result.

Scope, canonical scores, evidence records, model schemas, command shapes and
provider selection are unchanged. The CLI rejection still returns only the
existing deterministic sentence with `needs_review`, never the rejected rewrite.

### Test-first evidence

VERIFIED — executed with the existing Python 3.12 interpreter on this machine:

```text
python -m pytest -q -p no:hypothesispytest tests/adversarial/test_ai_boundary.py -k 'raw_canary_cannot or malformed_evidence_ids'
6 failed, 23 deselected in 0.83s
python -m pytest -q -p no:hypothesispytest tests/adversarial/test_rationale_boundary.py -k cli_canary_cannot
1 failed, 1 passed, 19 deselected in 0.62s
python -m pytest -q -p no:hypothesispytest tests/adversarial tests/test_analyst.py tests/test_all.py tests/test_live_assessment.py
228 passed, 384 subtests passed in 5.83s
```

The first two commands intentionally reproduced the bugs before their fixes;
the final command checked the integrated fixes. Eight parameterized regression
cases are new: two analyst canary cases, four malformed-ID cases and two CLI
canary cases. Existing tests retain the fabricated-quote, invented-identifier,
score-consistency, malformed-schema and sample-disagreement checks.

TESTED WITH MOCKS — fake provider callbacks and synthetic, in-memory evidence
exercise fail-closed rejection, evidence-ID flagging, hash-only auditing and
payload preservation. They do not establish a real model's resistance to prompt
injection. Quote alignment proves content alignment, not semantic entailment
or byte offsets into an original scanner file.

### Limits and next contract

NOT RUN — live scanning, model inference, feed retrieval, browser walkthrough
and independent expert evaluation. No dependency or credential was changed.
The running local server has not been restarted for this follow-up.

MISSING — an independent real Nikto JSON capture with a completed provenance
row under `tests/fixtures/nikto/`; its README still lists none. This absence
does not block a pure boundary regression but prevents a real Nikto integration
claim. Independent scanner captures and expert labels remain necessary for the
broader context, verification and fusion research claims.

The next contract is [AI-PLAN-01](ai-scan-plan-contract.md), explicitly PROPOSED.
It requires human approval before new public planning interfaces are built.
No planner, typed probe executor, reconciliation agent, critic or ranking change
is included in this follow-up.

### Final integrated gate and increment report

VERIFIED — actual executions after the fixes and formatting:

```text
python -m ruff check .
All checks passed!
python -m ruff format --check .
169 files already formatted
python -m pyright
0 errors, 0 warnings, 0 informations
python -m pytest -q -p no:hypothesispytest --cov=vulnassess --cov-report=term --cov-fail-under=85 --durations=10
569 passed, 480 subtests passed in 269.56s (0:04:29)
Required test coverage of 85% reached. Total coverage: 85.62%
```

No project tests failed or were skipped. The unrelated auto-loaded Hypothesis
plugin remains excluded because Windows App Control blocks its native dependency;
no project test or assertion is excluded. Baseline commit `29888b4` recorded
561 tests, 480 subtests and 85.59% coverage. Delta: eight added regression cases
and +0.03 percentage points of source coverage; this is not model-quality evidence.
Boundary-module coverage is 88%, analyst coverage 89%, and CLI explanation
coverage 81%; the gate is aggregate source coverage, not full branch coverage.

STATUS: safety repair locally verified; not merged, pushed or live-deployed.
BRANCH / COMMIT: `codex/ai-assessment-foundation`, based on `29888b4`;
the resulting local commit identifies this report.
GATE: lint, format, Pyright and full pytest/85% coverage checks passed above.
BUILT: sticky raw-canary rejection and explicit malformed-ID rejection, with
eight adversarial cases; the planner contract is a proposal only.
CHANGED: `vulnassess/` boundary/analyst/explanation modules;
`tests/adversarial/` regressions; `docs/` follow-up, decisions and proposed plan.
DECIDED: honor any raw warning rather than trusting valid parsed output; retain
strict citation/score guards and existing deterministic fallback.
DECISIONS: AI-BOUNDARY-05 (decided), AI-PLAN-01 (proposed, not human-approved).
EVIDENCE: actual commands/output above; provider callbacks tested with mocks.
DEFERRED: new planning interfaces pending approval, later reasoning/fusion
increments in the specified order, and real capture/expert evaluation. These
omissions do not prevent verifying this boundary repair; they do prevent claiming
the full AI assessment roadmap or research hypotheses are complete.
NEXT: human review of AI-PLAN-01, then test-first implementation of Increment 2;
do not treat this follow-up or a green gate as that approval.
