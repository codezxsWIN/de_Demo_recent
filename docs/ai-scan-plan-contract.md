# AI-PLAN-01 — Human-approved AI scan planning

Status: **IMPLEMENTED ON REVIEW BRANCH — implementation directed by the user's
2026-10-02 request to proceed; live model/scanner integration not executed.**
This document retains the original proposal below. The implemented differences
and exact verification are recorded in [Increment 2](ai-scan-plan-increment-2.md).

This is the next increment after the AI safety-boundary recheck. It serves
PROJECT.md stages 1-2 and improves the evidence coverage needed by the context,
verification and multi-scanner research directions. It does not deliver those
later reasoning agents or imply measured ranking improvements.

## Decision requested

The user subsequently asked the agent to proceed instead of imposing another
procedural pause. That is implementation direction for this bounded planner,
not evidence of a formal sign-off on every clause below, a scope expansion, or
permission to execute a live model/scan. Authorization and canonical scoring
remain deterministic. The original local-only proposal has an implemented
variant: existing provider selection is reused, with explicit evidence-sharing
consent required for a cloud proposal; the agent did not make a cloud call.

Approve a local-only planning agent with the additive contracts below. The
agent proposes a scan; a human edits and approves it; the deterministic runner
checks scope, content hash, tool readiness and approval before execution. AI
cannot authorize targets, launch tools, change scores or replace raw evidence.

This is a narrow exception to the prototype's rationale-only AI role, not an
exception to its authorization, score, local-processing or provenance walls.
No dependency, model download, feed retrieval, credential access, SQL migration
or cloud data flow is requested. Live execution still needs the existing lab
authorization and artifact prerequisites; approval of this design alone is not
permission to run a scanner or provision a model.

## Evidence and model boundary

- The server supplies one deterministically accepted, pinned literal IP. A
  hostname may be displayed as metadata but never substituted as an executor
  target. A changed DNS answer requires a new scope decision and approval.
- Planning reads only supplied prior-run evidence, imported records, DNS and
  certificate metadata, and user hints. It performs no discovery or fetch.
  Absent history, certificate or DNS evidence is explicitly unavailable, not
  fabricated. Stale prior evidence retains its timestamp and limitations.
- The server assigns evidence IDs before composing a bounded prompt. All text,
  including hints and imported filenames, crosses the existing untrusted-data
  envelope. Only an already-provisioned local model may be called, after its
  readiness checks. No automatic provider switch or cloud fallback is added.
- Every prose claim has label, confidence, evidence IDs, aligned quote references
  and a verification action for hypotheses. These reuse the shared boundary;
  unknown identifiers, schemas, scores or canaries yield Needs review with no
  partially accepted draft. Defaults cite server-issued baseline-policy evidence
  rather than invented target observations.
- Each model attempt records model, prompt/input/output/schema hashes, decision
  and outcome through the existing hash-only audit mechanism. No prompt bodies,
  secrets or target-controlled instructions become executable parameters.

## Proposed structured contract

New model JSON uses `scan_plan.v1` with additional properties forbidden at every
level. The model returns only the pinned target reference, ordered steps and
claim metadata. Approval and execution fields are exclusively server-generated.

| Field | Required constraint |
| --- | --- |
| `schema_version` | Exactly `scan_plan.v1`. |
| `target_ip` | Exactly the server-pinned literal IP; no hostnames, CIDRs or URLs. |
| `steps` | Nmap first, optionally followed by Nikto; one or two steps, no duplicate tool/profile/endpoint tuple. |
| Step `tool` | `nmap` or `nikto`; no arbitrary executable or shell syntax. |
| Step `profile` | Fixed `nmap_light` or `nikto_web_bounded`, matching the tool. |
| Step `timeout_seconds` | Integer, never boolean; Nmap 30-180, Nikto 30-150; total at most 330. |
| Step `endpoint_evidence_id` | Null for Nmap; server-issued observed web-endpoint ID for Nikto. |
| Step `reason` | Non-empty, at most 500 characters; claim metadata and citations required. |
| Step `confidence` | Finite number from 0 to 1, not boolean. |
| `claims` | Exactly one metadata row for each model-authored prose field; no uncited explanation. |

The two profiles map to the existing light-Nmap and bounded-Nikto behavior;
their fixed mapping is versioned and included in the approval hash. No free-form
flags or profile extensions are accepted. Nikto uses the endpoint referenced by
server evidence while its network target remains the pinned IP. Host headers
and paths are validated by existing endpoint and scope guards, not model text.
Nessus remains an imported-report source. Existing legacy adapters are retained.

With no history, propose Nmap only. With supplied observed web evidence, the
model may propose Nmap then bounded Nikto and justify both choices. User hints
alone cannot assert that a web endpoint was observed. Newly discovered services
can motivate a new draft after discovery, never an automatic tool addition.

## Approval and execution contract

The server maintains a bounded in-memory registry: at most 32 active drafts,
30-minute lifetime, invalidated on restart. It generates an opaque plan ID,
the immutable evidence-snapshot hash, scope-configuration hash, profile-map hash
and canonical SHA-256 plan hash. JSON exported for review is not approval authority.
Hashes establish content identity, not trust in whoever supplies a hash.

State changes are `draft -> approved -> executing -> completed/needs_reapproval`.
Editing creates a new draft/hash and revokes the old approval. Approval is an
explicit human action on the displayed exact plan and server snapshot. Approval
does not alter the scope engine's decision. Execution atomically consumes the
matching approval before starting a tool; replay or concurrent consumption fails.

Before **each** tool, the runner checks pinned IP, current scope hash, evidence
binding, profile-map hash, plan hash, approval state, expiry and readiness. A
changed target, added/skipped tool, timeout or profile change requires re-approval.
If execution cannot follow the exact approved plan, halt that plan and preserve
already collected evidence with honest partial status. Do not call a substitute
tool or mark an unexecuted step complete. Scanner success remains distinct from
subsequent AI-analysis availability in the existing reporting flow.

Proposed additive local UI actions:

| Action | Contract |
| --- | --- |
| `POST /api/scan-plans/propose` | Refer to server-held scope/evidence snapshot; return validated draft or Needs review; never scan. |
| `POST /api/scan-plans/edit` | Submit plan ID, expected current hash and edits; validate and return new unapproved revision. |
| `POST /api/scan-plans/approve` | Submit plan ID and displayed hash; approve only the matching current draft. |
| Planned execution | Add optional `plan_id` and `plan_hash` together to the existing explicit live-run action; no field defaults to approval. |

These actions require the existing loopback, exact same-origin and explicit-action
guards. GET inspection never generates plans or launches scanners. This is a
single-user local approval boundary, not multi-user authentication or a remote
deployment design. Existing quick/manual runs retain their current deterministic
gates and behavior; they must not be presented as AI-approved planned runs.

The UI shows target, evidence age, ordered tools, profile, timeout, reason,
confidence, citations and total time bound before the separate Approve action.
Run is disabled for an unapproved, expired or edited plan. Every edit, approval,
rejection, invalidation and execution outcome is audited; the canvas distinguishes
proposed, approved, executed, failed and not-applicable evidence paths honestly.

## Acceptance tests required before completion

1. No history produces a bounded Nmap baseline; prior observed web evidence
   permits the web tier with traceable reasons, never a guessed endpoint.
2. Planner generation and all GETs invoke no scanner. Unapproved plans and
   user-controlled approval fields cannot reach the executor.
3. Invented evidence IDs, malformed JSON, canaries, fabricated quotes, unexpected
   model identifiers and canonical numbers fail closed with an audited rejection.
4. Out-of-scope or non-pinned targets are rejected before any subprocess.
5. A stale plan, scope, evidence or profile hash prevents execution. A human edit
   creates a different hash and invalidates the old approval.
6. Expired, restarted or already-consumed approvals reject execution. Concurrent
   requests cannot launch the same approved step twice.
7. Missing scanners or changed endpoint observations stop the plan with partial
   evidence retained; no silent skips, replacements or newly authorized tools.
8. Existing scanner/report paths and deterministic scores remain unchanged.
9. Full lint, format, type, adversarial and coverage gates pass. Real scanner/model
   integration needs separately authorized captures; mocks are labeled as such.

## Deferred, not removed

Typed evidence requests, reconciliation and CVE candidate ranking, context
reasoning, exploitability vectors, critic/coverage agents, routing/memory, RAG
and expanded evaluation remain in the user's specified later-increment order.
No unrelated tool or agent is introduced. The bounded planner improves what
evidence to collect; it is not a claim that every tool is applicable to every
target or that AI reasoning has been validated against expert ground truth.
