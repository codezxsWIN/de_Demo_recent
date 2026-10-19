# Increment 3: typed follow-up evidence requests

## Purpose and implementation

The existing planner chooses scanners. This increment adds one follow-up observation
at a time: the selected model proposes a typed probe, explains its information gain,
and cites the observed service. The operator approves or rejects that exact request
in the workflow Run panel. A completed observation can be included in a subsequent
validated analyst response. Existing quick scans, imports, intelligence and scoring
are unchanged.

The new `evidence_requests.py` module owns proposal validation, a one-use request
registry, three fixed transports, append-only audit events and immutable evidence
artifacts. The existing scope engine, provider clients and AI boundary are reused.
No dependencies, scanner installations or scope entries were added.

## Contract and execution

The `evidence_request.v1` object has exactly these fields:

- `schema_version`, server-pinned literal `target_ip`;
- `kind`, observed `port`, integer `timeout_seconds` in 1–10;
- `reason`, `expected_information_gain`, each at most 500 characters;
- two labeled, cited claims, with paths `reason` and `expected_information_gain`.

Candidate operations come from server-observed TCP services. TCP connect is eligible
on an observed TCP port; HTTP/TLS options use the existing test-asset web endpoint
selection. Model-provided URLs, hostnames, paths, headers, flags and shell commands
are not accepted. The proposal is evidence, not authorization. The browser displays
its target, port, timeout, claim labels, confidence, exact quotes and binding hash.

`POST /api/evidence-requests/propose` accepts target, run_id, provider and explicit
cloud-evidence-sharing choice. It only calls the selected model. `approve` consumes
the request_id/request_hash once and executes the fixed operation. `reject` requires
a reason and logs it. `analyze` attaches saved observations to captured or stored
target evidence and calls the existing analyst validator. All four routes require
the loopback same-origin action header. GET never launches these operations.

Approval expires after ten minutes or a server restart. The request hash binds the
proposal and its entire server context, including the scope snapshot. Immediately
before I/O the same runner scope fence requires an exact named target, rejects the
canary and compares the current scope hash. A broad CIDR allowance alone is not a
named-target authorization for these follow-up probes. No scope configuration is
changed to make a probe pass.

The transports are intentionally small:

| Kind | Network operation | Meaning and limitations |
| --- | --- | --- |
| `tcp_connect` | One socket connection to literal IP/port | Reachability at that time; no service/authentication conclusion |
| `http_head` | `HEAD /`, IP Host header, connection close | Root status and selected headers; never follows a redirect or sends credentials |
| `tls_inspect` | Verified TLS handshake against literal IP | Protocol and certificate; IP-name mismatch/self-signed certificate fails rather than disabling verification |

Socket deadlines cover the operation; response/certificate bytes are capped at
8 KiB. A malformed, partial or oversized HTTP response fails closed. TLS virtual
hosting is a limitation: domain certificates may be valid for a hostname but not
for the literal IP. DNS lookup and hostname/SNI expansion are not implemented in
this increment. Failure does not create a vulnerability finding or change a score.

## Persistence and analyst integration

Successful observations are exclusive-create JSON artifacts in the ignored local
`data/ai_evidence/` store. Each carries a server-issued source ID, target, assessment
ID, operation, port, capture time, `origin: ai_request`, request hash, raw bytes as
hex and their SHA-256. The envelope has an additional canonical JSON integrity
hash. Reads verify both hashes. These hashes detect accidental/partial alteration;
they are not signatures protecting against an administrator rewriting both data
and hashes. Raw HTTP headers can contain sensitive values; this local directory
must remain private and must not be committed.

Audit records include proposal model/prompt/input/output hashes and outcomes,
human approval/rejection, rejection reason and execution outcome. Approval state
is process-local and never restored from an evidence file.

Analysis maps accepted observations to request-local E IDs, retaining source ID,
raw hash, capture time and origin alongside each. It uses the newest eight matching
target/assessment artifacts within the existing evidence/prompt budgets and reports
omitted supplementary observations. Raw captures, canonical findings, context
controls and deterministic scores remain unchanged. An HTTP 401 at `/` cannot be
generalized into proof that every endpoint requires authentication.

The Run panel has **Find the next evidence gap**, **Approve and collect evidence**,
**Reject request**, and **Analyze with follow-up evidence** controls. Target/model/
assessment changes invalidate browser state. Late responses for old selections
are ignored, and a consumed approval cannot be retried from the same button.

## Verification record

The new adversarial tests exercise unpinned targets, invented ports, flags, invalid
bounds, fabricated quotes, prompt-injection sentinel handling, malformed model
output, expired/stale approvals, scope changes, replay, rejection logging, raw
integrity, redirect non-following, response limits, TLS verification and IPv6
connect-only behavior. HTTP integration tests cover explicit origin/action checks,
proposal/approval/reanalysis, preserved canonical values and cross-target exclusion.
The Node client test covers stale-response disposal and consumed approval state.

Final gate results and live-browser findings are recorded below before handoff.

## Deferred and uncertain

No evidence reconciliation/CVE-ranking agent (increment 4), context-reasoning agent,
critic, RAG or new scoring formula is introduced. Expert triage improvement and
real finding recall are not established by passing software tests. Follow-up
observations do not automatically confirm CVEs or remove findings.

STATUS: work-in-progress checkpoint, paused at the user's request on 2026-10-03.
BRANCH: codex/ai-assessment-foundation. GATE: latest full run interrupted on pause;
do not treat this checkpoint as a verified release.
BUILT: typed request/review/collection/reanalysis loop.
CHANGED: evidence request core, analyst evidence attachment, workflow API/client,
shared claim schema and tests. DECIDED: preserve raw observations separately from
canonical scores/findings. DECISIONS: AI-EVIDENCE-01. EVIDENCE: tests and browser
results below. DEFERRED: increments 4–10. NEXT: review this increment and validate
against a human-approved real lab probe before claiming scanner integration.

## Resume checkpoint — 2026-10-03

All current source, UI, tests and documentation are saved locally. No merge or push
was performed. The latest focused run passed 44 tests. An earlier full revision
passed 642 tests and 490 subtests with 85.89% coverage; subsequent schema and outage
handling changes mean that result does not verify the final checkpoint. The final
full run was stopped at the user's request.

Real local `llama3.2:3b` proposal attempts exposed claim-path, quote-copying and
cross-service citation errors. The final code attaches exact quotations server-side
from model-selected IDs, rejects model-supplied quote fields, and binds each typed
operation/port to its observed service IDs through schema alternatives. The last
live retest was still awaiting verification when work paused. No follow-up network
probe was approved or executed, and no complete real probe-to-analysis result is
claimed. No scope, canonical scores or scanner evidence were changed.

On resume: inspect this saved diff, rerun lint/format/type and full coverage gates,
verify the final schema against local Ollama, then verify a human-approved real lab
capture and follow-up analysis. Keep Increment 4 and later work deferred until this
increment's acceptance checks are satisfied.
