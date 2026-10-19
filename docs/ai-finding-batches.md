# Bounded finding coverage

The live analyst previously selected only the highest-ranked findings that fit
the 14,000-character prompt. Remaining findings were disclosed as omitted but
never sent to the model.

The optional live-analysis entry point now submits consecutive bounded cases.
Each subsequent case contains only findings not included in an earlier case,
with their original deterministic scores and enrichment records. Host context
and scanner coverage remain available in every case. The input payload is not
mutated.

Each request uses the existing trust envelopes, claim validator, citation checks,
provider routing rules, and audit log. Audit records include the canonical
finding IDs supplied in that call. Evidence IDs are local to each batch. The UI
renders each batch separately so E1 in one batch cannot be mistaken for E1 in
another.

The aggregate coverage counter is computed by the server from validated cases.
It means findings were included in validated requests, not that each finding has
been independently confirmed or that the model produced a recommendation for
every finding. No cross-batch correlation or synthesis is claimed.

At most eight batches are allowed per provider attempt. A rejected batch or
exhausted batch budget withholds the entire AI result and reports Needs review;
scanner evidence remains available. Each prompt retains its existing character
budget. Service and intelligence truncation limits also remain and are disclosed
within the affected batch.

Verification covers all six findings without duplication, prompt budgets,
unchanged input scores, evidence isolation, rejection of a later batch, and
budget exhaustion. The original single-case API is unchanged for callers that
explicitly request one bounded case.

## Nikto finding identity

The installed Nikto header plugin reports multiple missing headers under native
check ID 013587 and the same URL. The old parser generated the same canonical
finding ID for these different observations. The parser now derives a stable
observation ID from the previous fingerprint and the original description, while
preserving Nikto's native check ID. Reordering the input or changing the run ID
does not change the observation ID. Existing stored imports are not rewritten;
new imports use the corrected identity convention.

The batch planner rejects duplicate canonical finding IDs before calling AI.
It also rejects missing or inconsistent finding-coverage metadata rather than
claiming that a partial review covered everything.

## Request schema alignment

Each generation request now enumerates its allowed finding and evidence IDs in
the output schema. Recommended actions and correlations require at least one
finding citation when findings exist, matching the existing server validator.
Zero-finding cases require empty finding-ID arrays. This prevents structurally
valid provider output from omitting citations required by the application;
server validation still rejects any violation.

Numeric claim scores use explicit schema alternatives: either a null score, or
exactly one finding ID paired with that finding's canonical risk value. Repeated
claim schemas are shared through local JSON Schema references to reduce request
size. Audit records include the schema hash.

The prompt explicitly maps each finding alias to its supporting evidence IDs.
Service-only investigations must not attach an unrelated finding. Repeated
decision-frame records are omitted from the prompt because the complete case
already supplies them; the full decision frame remains available to the UI.
Investigation verification text has an explicit action-prefix schema constraint,
matching the existing validator rather than relaxing it.

### Verification on 2026-09-28

A real Google-provider replay of the retained, hash-verified localhost test scan
included all nine Nikto findings across five validated requests (two findings
per request except the last). No findings were omitted and canonical scores
remained unchanged. This proves that bounded multi-batch analysis can complete
for this fixture; it does not establish reliability across arbitrary targets or
providers, nor cross-batch reasoning. Earlier invalid attempts were withheld.

A subsequent browser-driven localhost run collected nine findings but rejected
the first AI batch for an unsupported authentication assertion. A diagnostic
replay then encountered Google HTTP 503. Therefore end-to-end reliability is
**not verified**: a successful replay must not be represented as a reliable fix
for every generation. The browser correctly retained an evidence-only summary.
Final automated checks: 489 tests and 465 subtests passed. Coverage percentage
was not measured in this increment.

## Groq schema compatibility correction

Live diagnosis found that Groq rejected the overlapping score `anyOf` branches
with `discriminator_value_overlap`, before any model generation. Groq requests
now enumerate the permitted numeric values in a nullable score field instead.
The server still checks every non-null score against exactly one canonical
finding; provider-side schema acceptance is never the trust boundary. Google
and local requests retain the paired-score schema. The audited schema hash
records the actual provider-specific schema.

HTTP 400 errors explicitly identifying an invalid request schema now raise a
configuration error, not a provider-outage error. Provider error bodies are not
displayed, and no invalid-output retry was introduced.

Runtime verification: GPT-OSS accepted the corrected schema and validated one
batch, then returned HTTP 429 on the next batch. Qwen accepted it but produced
an unknown-host claim, which was rejected. Google remained HTTP 503 during this
diagnostic. These observations do not establish full-provider reliability.

Reference: https://console.groq.com/docs/structured-outputs

## Follow-up: live target and request diagnostics

Live execution now replaces the stored-host selector with the actual requested
target and pinned IP, disables stored-finding filtering for that live view, and
shows live counts separately. Preview restores stored selectors and explicitly
labels simulated data; neither path mutates stored assessment records.

Configuration errors now retain their specific diagnostic across the analyst
boundary instead of becoming a generic unexpected-validation error. Citation
support mappings are included in the output field schemas as well as the
prompt. Groq's target-wide summary has a null score; individual finding score
checks remain unchanged. These are preventive generation constraints, not
permission to repair or accept unsupported claims.

A replay of the user's retained six-finding pentest-ground capture validated
the first two findings with the revised contract. Batch two hit HTTP 429.
No new external scan was performed. Full six-finding completion remains
unverified; the UI and error-handling fixes do not resolve provider quotas.

## Retained scan evidence

New live scans retain scanner output in a unique directory under
`data/live/raw/`. Each completed collection writes `case.json` before AI runs,
and a `manifest.json` records SHA-256 hashes of the captured files and case.
The directory is returned in the live result. A failed model call no longer
causes the raw scanner files to disappear with a temporary-directory cleanup.

This is local artifact retention, not registration as a stored database
assessment. The existing stored-assessment selector is unchanged. These files
are excluded from Git, and no automatic deletion or retention schedule is added.
