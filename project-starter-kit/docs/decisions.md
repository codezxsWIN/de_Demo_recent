# Decisions log (append-only)

Format: date · decision · why · alternatives considered · who

## 2026-09-06 · Project scope for the prototype
Build the spine that proves the research claim (ingest, enrich, infer context, rank, report, evaluate);
defer orchestrator, Nikto, LLM rationale, semantic dedup, re-scan. Why: 50% of the full design must be
a working, demonstrable prototype by December. Alternatives: build everything thin (rejected: nothing
would be finished); build only scoring (rejected: no end-to-end demo). Team.

## 2026-09-06 · Lead statement
"Context Is Not Free" chosen as the paper's lead statement after a novelty-and-fit review of all nine
team statements. Why: highest weighted score on novelty, impact evidence, fit, measurability and
buildability. Alternatives: prompt-injection through scan content (Ananya N, most novel, second paper);
target-side scan safety (Shravani, companion paper). Team.

## 2026-09-06 · The AI does not compute scores
Scores come from a deterministic formula; the model only resolves ambiguous inference and writes
rationale. Why: auditability and honest comparison with baselines. Alternatives: LLM-judged ranking
(rejected: not reproducible, not comparable). Team.

## 2026-09-06 · CVE layer adds EPSS and KEV
The deck's step 6 listed CVSS only; EPSS and KEV are required for the research claim. Slide to be
updated. Team.

## 2026-09-06 · Q3: prototype LLM deferred; full-design limits

Decision: the prototype uses no LLM, including for roles or rationale. The full design may generate
one-line rationales and reword evidence-backed remediation under validation that permits no new
numbers, IDs or URLs. A future role fallback may emit a role label only, with a fixed configured
confidence rather than a model-emitted confidence. Why: isolate the inference/ranking experiment
and retain W4's numeric boundary. Rejected: LLM-generated scores or confidence; unvalidated advice.
Conflict / resolution: the parent repository also forbids LLM-derived scoring inputs. A role label
still affects rank; fixed confidence does not remove that influence. Keep fallback deferred pending
mentor approval of that wall change. Who: user supplied the design resolution; no future wall
approval or implementation acceptance is asserted.

## 2026-09-06 · Q4: missing EPSS has no threat score

Decision: with missing EPSS, threat_multiplier = None; rank on environmental score only and report
"no exploitation data", explicitly identifying missing EPSS and displaying KEV separately. Do not
substitute either a percentile of 0.5 or a threat multiplier of 0.5. Missing required snapshots still
raise IntelUnavailable; only a missing row in a validated snapshot uses this path. Why: make absent
exploitation evidence visible and preserve matched/unmatched findings. Rejected: either conflicting
default, silently dropping the finding, or reporting a fabricated percentile. Conflict / resolution:
the parent fixed float fields/return types and missing-value configuration require an ADR before
the nullable design can be built. Who: user supplied the resolution; integrator-plus-reviewer runtime
approval remains pending. This policy can change ordering when previously missing EPSS arrives;
monotonicity is asserted only between observed percentiles, not across missingness.

## 2026-09-06 · Q6: reachable low-evidence flag, never removal

Decision: propose evidence-confidence v0 = 0.50 + 0.25 for validated applicability + 0.15 for
independent corroboration - 0.30 when neither is present; flag < 0.30. The weak-evidence case is 0.20.
Keep confidence separate from risk, retain every finding/rank/evidence, and add a flagged appendix.
Why: replace the sketch's unreachable < 0.30 condition without declaring weak evidence false.
Rejected: changing only the threshold to <= 0.30, deleting findings, duplicate-count corroboration,
or tuning after expert labels. Freeze definitions and weights before evaluation; measure independent
false-positive labels and misflags, not criticality as a proxy. Who: lead-engineer design choice under
the user's Q6 delegation. These values are an unvalidated heuristic, not calibrated probabilities.
Configuration/model extensions still require the parent contract's integrator-plus-reviewer ADR.

## 2026-09-06 · Five-day plan; logistics are not model inputs

Decision: supersede the November/December planning horizon with the user's five-day window, planned
from 2026-09-06 through 2026-09-11. Capture owner and integrator/reviewer names remain unconfirmed;
do not encode them or a fixed panel size into runtime interfaces. Evaluation supports N>=1 experts:
N>=2 reports tie-corrected Kendall's W first; N=1 omits W, states the single-annotator limitation,
and still computes defined individual comparisons. N=0 or absent judgments means missing truth.
Why: logistics must not change architecture or manufacture evidence. Rejected: waiting for names,
requiring exactly three reviewers, fabricating rankings, or claiming an evaluated result without labels.
Who: user-supplied planning instruction. The actual faculty deadline and panel commitments are not
asserted. A two-week expert turnaround would miss this five-day window; report that limitation.

## 2026-09-06 · PROPOSED — awaiting reviewer: runtime contract changes

Q4 requires nullable ScoreBreakdown.threat_multiplier, the corresponding risk() return component,
and removal/replacement of the fixed missing-percentile default. Q6's confidence policy and any
flag/group/link fields or configuration, honest unknown exposure, a new truth format, and any new
end-to-end command must be reconciled with the parent fixed contracts before implementation.
These are proposals, not applied changes or approval records. Native 3.1 versus 4.0 scoring must also
be reconciled with earlier translation notes without inventing converted vectors. Why: honest
missingness and reproducible evaluation must not be obtained by silently changing interfaces.
Rejected: claiming this design is its own ADR approval. The integrator plus one reviewer must approve
interface/dependency changes; mentor approval is additionally required for walls or scope changes.
Work stays on branches, with no merge to main while approval is pending.

## 2026-09-06 · Owner-independent capture and fixture gating

Decision: use the parent docs/fixtures.md for exact per-target Nmap/ZAP baseline commands, capture
paths and the README template (actual date, command, target, version and capturer). Commands are
human-only and not run by the agent. The pytest needs_fixture marker is restricted to real-capture
paths under tests/fixtures/ and reports `fixture not provided: <path>` for absence. Missing packages,
ordinary logic tests and malformed existing captures must not be hidden by this exception.
Why: the capture owner can follow a stable procedure later, without code changes or substitute data.
Rejected: generated scanner output, placeholder feed records, automatic image pulls or blanket skips.
The original supplied PDF is kept in the parent docs/deck/de_ppt.pdf; its statements and percentages
remain source material, not measured prototype results. No original slide content is rewritten here.
