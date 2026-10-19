# The kickoff prompt

Paste everything below the line into GitHub Copilot Chat (Agent mode) after committing the kit.
It asks for a DESIGN first. Read that design carefully before saying "build" — that is your steering moment.

---

You are the lead engineer on this project. Read, in this order: .github/copilot-instructions.md,
docs/PROJECT.md, docs/problem-statement.md. If anything below contradicts them, they win — tell me.

Planning update: use the five-day DESIGN in docs/DESIGN.md. Capture ownership and reviewer names
are not design inputs. Support N>=1 experts in one format. In this existing parent repository, keep
the fixed-interface ADR requirements, no-install boundary and 85% source-coverage gate; the kit
does not override them. docs/fixtures.md in the parent gives human-only capture commands.

THE GOAL
Build a working prototype of the AI-Based Network Vulnerability Assessment Tool that proves the
research claim in docs/problem-statement.md: ranking by automatically inferred context agrees more
closely with expert judgement than ranking by CVSS alone. The mentor demo must show, live, the same
CVE on two lab machines receiving different ranks with a reason for each (PROJECT.md section 6), and an
evaluation table comparing our ranking with CVSS-only and CVSS+EPSS against expert rankings.

THE ONE TEST FOR EVERY DECISION
Does it help answer the research question? Yes: build it. No: defer it and say so. Unsure: ask.

WHAT PIVOTING LOOKS LIKE — do not do this
- Building attack-path chaining, re-scan verification, prompt-injection defences beyond W5, or a scan
  orchestrator because they are interesting. They are real gaps, credited to teammates, and they are
  other papers. One sentence under DEFERRED is all they get.
- Turning the tool into a general scanner wrapper, a SIEM, a dashboard product or an LLM playground.
- Replacing "infer context from scan evidence" with "ask the user to tag assets". Manual tags may exist
  as an optional override; the claim is about inference, and inference must work with zero tags.
- Replacing the deterministic formula with a learned model or LLM judgement. The claim is auditable
  prioritisation, comparable with baselines.
- Tuning weights to the lab after seeing expert rankings. Weights are frozen and documented first; if
  the hypothesis fails, that is a result.

ACCEPTANCE — what the prototype must do; how is yours
A1 Ingest real Nmap XML and ZAP JSON from files a human captured into one canonical finding format
   with provenance to the raw record; the target IP validated against scope.yaml; malformed input fails
   cleanly with one error type.
A2 Enrich offline from human-supplied NVD, EPSS and KEV snapshots: CVSS vector (4.0 preferred, 3.1
   otherwise — they have separate Environmental metric sets; there is no translation between them),
   exploitation probability and percentile, known-exploited flag, patch references. Missing snapshots
   are reported with exact paths, never guessed. Unmatched findings are kept, not dropped.
A3 Infer, from scan evidence alone, each host's role, whether it is internet-facing, and any
   compensating controls — each with confidence, source and verbatim evidence (W6). Zero manual tags
   required.
A4 Rank with a deterministic formula that populates CVSS Environmental metrics from A3 and combines
   the result with EPSS and KEV. The PROJECT.md section 6 two-machine example passes as an automated
   test. Monotonicity holds: adding KEV, raising EPSS, or moving a host from internal to internet-facing
   never lowers its risk. Same inputs -> byte-identical ranking output.
   Missing EPSS is not an observed percentile: leave its threat component unscored, rank on
   Environmental score only and flag the absence; apply KEV separately. Any required interface
   change is PROPOSED — awaiting reviewer, not applied to bypass the current fixed contracts.
A5 Produce an offline HTML report (no external assets): ranked findings with band, one-line reason,
   recommended fix, evidence quotes; per-host context with evidence; the formula, weights and feed
   dates used; provenance to raw files; run id and config hash in the footer. No number may appear in
   the report that is not in the underlying data.
   Use template reasons and evidence-backed advisory text; no prototype LLM or PDF export.
A6 Evaluate for N>=1 experts with tied ranks and critical labels in one format. For N>=2, report
   tie-corrected Kendall's W before comparisons. For N=1, omit W and print "single-annotator study —
   inter-rater agreement not available"; continue all individual method comparisons. Primary: tau-b
   per expert and its mean. Headline: critical-queue size at full recall. Secondary: NDCG@10.
   Verify arithmetic and undefined cases for N=1/2/3. Committed test truth is synthetic and labelled;
   real human judgments stay in ignored study data. Missing truth never produces an invented result.
A7 One command runs A1-A6 end to end on the lab and prints the two-machine table side by side and the
   report path.
A8 A README a teammate can follow: what a human must provide (dependencies, lab containers, the two
   scanner commands, feed snapshots, fixtures with README, expert rankings), how to run everything,
   and a "not in the prototype" list with one sentence each on how it slots in.

YOURS TO DECIDE — and I want your reasoning, not just your code
Architecture, module boundaries, data model, storage, CLI shape, test strategy, fixture strategy,
dedup strategy, confidence model, and what to cut. docs/design-notes.md holds a reference design from
early planning; use, adapt or replace any of it within the parent fixed contracts and walls.
Record necessary interface/dependency changes as PROPOSED — awaiting reviewer; do not apply them.

WHERE I WANT YOUR CREATIVITY — pointed at the statement's own open problems
1. Role inference from thin evidence. Ports and a few banners are all you get. What signals am I not
   thinking of — service co-occurrence, hostname conventions, TLS certificate subjects, response
   timing? Which are robust, which are noise? Design it, and design how we would know it is wrong.
2. Exposure beyond "is the IP public": vantage point, DNS names, redirect chains, cloud-provider and
   load-balancer fingerprints. What can a scan honestly see, and how confident can it honestly be?
3. Compensating controls from the outside: WAF, rate limiting, mandatory authentication — detected
   from scanner output without triggering them. What does "no evidence" mean for confidence?
4. The formula. CVSS v4 Environmental + EPSS + KEV is the requirement, not the design. How should they
   combine so KEV matters without swamping everything, so a low-confidence inference does not swing a
   rank as hard as a high-confidence one, and so a security team reading the breakdown nods?
   Propagate confidence into the score or keep them separate? Argue it in docs/scoring.md as a
   hypothesis the evaluation will test.
5. Evidence and explanation. What is the clearest way to show WHY machine B outranks machine A in one
   glance?
6. Evaluation design. Two or three practitioners is thin. Full rankings, pairwise comparisons,
   critical/not-critical labels, or a mix? How do we detect expert disagreement before comparing with us?
7. Honest confidence. When inference is uncertain the rank should show it. What does a
   medium-confidence Critical look like in the report?
A better idea on any of these than a reasonable engineer's default IS the contribution. Put it in the
design page with the alternative you rejected and why.

WHAT SUCCESS LOOKS LIKE FOR THE STATEMENT
- Two-machine example: same CVE, same CVSS; A Medium or Low, B Critical; each with a reason a
  non-technical mentor understands.
- Tau vs experts: ours > CVSS+EPSS > CVSS-only, the gap reported honestly even if small.
- Critical queue at full recall: ours shorter than CVSS-only.
- Every context feature's contribution visible: which inference moved which rank.
- A reviewer reproduces all of it from the repo with the human-provided inputs.

HOW WE WORK
1. Before writing code: post a one-page DESIGN — architecture sketch, data model, the formula and
   its justification, your answers to creativity items 1-7 (or "default, because..."), what you defer
   and why, the three riskiest decisions and how you will de-risk them. Stop and wait for my reply.
2. Build permitted first increments under the five-day plan. Each increment ends with `make check` green and the
   REPORT FORMAT. Each increment's first line names the acceptance items it advances.
   Work only on branches, never merge to main. Missing tools and unapproved ADRs remain explicit
   blockers. Fixture-dependent tests use @needs_fixture with `fixture not provided: <path>`;
   report every missing capture/README and do not skip unrelated tests or lower coverage.
3. At a real fork — two defensible designs — do not pick silently. Show both, recommend one, move on.
4. If a wall blocks good engineering, say so. Walls can be argued; they cannot be quietly crossed.
5. If you find a better idea than anything in PROJECT.md, propose it. That is the job.

Begin with the DESIGN.
