# Decisions

Durable changes are appended here with a date, rationale, and owner. Scoring or role changes also record the version and evaluation impact.

## Seed decisions — 2026-09-06

1. **Package name:** `vulnassess`.
2. **Runtime and license:** Python 3.11 or newer; MIT License.
3. **Lab scope:** `172.28.0.0/24`, limited to the three targets in `config/scope.yaml`. **Scanning is authorised only against the lab network defined in config/scope.yaml.**
4. **Local model:** `qwen2.5:7b`, `Q4_K_M`. Treat the model and quantisation as selected but not benchmark-verified until the smoke test and model metadata are recorded. Test-machine CPU and RAM remain to be recorded after verification; do not fabricate them.
5. **CVSS policy:** CVSS v4.0 is primary. When v4.0 is absent, translate v3.1 using the versioned project translator and record the original vector, method/version, assumptions, and translated result on the finding.
6. **Roles and bands:** v0 roles and thresholds are those in `docs/scoring.md`. Changes require a dated decision, scoring-version increment where relevant, rationale, and evaluation note.
7. **Evaluation plan:** recruit three experts: the project mentor and two security practitioners independent of score implementation. Ask them before Stage 3 closes. Each receives stable finding IDs and evidence, then returns a full ranking (ties allowed only if documented) and an `expert-critical` set. Identities may be pseudonymised in committed artifacts.
8. **Stage definition of done:** relevant tests pass, Ruff is clean, documentation is updated, and one documented demo command succeeds.
9. **Nine-person team split:** Stage 1 adapters/schema: 2; intelligence: 2; context inference: 2; scoring/explanation: 2; lab/evaluation/docs: 1. One person from the team is designated integrator and owns `main`; the role does not add a tenth person.
10. **Git workflow:** protect `main`; use one branch per prompt; require a teammate review before every merge.
11. **Initial scoring hypothesis:** use scoring v0 in `docs/scoring.md` until Stage 4. It is deliberately labeled a hypothesis and must not be described as validated.
12. **Golden test:** start with `CVE-2012-2122`; fixture evidence must confirm the product/version match. Any replacement requires a recorded decision.

## Verification record

The following items are intentionally not claimed complete until real commands and artifacts exist:

- Development-tool smoke test
- Local-model metadata and machine specification
- Lab startup and authorised manual scans
- Dated NVD, EPSS, and KEV fixture subsets
- Expert-panel acceptance

## Source alignment and Prompt 1 — 2026-09-06

Owner: scaffold integrator; changes remain on the prompt branch for teammate review.

13. **Source of truth:** the supplied implementation prompts replace the provisional project brief. The deck's exact eight steps and final six-section explainer are still unavailable; existing explanatory prose is not represented as verbatim source text.
14. **LLM boundary:** Prompt 0's hard rule (rationales only, no ranking influence) takes precedence over Prompt 5's role-classification fallback. Context remains rule-based unless an explicit later decision changes that boundary.
15. **Scoring correction:** specification `prompt-7-v0` supersedes the day-zero weighted mean. Use CVSS Environmental score, an EPSS-percentile factor of `0.5 + 0.5 * percentile`, and the KEV floor of 90. Bands are 80/60/35. No implementation or evaluation result is claimed yet.
16. **Role correction:** accept Prompt 5's ten role names as listed in `scoring.md`, replacing the provisional hyphenated list. Manual tags remain separate inputs per Prompt 6.
17. **Golden-test inconsistency:** KEV status cannot differ by machine for the same CVE/feed. Identical KEV=true inputs must both be Critical. The candidate CVE is unverified; defer its selection and the exact context-only band assertion until real fixtures exist. Test the KEV floor separately.
18. **Scope interpretation:** retain the existing three fixed lab IPs inside `172.28.0.0/24`; do not widen to CIDR-wide discovery. Empty `allowed_hosts` does not remove the explicitly configured lab targets.
19. **Execution boundary:** implement Prompt 1 only in this change, after applying Prompt 0. CLI commands and lab/e2e targets must fail explicitly as unimplemented. Do not install tools/dependencies, pull images/models, run scans, contact feeds, or fabricate real sample data.
20. **Packaging:** use a setuptools `src` layout, a `vulnassess` console entry point, and `python -m vulnassess` as an equivalent entry point. Development dependencies live in the `dev` extra.
21. **Environmental precedence:** when role and test-environment requirements overlap, apply the test requirements last. This makes Prompt 7's test-context mapping effective without introducing new weights.

### Dependency justifications

- `typer>=0.12`: implement the specified typed CLI and its testable command interface.
- `pydantic>=2,<3`: provide the requested v2 canonical models and validation in later prompts.
- `httpx`: support explicit feed refresh and local Ollama HTTP requests in later prompts; ordinary processing remains offline.
- `rich`: provide readable terminal output and evaluation tables.
- `PyYAML`: read the requested scope, role, weight, and expert-ranking configuration.
- `pytest` (development): run the requested deterministic unit and CLI tests.
- `ruff` (development): enforce the requested Python lint checks.
- `setuptools>=77` (build): package the `src` layout and console script with standardized license metadata.

No packages are installed as part of this change. Libraries requested only in later prompts (`cvss`, Jinja2, SciPy) are not added early.

### Prompt 1 validation commands

Run from the repository root using an environment that already provides the dependencies:

```powershell
python -m ruff check .
python -m pytest
$env:PYTHONPATH = (Join-Path $PWD 'src')
python -m vulnassess --help
python -m vulnassess scan
```

Help must exit 0; every named command must print `not implemented` and exit 2. On a machine with Make, `make lint` and `make test` run the same checks. Bare `make` defaults to tests, not installation. `make install` is an opt-in dependency installation command, not something executed during this task.

### Prompt 1 verification — 2026-09-06

- Python 3.12.10 and the existing runtime dependencies were used without installing or upgrading anything.
- `python -m pytest tests\test_cli.py`: 13 tests passed, including all eight exit-2 stubs, help, invalid commands, and module entry points.
- Built a wheel using the existing setuptools backend without dependency resolution or installation; verified its console entry point (`--help`, exit 0) and module entry point (`scan`, exit 2) directly from the wheel.
- `python -m ruff check .` could not run: Ruff is not installed in the active Python environment, is not on PATH, and no separate uv tools are installed. No lint pass is claimed.
- Make is not on PATH, so the Make wrappers were not executed; their underlying pytest command was verified directly. The install target was never run.
- Full Prompt 1 acceptance remains pending the required Ruff check. Do not mark the stage complete or advance to Prompt 2 on the strength of tests alone.

## Engineering contract update - 2026-09-06

**22. Conflict / resolution / why - installation:** decision 19 and the day-zero instructions prohibited installation without further approval; the latest engineering contract explicitly authorises creating or refreshing `.venv` and installing dependencies already declared in `pyproject.toml`, including development extras. Follow that newer permission. Adding or removing a declaration still requires approval and a dependency justification here. Alternative considered: retaining the blanket installation prohibition; rejected because it prevents the explicitly required verification workflow.

**23. Conflict / resolution / why - acceptance:** decision 8 and the Prompt 1 commands did not enforce formatting, static types, or coverage. The latest contract requires `make check` to pass Ruff lint, Ruff formatting, Pyright, pytest, and at least 85% source coverage before completion. A missing tool or target is a failing prerequisite, not a passing or skipped check. Alternative considered: reporting the prior pytest-only result as completion; rejected because it does not satisfy the new gate.

**24. Conflict / resolution / why - provenance:** the day-zero context-source list contained only `rule` and `llm`; the latest contract also permits `manual`. Adopt all three provenance labels while retaining the existing prohibition on LLM influence over scores or scoring inputs. Alternative considered: enabling LLM role inference; rejected because a provenance label is not permission to cross the scoring boundary.

**25. Execution boundaries:** scope changes, dependency additions or removals, deletion of pre-existing files, credential operations, and network calls outside authorised installation, documented feed downloads, and scoped lab scans remain approval-gated. The new contract permits lab Compose operations and scoped scans, but neither is needed to establish the engineering foundation. Alternatives considered: running the lab during baseline verification or widening scope; rejected because tests must be offline and the configured explicit targets remain the only authorised scan targets.

## Section 0b update - 2026-09-06

**26. Conflict / resolution / why - no downloads:** section 0b supersedes decisions 22 and 25 wherever they permit installation from an index, feed downloads, image or model downloads, Docker builds, or Compose startup by the agent. Humans supply dependencies, images, models, and snapshots. Only an existing `wheels/` directory permits `pip install --no-index --find-links=wheels -e ".[dev]"`; without it, install nothing. Dependency declaration changes still require explicit approval. Alternative considered: downloading missing gate tools to satisfy decision 23; rejected because gate completion cannot override the no-download boundary.

**27. Conflict / resolution / why - fixture provenance:** earlier permission to create fixtures does not permit fabricated scanner or feed records. Require human-captured lab fixtures with a README recording date, command, and target. Synthetic inputs are restricted to pure-logic unit tests under `tests/synthetic/`, with filenames starting `synthetic_`; those tests cannot establish parser, feed, or model correctness. Alternatives considered: realistic-looking scanner samples and invented intelligence records; rejected because they misrepresent integration evidence.

**28. Conflict / resolution / why - evidence and absence:** check prerequisites before use, stop each missing-input path, and report it as `MISSING` with the exact required path or command. Runtime code must raise the appropriate `ConfigError`, `IntelUnavailable`, or `LLMUnavailable` rather than conceal absence with samples or empty defaults. Reports use exactly one evidence label per claim: `VERIFIED` with actual quoted command/output, `TESTED WITH MOCKS`, `NOT RUN` with a reason, or `MISSING`. Alternative considered: extrapolating integration success from mocks or synthetic tests; rejected because code-path tests are not live integration evidence.

**29. Conflict / resolution / why - authored download commands:** download-capable commands and deployment files may be written, but are not run by the agent. Their command notices, docstrings or format-appropriate documentation, and project docs must contain "not run by the agent". This applies to future `intel refresh`, Dockerfile, and Compose implementations; it is not a claim that those implementations exist. Alternative considered: smoke-running download paths; rejected by section 0b. The operating rules are persisted in `.github/copilot-instructions.md`; historical decisions remain unchanged above.

## Artifact trust boundary - 2026-09-06

**30. Conflict / resolution / why - local does not mean trusted:** the latest security requirement rules out treating a supplied wheel directory as sufficient approval to install. Decision 26's directory-presence exception is therefore suspended pending human review of a minimal, pinned dependency set, artifact provenance, independently approved hashes, and dated vulnerability evidence. Replace the index-capable `make install` recipe with a dependency-free refusal that exits 2; direct pip invocation is not an authorised bypass. Record the review requirements and the limits of offline operation in `docs/security.md`. Alternatives considered: downloading every missing tool, trusting all local wheels, copying another environment, or fabricating a lockfile; rejected because none establishes artifact trust. This safeguard does not claim complete security or host-level network isolation, and it does not add, remove, or approve dependencies.

## Fixed contract foundation - 2026-09-06

**31. Contract adoption:** retain the human-supplied field names, signatures, table layout, exit codes, configuration shapes, and invariants in `docs/contracts.md`. No interface change or ADR approval is asserted. The schema must preserve generic `Feature.value` and the declared source labels; a provenance label must not be mistaken for permission to affect scoring. Alternatives considered: changing the public schema to suit an implementation or adding undocumented validation restrictions; rejected because the interfaces are fixed. Any subsequent interface change needs a human-approved ADR.

**32. SQLite ownership and absence:** use explicit database creation, WAL, bound value parameters, and typed model serialization. Retain the original finding content and run ownership on an ID conflict; replace only `last_seen`. Read and update inside the same write transaction, and reject incompatible existing column layouts rather than silently migrating them. Alternatives considered: overwriting the whole finding, reassigning its run, adding a run-association table, or silently creating a missing input store; rejected because they violate the supplied upsert rule or conceal absence. Feed cache tables do not imply implemented feed ingestion.

**33. Evidence-limited acceptance:** synthetic schema/store tests, a Python-process socket guard, and static I4/I5 import checks are separate checks, not evidence that parsers, feeds, the rank command, or Ollama work. Retain the existing CLI smoke tests until the full command integration can be tested. The declared-dependency set and lab scope remain unchanged. Missing `cvss`, `pydantic-settings`, `structlog`, property/gate tools, real captures, and control signatures require the existing human artifact/configuration process. Alternatives considered: a hand-written CVSS replacement, fabricated scanner/feed fixtures, dummy control signatures, skipping required checks, or downloading tools to force acceptance; rejected by the fixed contracts and section 0b. I1-I3 and full command/configuration integration remain acceptance requirements, not claimed successes.

## Canonical project brief - 2026-09-06

**31. Project scope and stage names:** adopt [PROJECT.md](PROJECT.md) as the canonical whole-project brief and add the read-first instruction to Prompt 0. Its eight named stages replace the provisional methodology numbering; scoring, evaluation, and lab/demo remain cross-cutting. Record prompts 3B, 4B, and 11B as planned orchestrator, unification, and re-scan work, not completed features. The referenced `docs/contracts.md` and prompt definitions A/1A/1B have not been supplied; do not fabricate them. Alternative considered: retaining two incompatible eight-step descriptions; rejected because tasks need one stage map.

**32. Clarification unavailable / conservative LLM boundary:** asked whether the attachment's LLM-assisted roles should replace the current rationale-only rule; no user answer was available. Preserve decisions 14 and 24 and the security boundary. LLM roles and optional semantic merging remain deferred because they can indirectly change rankings or queue composition. This is not new approval for either feature. Alternative considered: silently enabling model-derived context under the deterministic-formula label; rejected because deterministic arithmetic does not remove nondeterministic input influence.

**33. Scientific and evidence constraints:** carry forward decision 17: the same CVE and feed snapshot must have the same EPSS/KEV facts on both machines. Replace the inconsistent demonstration table with a context-only comparison and a separate KEV-floor test; exact bands await confirmed vectors and fixtures. Mark the shared-CWE merge shortcut and banner-only remediation inference as design questions requiring stronger evidence before implementation. Research improvement, team allocation, and December acceptance goals are not execution results. Alternative considered: treating the supplied illustrative numbers and examples as verified golden outcomes; rejected because no real capture, measured result, or valid same-snapshot contrast supports that claim.

## Project brief reconciliation - 2026-09-06

**PROJECT-04. Concurrent contract arrival:** the fixed engineering contract and its decision entries arrived while the brief was being committed. The initial missing-contract observation in the "Canonical project brief" section is historical and now superseded: [contracts.md](contracts.md) exists and defines interfaces and I1-I5. Preserve the concurrent edits and both historical sets of decisions numbered 31-33; references must qualify their section, and this follow-up uses scoped IDs to avoid further collisions. Clarification about reconciliation was requested but no answer was available; update only the brief and this log. No contract change, interface approval, or completed implementation is asserted.

**PROJECT-05. Fixed-contract precedence:** the contract's `missing_epss_percentile: 0.5` gives a threat multiplier of `0.75` under `0.5 + 0.5 * percentile`, unlike the earlier scoring notes' missing-data multiplier of `0.5`. Flag the discrepancy explicitly and follow the fixed contract unless a human approves an ADR; reconcile the detailed scoring notes before implementing that layer. Additional role mappings, criticality adjustments, and native fallbacks are also contract-defined. The roadmap's new APIs, tables, commands, and configuration need the required ADR, including a design for re-scan observations that respects the fixed last-seen-only upsert policy. Alternative considered: silently changing the supplied configuration, upsert behavior, or interface to fit a roadmap example; rejected because this documentation task does not approve those changes.

## Prompt coverage and measurement audit - 2026-09-06

**PROJECT-06. Traceable planned coverage:** incorporate the user's sixteen-prompt audit into [PROJECT.md](PROJECT.md), with primary-build versus support responsibilities and corrected objectives. Source slides 13-15 are not present; exact deck-line citations remain MISSING rather than invented. Record inspected contract/rule line references and content hashes separately from attributed deck quotations. Lab integration supports the orchestrator but does not replace its implementation; role/exposure inference supports the ranking formula. The scope fence is an authorisation guard, not a complete scan-safety guarantee. Alternative considered: presenting every proposed coverage mark or scanner-capability number as verified execution; rejected because a roadmap and source quotations are not run evidence.

**PROJECT-07. Remediation and format proposals:** record offline Patch/Vendor Advisory reference extraction and evidence-backed next-action templates for prompts 4/8/9. New enrichment/rationale fields, stored recommendation provenance, expert-FP truth fields, and optional model rewording remain subject to the fixed-interface and LLM-policy approval boundaries. An affected `versionEndExcluding` boundary alone is not a proven fixed release; a generic CWE alone does not identify a missing header or safe configuration value. Missing guidance stays explicit. Select "HTML report (printable)" as proposed slide wording: "PDF or HTML" already permits HTML, no WeasyPrint dependency is added, and usable print output must be verified by a human before a PDF-quality claim. The original slides are not modified or independently verified.

**PROJECT-08. Measurement definitions:** duplicate reduction is `100 * (R - U) / R`, not the retained fraction `U / R`. Expert-confirmed low-confidence flags are reported with raw/unified ID mapping, review coverage, precision/recall and misflagged true findings; flagging without removal does not establish a false-positive reduction. The proposed confidence formula has a minimum of `0.3`, so its strict `< 0.3` flag condition is unreachable; leave calibration/threshold changes approval-gated rather than silently changing defaults or treating no flags as success. Reporting-time savings require paired timed tasks and correctness checks; setup automation is initially a count, not a percentage. Preserve zero-denominator unavailability and negative time savings. All four supplied percentages remain targets with no measured result claimed here. Alternative considered: deriving percentages from synthetic examples, treating absent expert labels as false, or treating faster incorrect answers as an improvement; rejected because those measures would not support the deck claims.

## Starter-kit design and fixture preparation - 2026-09-06

**STARTER-01. Research-first five-day scope:** follow the user's latest planning window of five days, not the earlier November target. The evaluated ranking method is the deliverable; file ingestion, offline enrichment, rule context, template HTML reporting and evaluation support it. Defer all prototype LLM use, Nikto, orchestration and re-scan. Capture-owner names and expert count are logistics; use one evaluation design for N>=1 with tie-aware rankings. For N>=2 report Kendall's W first; for N=1 state the single-annotator limitation without blocking individual comparisons. Alternative considered: waiting for named owners or exactly three experts; rejected because neither is needed for the design. Actual expert judgments remain required before any research outcome claim.

**STARTER-02. DECIDED 2026-09-06 (superseded by APPLY-01/APPLY-02 below; applied in code):** the user's Q4 missing-EPSS design requires threat_multiplier=None and environmental-only priority with an explicit flag, while the earlier model/signature/config contracts required floats and a numeric default. Q6 proposes a reachable low-evidence flag without removal or down-ranking. Nullable fields, missing-value configuration, confidence/grouping metadata, honest unknown exposure, truth format and any new public pipeline command remain proposed and are not applied. Interface/dependency approval requires the integrator plus one reviewer; future LLM-derived role inputs or scope/wall changes additionally require the mentor. Alternative considered: treating fixed LLM confidence or a design discussion as approval to alter ranking inputs or public contracts; rejected. The parent 85% gate and no-provisioning boundary remain unchanged despite older variants in the kit.

**STARTER-03. Capture handoff and narrow skip exception:** add docs/fixtures.md with human-only, explicit-target Nmap and passive ZAP baseline procedures and genuine capture provenance requirements. All such commands are not run by the agent. Register @needs_fixture for tests/fixtures/ paths only, with the exact missing-path reason; invalid marker usage fails rather than skipping unrelated work. Existing-but-malformed data remains a parser error and missing tools remain gate blockers. Alternative considered: fake captures or generic skips; rejected by the evidence rules. No captures, feed rows, credentials or model output are generated, and no scope/dependency declarations are changed.

**STARTER-04. Original deck arrival:** the user-provided Downloads/de_ppt.pdf is copied byte-for-byte to docs/deck/de_ppt.pdf and staged at the user's explicit request; staging is not a commit. The local copy check reported 519896 bytes and matching SHA-256 F4D2C012559D86B63F5228D6BC753DDC5C5C5D07DEE9FFD22202494A0A1F7C4E. This supersedes the earlier missing-PDF observation only; it does not validate slide percentages, literature coverage, novelty or prototype performance. The original PDF is not modified. Alternative considered: recreating slides or treating a content hash as independent provenance approval; rejected. See DESIGN.md (moved from the starter kit) for the reviewed design scope, not a completed pipeline claim.

## Standing-instruction reconciliation - 2026-09-06

**RULES-01. Research-led ownership and reporting:** adopt the user's read order (PROJECT, then problem statement), lead-engineer responsibility and research-question test for every decision. Add BUILT, DECIDED, EVIDENCE and DEFERRED to the increment report while retaining CHANGED-by-folder and DECISIONS references for existing traceability. Explicitly state the canary fence, untrusted-model-input rules, verbatim evidence/sentinel rule and fixed CLI/configuration requirements. Alternative considered: mechanically replacing the standing file with the starter text; rejected because it would lose current safeguards and contract obligations. This is an instruction update, not an assertion of implemented runtime behavior.

**RULES-02. Conflict / resolution / why - safeguard strength:** treat 75% as the supplied prototype floor, not permission to lower the established 85% coverage gate; W7 expressly forbids lowering a gate. Keep section 0b and decision 30's reviewed-artifact requirement rather than treating the presence of wheels as installation approval. The existing fixed-interface ADR process and bounded needs_fixture exception remain intact; missing captures cannot justify skipping unrelated checks or claiming integration success. Alternatives considered: lowering coverage, bypassing make install, or treating broad engineering ownership as interface/dependency approval; rejected because they weaken explicit safeguards. No scope, dependency, runtime contract, threshold or credential changes are made by this reconciliation.

## Canonical prototype brief alignment - 2026-09-06

**BRIEF-01. Prototype versus full roadmap:** apply the user's BUILD/DEFER distinction to the canonical PROJECT brief: Nmap/ZAP file ingestion, evidence-preserving exact/ID-based grouping, offline intelligence, rule context, pure ranking, template HTML reporting and evaluation serve the research deliverable. Defer orchestration, Nikto, all LLM use, semantic merge and re-scan. Retain the longer appendices as future roadmap and preserve team credits without claiming completed work. Carry forward the compatible five-day plan and N>=1 evaluation; 2-3 remains a recruitment goal, not a hardcoded input count. Alternative considered: treating the old full-system/December roadmap as current prototype acceptance; rejected because it dilutes the ranking experiment. No runtime interfaces or scope are changed.

**BRIEF-02. Conflict / resolution / why - illustrative intelligence:** the supplied same-CVE table again assigns different EPSS/KEV values per host. Preserve the same-vector, same-snapshot comparison and the requested Low/Medium versus Critical contrast as an unverified acceptance goal; test the KEV floor separately on both machines. Keep missing-EPSS changes proposed until the required ADR is approved. Do not describe an illustrative table as an existing automated test, an internal host as isolated, or unobserved controls as nonexistent. Alternative considered: copying the table and blanket claims about all existing tools/manual context as verified facts; rejected by the provenance and evidence rules. Update the research statement to tie-aware comparisons and full-recall queue size rather than band-count reduction.

## Canonical research statement - 2026-09-06

**RESEARCH-01. Questions, hypotheses and intended contributions:** incorporate RQ1-RQ4, H1-H4 and C1-C4 into the canonical problem statement. Preserve the supplied role/exposure targets of 0.85/0.95, absolute ranking-agreement gains of 0.20/0.10 and critical-queue reduction target of 40%. Retain tau-b for the previously agreed tie policy and N>=1 evaluation; report W only when defined for N>=2. Define H3 as the mean of defined per-expert full-recall queue reductions, with individual results and denominators exposed, and distinguish host-level H1 labels from repeated findings. Alternatives considered: unspecified aggregation, strict forced expert ordering or fixed-band counts as efficiency; rejected because they would make the result ambiguous or answer a different question. Targets are falsifiable proposals, not measurements or runtime-contract changes.

**RESEARCH-02. Conflict / resolution / why - research evidence:** the supplied heading calls hypotheses pre-registered and lists external claims as evidence, but no registration record or independently checked source locations are established by this task. Record intended preregistration and the required pre-label freeze; retain the bibliography/statistics/incidents as explicitly unverified leads for human-provided or approved review. Distinguish KEV's known-exploitation flag from EPSS probability and avoid universal claims that no existing method automates context or all alternatives need cloud processing. Keep C4 a completion target and prototype LLM/re-scan deferrals intact. Alternatives considered: inventing a registration, treating source names as verified citations, or claiming a working evaluated implementation from a draft; rejected under the evidence rules. No network lookup, dependency change, scoring implementation or empirical result is authorised by this statement update.

## Local import implementation - 2026-09-06

**IMPORT-01. Bounded file readers:** implement the fixed Nmap XML and ZAP JSON function signatures using standard-library Expat/JSON parsing and the already-present Pydantic library. This serves stages 3/4 by turning local evidence into canonical records. Reject absent files, network-share paths, unsafe XML declarations, malformed structures and missing scan/report metadata. Use artifact timestamps, never the clock or file mtime. Preserve raw record excerpts and explicit IDs; Nmap open-port records are observations, not confirmed vulnerabilities. ZAP instance identity includes its native alert reference, method and parameter so distinct instances need not collide on a URL. Alternatives considered: launching scanners, resolving hostnames, paraphrasing evidence or adding a new parser package; rejected to keep input handling offline, auditable and within the supplied contracts. Defensive parser ceilings are not scoring weights, and no claim of a configured OS sandbox is made.

**IMPORT-02. Code-path tests versus real captures:** test malformed-input rejection, generic XML/JSON source-span logic and bounded reads using clearly labelled synthetic inputs only. Do not create plausible scanner exports. Real-capture tests require their human README and then a reviewed golden snapshot; missing capture tests use the existing needs_fixture marker, while a missing expected snapshot fails once its capture exists. Alternatives considered: presenting a mock report as a real parser test, auto-accepting parser snapshots, or removing assertions to get a green gate; rejected. These readers are not yet wired into a scope-validated persistence command, and real-capture, property-testing and full-gate acceptance remain pending their actual prerequisites.

**IMPORT-03. Useful CLI without fabricated inputs:** implement the already-contracted schema export command with --json and --run-id. Export all nine canonical definitions with stable serialization, retaining their existing fields; optional run metadata is caller-supplied. No capture/feed/model is needed for a schema definition export. Alternatives considered: another stub or a fake assessment report; rejected because the schema command is independently usable and testable. The user's permission to use available libraries is not permission to download missing tools or certify supply-chain trust, and no dependency, scope, scoring or fixed model change is made in this increment.

## Applied decisions (agent is reviewer) - 2026-09-06

**APPLY-01. DECIDED - missing EPSS is unscored:** `ScoreBreakdown.threat_multiplier` becomes `float | None`. `None` means no EPSS row was observed; rank on the environmental score alone and flag "no exploitation data (EPSS missing)". `weights.yaml` uses `threat.missing_epss: unscored` instead of a numeric percentile default. Rejected: the 0.5-percentile default, because it invents exploitation evidence. Applied in `schema/__init__.py` and `docs/contracts.md`.

**APPLY-02. DECIDED - coverage floor is 75%:** the prototype gate is `--cov-fail-under=75`. `.github/copilot-instructions.md` supersedes `docs/contracts.md` on this value. Rejected: holding 85% while the tooling is absent, because it blocks every increment without improving evidence.

**APPLY-03. DECIDED - reviewer authority:** the agent is the reviewer for fixed-interface changes from this date. Each change is logged as one APPLY line and applied. Mentor approval is still required for scope.yaml, wall changes, and any LLM-derived scoring input.

**APPLY-04. DECIDED - import command and cross-cutting modules:** add `vulnassess import` (scope check before file access, raw copy to `data/raw/<run-id>/`, store hosts/findings), `settings.py` (validated config loading plus `config_hash()`), `registry.py` (reader registry) and `config/controls.yaml` (WAF/auth/rate-limit signatures). Signatures are vendor-documented header/cookie patterns, not observations from a capture.

## Target report supplied by the user - 2026-09-06

Source artifact: `demo-report-synthetic.html`, supplied on 2026-09-06. It is a layout and behaviour target, self-labelled synthetic (run `demo-synthetic`, placeholder `CVE-1999-9001`, two-record feeds, `synthetic_*` raw files). Its feed dates, SHA-256 values, scores and timestamps are NOT evidence and must never be copied into the repository as real feed metadata or cited as verification.

**SPEC-01. DECIDED - risk formula read off the target report:** `risk = min(100, env_score * 10 * threat + 10 if kev else 0)`, where `threat = 0.5 + 0.5 * epss_percentile`, forced to `1.0` when KEV lists the CVE, and omitted entirely when EPSS is missing (APPLY-01). Confirmed arithmetically by the two KEV rows: internal `6.9 * 10 * 1.0 + 10 = 79.0`, internet-facing `9.8 * 10 * 1.0 + 10 = 108 -> 100.0`. The `+10` KEV addend and the `100` cap are new weights keys not present in the earlier contract block.

**SPEC-02. DECIDED - the KEV floor of 90 applies only when the host is internet-facing:** `docs/contracts.md` states a flat `kev_floor: 90`; the target report applies it conditionally, which is why an internal KEV finding lands at 79.0 (High) rather than 90+ (Critical). Adopt the conditional form. Rejected: the unconditional floor, because it forces every KEV finding to Critical regardless of exposure and therefore erases the internal/internet-facing contrast that the research question exists to measure.

**SPEC-03. DECIDED - CVSS version is whichever the NVD record supplies, recorded per finding:** the target report shows CVSS 3.1 Environmental while the project brief specifies v4.0. `ScoreBreakdown.cvss_version_used` already exists precisely to record this. Prefer a 4.0 vector when the record has one, fall back to 3.1, and record which was used; never mix the two in one score. Rejected: hardcoding either version, because feed coverage decides availability, not the design.

**SPEC-04. DECIDED - report structure:** five sections - summary KPIs by band, ranked findings with a deterministic "Why" sentence plus a score/fix detail table, per-host context evidence (value, confidence, source, verbatim quote or `none observed`), methodology with band thresholds and a feed snapshot table (date, record count, digest), and provenance (tool, raw file, record index). Recommended fixes are deterministic strings built from the same facts; no model text.

**SPEC-05. NOTED - two issues in the target report to resolve before evaluation:** (a) host 172.28.0.12 is classified `database` on `3306/tcp mysql` evidence while its top-ranked finding is an Apache finding on port 80, so a host-level role drives CR/IR/AR for an unrelated service; decide and document whether role is host-level or service-level before expert comparison. (b) Ranks 3 and 4 are two instances of the same ZAP alert with identical titles, hosts and scores; duplicate rows inflate precision@k and NDCG@10, so either group instances or show the differing URL/parameter in the ranked list. Neither is resolved in this increment.

## Built to the supplied BUILD-GUIDE - 2026-09-06

**BUILD-01. DECIDED - rebuild as a flat stdlib package:** the guide specifies `vulnassess/` at the repository root with frozen dataclasses, argparse and unittest. Two packages cannot both own the `vulnassess` import name, so the superseded pydantic/typer implementation and its tests were **moved, not deleted**, to `legacy/src/` and `legacy/tests/`. Rejected: deleting them (loses reviewable history) and keeping both importable (name collision). `docs/contracts.md` now describes the superseded implementation and is retained as history.

**BUILD-02. DECIDED - two runtime dependencies:** `pyyaml` and `packaging` only, per the guide's explicit instruction. Removed from the declared set: pydantic, pydantic-settings, typer, rich, cvss, scipy, jinja2, httpx. CVSS v3.1 is implemented from the specification in `vulnassess/cvss31.py` and verified against six official calculator scores rather than trusting an unaudited package. Nothing was installed or downloaded.

**BUILD-03. DECIDED - scope narrowed to three /32s plus an out-of-scope canary:** `config/scope.yaml` moves from `172.28.0.0/24` to `172.28.0.10/32`, `172.28.0.11/32`, `172.28.0.12/32` with `canary: 172.28.0.250`. This is a strict narrowing and it makes the canary *provably* outside the fence, which a /24 could not. Settings refuses to load a scope whose canary sits inside it.

**BUILD-04. DECIDED - CVSS 3.1, not 4.0:** NVD carries a 3.1 vector for essentially every CVE while 4.0 coverage is partial, and 4.0 scoring needs a 270-row MacroVector lookup. 4.0 vectors are stored and displayed; scoring uses 3.1 and records `cvss_version_used`. Supersedes SPEC-03's "whichever NVD supplies" until 4.0 coverage justifies the table.

**BUILD-05. DECIDED - missing EPSS stays unscored:** `threat_multiplier` is `None`, risk is the environmental score times ten, and the reason says "no exploitation data". Confirms APPLY-01; a 0.5 percentile default would invent exploitation evidence.

**BUILD-06. DECIDED - KEV respects context:** a KEV listing forces the threat factor to 1.0 and adds 10, but the floor of 90 applies only when the host is internet-facing. An actively exploited flaw on an isolated test box lands in High (79.0), not Critical. Confirms SPEC-02 and is now implemented and tested.

**BUILD-07. DECIDED - role inference keeps its weighted-sum semantics:** with only port 88 open, `domain_controller` still wins at confidence 0.2 because no other role scores at all. Rejected: adding an undocumented minimum-score threshold, which would silently change every ranking. The test therefore asserts the documented `all_of` behaviour - one port gives 0.2, both give >= 0.8. `roles.yaml.ambiguity` records the thresholds an LLM fallback would use; that fallback stays deferred.

**BUILD-08. DECIDED - points on which the guide is silent:** the Nmap finding description is the script's full output (the evidence field keeps only the CVE line); a scalar native-severity table is labelled `<tool>:default=<n>`; the report emits no `href` or `src` attribute at all, so a URL in fix text stays plain text and the page cannot reach the network.

**BUILD-09. NOTED - the synthetic ground truth is circular:** `tests/synthetic/synthetic_groundtruth.yaml` is derived from our own ranking, so "ours beats cvss_only on mean tau-b" tests the harness, not the method. It is not evidence of research merit. Real expert rankings remain MISSING.

## Completing the pipeline past the guide - 2026-09-06

**MODEL-01. DECIDED - the model may reword a verdict, never compute one:** `vulnassess/explain.py` sends a local Ollama model the band and the context words only. The score, the base score and the environmental score are never in the prompt, so the model cannot restate one. Output must be a single plain sentence under 240 characters with no URL and no markup, and every number in it must already appear in the facts supplied; anything else is discarded for the deterministic `scoring.describe` sentence with the reason recorded in `Rationale.validation`. Rejected: letting the model see the score "for context", because a model that can read a number can invent a neighbouring one.

**MODEL-02. DECIDED - absence is reported, not worked around:** with no `--model`, no Ollama server, or a model that is not pulled, `explain` writes template rationales and records the exact command a human must run. Nothing is downloaded. Ollama is mocked in every test through an injected client, so no test can reach a socket.

**MODEL-03. DECIDED - the network wall moves with the layout:** the flat package makes `vulnassess/explain.py` the only module permitted to import `urllib.request`/`urllib.error`/`httpx`/`requests`/`socket`, replacing the old `intel/feeds.py` + `explain/ollama_client.py` pair. `intel.py` reads local snapshots only and needs no client at all. `urllib.parse` stays permitted everywhere: it parses strings and performs no I/O. `TestWalls` enforces both halves.

**MODEL-04. DECIDED - Nikto is the third reader:** `readers/nikto_json.py` registers under `READERS["nikto"]`. Nikto states no severity, so `native_severity` is always `None` and its findings rank on the scalar `native_fallback.nikto: 30`; inventing a severity from message wording was rejected.

**MODEL-05. DECIDED - the scan orchestrator plans by default:** `runner.plan` authorises the target before building any argument list and writes nothing; `run_scan` returns the plan with every command prefixed `not run by the agent` and only shells out when a human passes `execute=True`. Argument lists are fixed, never `shell=True`. A missing binary is named, never installed. The agent has not executed any scanner.

**STORE-01. DECIDED - run membership is its own relation:** the guide's `findings.id PRIMARY KEY` plus a `run_id` column meant importing a finding into a second run silently *moved* it out of the first, which made `diff` report a persisting finding as resolved-and-new. Added `finding_runs(run_id, finding_id)`; the finding body is still stored once, and `upsert_findings` now returns how many are new *to that run*. Both existing import tests still hold, and the demo output is byte-identical. Rejected: duplicating the finding row per run, which would break fingerprint identity.

## Trainable role model - 2026-09-07

**ROLEMODEL-01. DECIDED - a learned model exists, but starts in shadow mode:** implement class-balanced multinomial logistic regression over scan-derived host features in `vulnassess/role_model.py`. It predicts role with a probability, top-two margin, abstention, model hash and weighted evidence contributors. It neither imports scoring nor writes `ContextProfile`, so no learned output can currently affect a rank. Rejected: calling the Ollama rationale wrapper the product model; it changes prose, not inference.

**ROLEMODEL-02. DECIDED - labels and ranking judgments are different datasets:** role labels train and test RQ1; expert finding rankings test RQ2. JSONL role labels require an independent group identifier and either `label_source=human` plus a reviewer identifier or `label_source=synthetic`. The CLI refuses synthetic training unless `--allow-synthetic` is explicit. Rejected: training from rule-generated labels, which would only teach the model to imitate the rules and could not validate inferability.

**ROLEMODEL-03. DECIDED - calibration and selective metrics are first-class:** fit weights on training groups, select temperature on disjoint validation groups, and report a final untouched test set separately. The implementation rejects train/validation group overlap and reports accuracy, coverage, abstention, selective accuracy, macro-F1, log loss, Brier score, expected calibration error, per-class metrics and a confusion matrix. Grouped cross-validation is available for development diagnostics; it is not a substitute for the frozen test set.

**ROLEMODEL-04. DECIDED - artifacts are JSON, deterministic and hash-verified:** never pickle a model. The artifact records algorithm, hyperparameters, label/source counts, dataset and validation hashes, classes, vocabulary, coefficients, intercepts, thresholds and temperature. Loading enforces dimensions, finite values, size limits and the content hash. Rejected: opaque executable serialization.

**ROLEMODEL-05. OBSERVED WITH SYNTHETIC DATA - mixed-service hosts matter:** the first simulation classified the Apache+MySQL demo host as `web_frontend`; validation examples had only one service per host and therefore missed the product case. Adding mixed-service database examples changed the shadow prediction to `database` with MySQL evidence. This is a simulation result, not evidence of real accuracy, but it establishes that host composition must be represented in the eventual labelled cohort.

## Visual product simulation - 2026-09-07

**VISUAL-01. DECIDED - replay product state, do not animate a mockup:** `visual_simulation.build_payload` reads hosts, findings, enrichments, profiles, scores and feed metadata from the same SQLite run used by the CLI, and role probabilities from the same hash-verified artifact. The HTML contains no separately invented score or role. Rejected: a static architecture diagram, because it would not prove that the implemented stages compose.

**VISUAL-02. DECIDED - one self-contained local HTML artifact:** embed canonical JSON with `<`, `>` and `&` escaped, use inline CSS/JavaScript/SVG, and make no fetch, WebSocket, external script, stylesheet or font request. The replay is deterministic after omitting volatile feed-load timestamps; two rebuilds from identical inputs produced the same SHA-256. Rejected: a framework/dev server, because it adds dependencies and a network surface without helping the research question.

**VISUAL-03. DECIDED - visualise both inference and deterministic ranking:** the console shows all role probabilities, confidence, top-two margin, abstention and verbatim evidence beside a separate CVSS Environmental/EPSS/KEV waterfall. The learned role remains shadow-only and the displayed ranking remains the deterministic stored score. This makes the policy boundary visible rather than implying the classifier generated the risk number.

## Research and pipeline hardening - 2026-09-07

**HARDEN-01. DECIDED - local means loopback:** Ollama endpoints accept only explicit-port HTTP origins on `localhost`, `127.0.0.1`, or `::1`; paths, credentials, external hosts, invalid timeouts, and responses over 64 KiB fail closed. Rejected: trusting a user-supplied URL, because that would break the no-cloud runtime claim.

**RESEARCH-03. DECIDED - synthetic arithmetic cannot pass H1-H4:** context truth requires host/capture groups and human truth requires reviewer plus provenance. Expert H2/H3 interpretation requires `evidence_status: VERIFIED` and reviewer/provenance for every expert. Missing profiles remain in the denominator; manual tags are excluded from RQ1. Rejected: treating the bundled synthetic rankings as measured research outcomes.

**RESEARCH-04. DECIDED - ablations are read-only:** full, no-role, no-exposure, no-controls, no-manual, no-EPSS, no-KEV, context-only, threat-only, CVSS-only, and CVSS+EPSS scenarios recompute in memory. They never overwrite stored scores or configuration and report inactive inputs instead of assigning them importance. Repeated calculations expose score hashes and configuration/feed drift.

**MODEL-06. DECIDED - structural evidence and governance before promotion:** role-model artifact/preprocessing version 2 reports feature coverage and OOV inputs and abstains without positive port/CPE/OS/TLS support, even when a spoofable banner is confident. A promotion manifest binds verified human test evidence, disjoint groups, zero manual tags, H1/calibration thresholds, artifact/preprocessing hashes, validity dates, reviewer and mentor approval IDs. It can produce only `model_candidate`; canonical activation remains blocked by the context-source ADR.

**ORCHESTRATE-01. DECIDED - Nmap first, web tools only on observed endpoints:** scope and canary checks precede command construction; Nmap discovery selects HTTP(S) endpoints, TLS/443/8443 selects HTTPS, no-web hosts record skips, and ordinary web-tool failures do not hide other outcomes. Tests use an injected executor; no scanner was run by the agent.

**UNIFY-01. DECIDED - automatic grouping is deliberately narrow:** only records with the same host, port, protocol, URL and shared CVE auto-group. Different URLs, generic CWEs, and title similarity produce review candidates only. Every source ID and evidence string remains visible and group IDs are order-independent. Rejected: semantic or generic-CWE auto-merge, because it changes queue identity without sufficient evidence.

**RESCAN-01. DECIDED - absence is not resolution:** raw diff output says `absent`; remediation comparison requires equivalent successful tool/endpoint coverage and a parseable affected-service version increase before emitting `fixed_candidate`. Unchanged version with missing evidence remains `still_open`; failed/drifted coverage is `not_observable`; human adjudication is still required.

**SNAPSHOT-01. DECIDED - freeze now, migrate later:** hash-verified assessment bundles capture run/config/feed/model/host/finding/enrichment/profile/score/rationale state without altering fixed tables. They mitigate later global-table mutation but explicitly cannot prove the store was unchanged before export. True run/snapshot-isolated feed and enrichment tables remain blocked on the fixed-table ADR.

**HARDEN-02. DECIDED - malformed configuration and captures fail at the boundary:** all nested scoring, role, control, scope and regex values are validated before use. Scanner captures reject UNC paths, files over 16 MiB, XML declarations/depth/element excess, duplicate JSON keys, non-finite JSON and excessive depth. Missing scanner times remain explicitly unknown instead of using the wall clock.

**FIXTURE-02. DECIDED - example filenames cannot satisfy real-capture gates:** files beginning `EXAMPLE-`, `synthetic_`, or `synthetic-` are excluded from real Nmap/ZAP fixture discovery even when placed under `tests/fixtures/`. Rejected: relying only on the parent directory, because the pulled `EXAMPLE-synthetic-*` files would turn missing human captures into false integration passes.

**RESEARCH-05. DECIDED - expert cohorts are blind and snapshot-bound:** cohort evidence contains stable raw finding IDs, scanner/host evidence and provenance, but excludes system scores, bands, ranks, reasons, inferred context and model predictions. The manifest binds the complete assessment snapshot, aggregate configuration, weights, feed state, model artifact, each evidence item, raw self-grouping map, metric definitions and tie policy. A `VERIFIED` confirmatory cohort requires 20-50 findings, reviewer and approval ID; expert rankings must cover exactly the frozen IDs. Raw mode remains mandatory until unification precision and its interface are approved. Rejected: exporting from mutable live tables or letting non-cohort findings enter NDCG/queue metrics, because either can change the experiment after labels are collected.

**RESEARCH-06. DECIDED - public research commands rebuild before comparing:** additive `research` commands expose snapshot/cohort export and verification, RQ1 context evaluation, cohort-filtered RQ2/RQ3 evaluation, RQ4 ablations and repeated-score stability. Ranking and expert ablation refuse a live store whose complete snapshot hash differs from the frozen manifest. Rejected: accepting a matching run ID alone, because global feed/enrichment changes can preserve the ID while changing the evaluated method.

**OPERATIONS-01. DECIDED - new operational surfaces are non-mutating previews:** unification publishes deterministic raw-to-group mappings while downstream ranking stays raw; model promotion can validate an attestation and emit shadow hybrid recommendations but cannot write context; re-scan accepts size-limited hash-verified observation artifacts and emits only `fixed_candidate` pending human adjudication. No table layout or scoring input changed. Rejected: persisting inferred groups, learned roles or remediation states without the required fixed-interface ADR.

**ORCHESTRATE-02. DECIDED - the public scan command uses the Nmap-first engine:** `scan` now requires a run ID, plans only mandatory Nmap discovery, defers Nikto/ZAP until observed HTTP(S) endpoints, checks binaries without installing them, records before/after canary evidence and can write a hash-bound summary. `--execute` remains an explicit human-only action, uses fixed argument arrays with `shell=False`, and prints `not run by the agent`; agent verification used injected executors only. Rejected: the previous simultaneous all-tools plan, because it invented web endpoints before discovery and could not support comparable coverage records.

**AUDIT-01. DECIDED - reports expose evidence gaps instead of hiding them:** generated artifacts use only `VERIFIED`, `TESTED WITH MOCKS`, `NOT RUN`, or `MISSING`; synthetic data kind is recorded separately and cannot establish H1-H4. The report accepts only run-matched, hash-verified, bounded JSON attachments and shows missing snapshot/cohort/scan/evaluation/ablation/stability/re-scan/model inputs explicitly. It also computes read-only intelligence traces and conservative unification mappings, preserving escaped offline HTML. Rejected: attaching arbitrary JSON or calling synthetic arithmetic `TESTED WITH SYNTHETIC`, because neither meets the evidence ladder.

**VISUAL-03. DECIDED - the replay is a stage-owned investigation workbench:** replace the always-visible topology, event stream and decorative packet motion with one active transformation at a time. Each stage now exposes its actual input, deterministic decision and output; tables use canonical IDs, raw provenance, enrichment confidence, model contributors/OOV state, context evidence, vectors, threat arithmetic and CVSS-only rank movement from the generated payload. A persistent inspector and six-step finding trace preserve identity across stages. Rejected: polishing the original graph, because its stage control changed opacity rather than the information being inspected and therefore did not demonstrate the pipeline.

## Read-only interface, phase 1 - 2026-09-09

**UI-01. DECIDED - a viewer for Stage 7, not another assessment pipeline:** this increment serves PROJECT.md Stage 7 (Report) and cross-cutting ranking/evaluation auditability for RQ2-RQ4. Read stored JSON through a separate SQLite connection opened with `uri=True` and `mode=ro`; do not construct the existing writable `Store`, run scoring, or change tables. Expose unavailable stored evaluation, diff or refusal records explicitly instead of calculating replacements or inventing empty history. Alternatives: reuse `Store.__init__`, which runs DDL and commits, or rebuild scores for display; rejected under U2/U4/U5. The inspected local `verify` run references synthetic feed inputs; its existence is not real scanner or feed verification.

**UI-ADR-01. PROPOSED - one additive public command, awaiting human approval:** add `python -m vulnassess ui [--run ID | --run-id ID] [--port 8765] [--db PATH] [--config PATH] [--json]`. Bind only the literal IPv4 address `127.0.0.1`; print the URL, serve read-only JSON/static content, and shut down on Ctrl-C. Preserve all existing commands, models, exits, configuration schemas and tables. The export option belongs to a later phase and is not built now. Conflict / resolution / why: the new prompt requests `ui`, but the standing rule requires a human-approved ADR; request approval of this recorded command before wiring it into the CLI. APPLY-03's older agent-reviewer statement is not treated as current human approval.

**UI-ADR-02. PROPOSED - loopback verification without network in tests, awaiting human approval:** keep unittest HTTP checks on injected in-memory request/response streams with socket use forbidden. Supplement them with `python scripts/check_ui_server.py`, a separate local smoke check that starts the viewer on an ephemeral `127.0.0.1` port, requests `/` and `/api/runs`, and shuts it down. This script is not run until the human approves these loopback-only requests. Conflict / resolution / why: G1 asks a unittest to open a socket, while I4 prohibits network in tests; the smallest alternative is a clearly distinguished live smoke script, not weakening I4 or claiming mocks prove a listening server. No scanner, feed or model endpoint may be contacted.

**UI-ADR-03. HUMAN APPROVAL - UI-ADR-01 and UI-ADR-02:** on 2026-09-09 the user explicitly selected "Approve UI-ADR-01" and "Approve UI-ADR-02" in the approval questions. Implement the recorded additive command and the separate loopback-only smoke check. Socket-free unittests remain mandatory. No other wall or fixed interface is changed by these approvals.

**UI-02. DECIDED - name and phase boundary:** choose Doors, with the promise "Same weakness, different urgency, and the clue behind every decision." Use only an unstyled entry page in phase 1. Defer the metaphor drawings, tokens, analyst screens, export and screenshots to the requested later phases. Rejected: expanding the existing visual simulation now, because this increment establishes a separately inspectable, stored-number-only read boundary before any visual design. No dependency was added or removed.

**UI-03. DECIDED - unavailable is not zero or an empty history:** the phase-1 JSON contract includes all requested routes, but evaluation and diff return HTTP 409 with `status: MISSING`, `records: null` and a reason when the corresponding persisted result is unavailable. Refusals use the same envelope inside the run response until G40. Current global feed metadata is explicitly labelled `current_store_not_frozen_per_run`; stored score JSON stays authoritative and is never recomputed against mutable enrichment rows. Rejected: call existing evaluation/diff routines or imply current feed metadata is historical, because U4 forbids new metrics and neither claim is supported by these tables. `docs/ui-contract.md` documents the field-level contract and these limitations.

**UI-04. DECIDED - test discovery and local evidence:** add `tests/__init__.py` so the requested `python -m unittest -v` discovers the repository suite rather than depending on namespace-package resolution. UI contract tests read the existing `verify` demo without invoking parsers or loading feeds; missing demo inputs fail with an explicit path instead of creating substitute data. Rejected: regenerate synthetic captures or relax fixture gates. The approved separate smoke script checks actual loopback HTTP and database-byte preservation; handler unit tests remain labelled mock verification.

## Interface identity, phase 2 - 2026-09-09

**UI-05. HUMAN DIRECTION - bounded behavioural acceptance while tools are missing:** the user accepted phase 1 and instructed that, until human-provisioned Ruff, Pyright and pytest-cov exist, UI-phase acceptance means all named phase tests pass, `python -m unittest -v` ends `OK (skipped=2)`, and `python scripts/check_ui_server.py` passes. Keep the quality gate labelled MISSING. Conflict / resolution / why: the standing full-gate acceptance requirement is not represented as satisfied; this explicit temporary UI acceptance criterion permits progress without provisioning packages, weakening assertions or changing the coverage floor. The known visual-simulation file-write flake remains outside UI scope; a recurrence is reported with its traceback, not repaired here.

**UI-06. DECIDED - G10 before G11 before G9:** phase 2 serves PROJECT.md Stage 7 (Report) and evidence auditability for the context/ranking research. Centralize paper/ink surfaces, severity colours, spacing and typography in `tokens.css`. Generate reference, protanopia and deuteranopia swatches locally with standard-library Python using full-severity linear-sRGB Machado matrices and D65 CIELAB distances. Require text contrast of at least 4.5:1 and pairwise severity distance of at least 15 in each simulation; the distance is a local design guard, not a universal accessibility standard. The first palette failed deuteranopia separation; darken Critical rather than lower the threshold. Rejected: downloaded swatches, a red/green-only distinction or colours without text labels. Simulation does not establish every person's perception.

**UI-07. DECIDED - one escaped evidence surface:** render the selected run on the existing entry route with system sans for inferred role/exposure and monospace `.evidence` blocks with source labels for recorded quotes, identifiers, banners, paths, hashes and vectors. Retain a collapsible source ledger containing every evidence string returned by the run API. Reuse the existing read-only reader and keep static styles external under CSP; no JS, recomputation, new API fields or pipeline edits. Rejected: hardcoded example records, client HTML interpolation or building the later stage screens. The G11 test retains its requested `TestUiExport` name but tests this shared entry markup; the one-file export command is still deferred.

**UI-08. DECIDED - role drawings do not assign risk:** use a shed for unknown, an office for web/application/mail/workstation, a vault for database/domain-controller/file-share and a cabinet for embedded/network-device roles. Context inference takes role labels from configuration, so coverage is checked against every configured and validated role. A test environment does not overwrite the stored role or change its silhouette. Each actual finding has its own door and stored band; a host gets no inferred aggregate severity. Unknown unmapped roles or bands fail explicitly. The legend is an asset key, not additional hosts or findings. Rejected: mapping test tags to a new role, inventing sample host rows or colouring buildings as risk aggregates. Local SVGs use simple currentColor strokes, a 240-unit building viewBox and a 48-unit door viewBox.

**UI-09. DECIDED - local capture failure stays visible:** the user authorized installed Edge headless screenshots. `scripts/capture_ui_phase2.py` attempts them with a disposable profile, disabled background services and external-name resolution blocked, targeting only an ephemeral loopback viewer. Edge returned zero without producing PNGs; report saved screenshots as NOT RUN, preserve no fake image and describe the page instead. Live integrated-browser inspection is separate from persisted screenshot evidence. Rejected: installing a browser/driver or claiming the absent PNGs exist. No later UI phase was started.

## Resumed model workbench - 2026-09-13

**UI-10. USER-DIRECTED - retain flow, replace the passive Doors concept:** the user rejected the Doors metaphor and required a UI that clearly explains the workflow and is connected to the actual model, so the model works through the UI. Preserve the original visual replay as a separate historical artifact. Build the live interface in the same `vulnassess/ui/` files, with explicit model execution rather than a timed replay. No building illustration or simulated progress establishes computation.

**UI-11. USER-DIRECTED BOUNDARY - explicit local inference, not learned scoring:** the latest request for model execution supersedes U2/U4 only for a user-triggered `POST /api/model/run` and its transient model outputs. The follow-up boundary question received delegated-autonomy text, not a selected approval; no broader approval is inferred. Run the existing hash-validated local `RoleModel.predict` on the selected run's stored hosts. Return predictions, extracted features, evidence, model/input hashes and actual execution timing. GET never invokes prediction. Require exact loopback Host, same Origin, JSON and an explicit action header; reject unknown fields, paths, oversized requests and concurrent execution. SQLite remains `mode=ro`; canonical context and scores are unchanged. No scan, feed fetch, retraining, Ollama call, new dependency or model promotion is authorized. The existing model's synthetic training provenance remains visible and cannot establish real-world accuracy. Rejected: rewording saved predictions as live, or letting learned roles change risk without the separate promotion approval.

## Reference-driven viewer boundary - 2026-09-13

**UI-12. USER-DIRECTED - restore U2/U4 and supersede UI-11:** the UI-UPGRADE-PROMPT explicitly rejects browser-triggered backend/model execution. Remove both model routes and the inference import from the viewer; all non-GET methods return 405, including previously valid same-origin model requests. Preserve the earlier runtime helper file without exposing it, and retain its isolated tests while adding stronger HTTP refusal checks. Scores, profiles and tables remain unchanged. Any future stored shadow prediction may appear only beside rule context, labelled "shadow - does not affect scores", never in risk or priorities. Conflict / resolution / why: the latest explicit read-only instruction overrides the earlier model-action direction; a claimed UI action is not authorization to recompute assessment results.

**UI-13. MISSING - reference parity input:** `doors-reference.html` was not present in the workspace when this increment began. Step 1 serves PROJECT.md Stage 7 (Report) and cross-cutting evidence auditability, but the visual port, export-text parity test and reference screenshots are blocked until the human supplies that exact file. Do not synthesize a replacement from the prompt, substitute `demo-report-synthetic.html` or the saved visual replay, copy claimed evaluation metrics into the store, or start later steps. Alternative: approximate the four-stage design from prose; rejected because the user made the actual file authoritative. Read-only boundary restoration is independent of the missing reference.

## Four-stage UI checkpoint - 2026-09-13

**UI-14. BUILD-NOW INTERPRETATION - implementation without a parity claim:** after the reference-file blocker was reported, the user again requested that the UI be built and continued the work. The direction question returned delegated-autonomy text, not a selected reference-parity approval. Build a working four-stage surface from the written direction in the same files; do not create a stand-in `doors-reference.html` or claim a comparison with an unseen file. Conflict / resolution / why: this proceeds with the user's build-now request while exact visual/text parity remains MISSING. Stage 7 and research auditability remain the purpose, rather than accumulating unrelated operational features.

**UI-15. IMPLEMENTED - written four-stage structure and requested CLI export:** use Evidence, Context, Risk and Priorities with one inspector and a six-step finding tour. System serif identifies headings/inferences, monospace identifies quoted evidence, and sans identifies labels. Keep colour literals in tokens, add a dark token set, and use the original local SVG assets. Implement the explicitly requested `ui --export PATH` as a CLI-only output, not an HTTP write path; bundle the same assessment JSON/styles/module code behind hash-based CSP with network connections disabled. All other pipeline commands, score models, tables and weights are unchanged. Alternatives: a parallel data model, client model execution, or copying the reference's evaluation placeholder; rejected under U2/U4/U5/U7. Retain older assets/helpers without loading their old layout.

**UI-16. DECIDED - browser arithmetic exists only in the sandbox:** port the repository's CVSS arithmetic and configuration-driven context/threat formula to a pure browser module. The banner permanently labels the result as hypothetical, with current configuration rather than reconstructed historical weights. Eleven fixed regression vectors plus 200 seeded valid vectors, and 144 context/threat combinations, are checked against Python. Synthetic arithmetic fixtures remain under `tests/synthetic/synthetic_*`, not real scanner-fixture folders. Missing EPSS stays explicit; sandbox inputs never overwrite stored scores. Rejected: approximate arithmetic, a numeric model output affecting rank, or reporting Python parity as independent model/scoring certification.

**UI-17. CHECKPOINT - stop and preserve the incomplete review state:** the user authorized pushing changes to `https://github.com/codezxsWIN/privwork` and continuing later. Save source, named tests, design/contract notes and local documentation captures on `audit-no-assumptions`; do not merge to main or commit environments, credentials, databases, raw artifacts or generated assessment reports. `docs/ui.md` records startup/export commands, pending exact reference parity and the tour-capture limitation. The full quality gate remains separate from the temporary UI behavioral gate. Browser tests found and fixed explicit Escape handling and Back/Forward inspector synchronization; the tour keeps already-visible targets in place. The saved Edge tour PNG remains an unaccepted capture, not a fabricated pass.

## Repository simplification and real-feed provisioning - 2026-09-17

**CLEANUP-01. DECIDED - remove the parallel narratives:** delete `legacy/` (the superseded pydantic/typer prototype), `project-starter-kit/` (a duplicate mini-repo including a paste-into-Copilot PROMPT.md), `PROJECT_PROVISIONING_COMPLETE.md` and `PROVISIONING_SUMMARY.md` (which claimed pip-installed feeds and tooling that the project charter forbids an agent from installing and that were never committed). Git history preserves all four for review, which supersedes BUILD-01's "moved, not deleted" rationale now that the repository itself is the history. `project-starter-kit/docs/DESIGN.md` is retained as `docs/DESIGN.md` because three documents cite it as the reviewed design scope. The three root-level guides moved into `docs/`. Alternative considered: keeping everything "for reference"; rejected because roughly half the repository volume was narrative about the project rather than the project, and the provisioning manifests contradicted DOWNLOADS_REQUIRED.txt written the same week.

**FEED-01. DECIDED - real public feed snapshots provisioned with recorded provenance:** at the repository owner's explicit instruction, real public feed snapshots were fetched by the agent on 2026-09-17 and placed under gitignored `data/feeds/`: the CISA KEV catalog JSON, the EPSS daily CSV (score date 2026-09-17), and a full NVD API 2.0 mirror (rate-limited paged fetch). Each artifact's URL, fetch date, SHA-256 and row count are recorded in `docs/FEED_PROVENANCE.md` and the local `data/feeds/PROVENANCE.md`. This narrows, but does not close, the evidence gap: feed data is now real, while scanner captures, host-context truth, expert rankings and model labels remain MISSING, so RQ1-RQ4 outcomes remain ineligible. No pip installation was performed; the supply-chain rule for code dependencies is unchanged.

**CI-01. DECIDED - enforce the quality gate in CI:** add a GitHub Actions workflow running the same stages as `make check` / `scripts/check.py` (Ruff lint, Ruff format, Pyright, pytest with the 75% coverage floor) on push and pull request, with dependencies pinned in the workflow. The gate was previously advisory and local-only, so nothing prevented regressions. Alternative considered: continuing with a local-only gate; rejected as unenforced.

**TEST-01. DECIDED - the UI contracts must not depend on author workspace state:** tests/test_ui.py required a gitignored `data/vulnassess.db` containing a run named "verify" that nothing in the repository could build; a fresh clone failed 18 tests. `setUpModule` now runs `run_demo.py`'s pipeline when the database is absent and inserts a "verify" runs-table row the way the contract test itself creates `synthetic_ui_other`. DEMO_RUN changes from "verify" to "demo"; the "verify" id remains a probe target for the eval/diff 409 contracts. Alternative considered: skipping UI tests on a fresh clone; rejected because it would report a green gate over untested contracts.

**FEED-02. DECIDED - a committed real-feed subset for reproducible integration tests:** `tests/fixtures/intel/` now holds a curated slice of genuine NVD API 2.0 records (CVE-2021-44228, CVE-2014-6271, CVE-2017-0143, fetched by cveId), the matching EPSS rows (score date 2026-09-17) and KEV entries, with hashes in tests/fixtures/intel/PROVENANCE.md. `tests/test_real_intel.py` proves the loader, matcher (explicit and CPE range over real configuration data) and scoring accept official formats inside CI, which cannot download full feeds. This narrows, but does not close, the parser-verification gap: it is still not scan evidence.

**DEMO-01. DECIDED - one-command real-feeds demonstration:** `run_real_demo.py` runs the pipeline against `data/feeds/` using `examples/real_lab_nmap.xml`, a hand-built lab capture whose hosts are invented but whose CVE evidence, EPSS scores and KEV listings are real; the file says so in its header. The demonstration output (Log4Shell on an internet-facing host ranks Critical at 100.0; Shellshock on an internal test host ranks High at 79.0) is an acceptance case over real enrichment data, not research evidence.

## Real local scan - 2026-09-17/18

**SCAN-01. DECIDED - reader accepts real Nmap output; entity risk stays fenced:** the first real execution of `vulnassess scan --execute` (Nmap 7.80, loopback lab) exposed a parser defect: `_input.reject_xml_declarations` rejected ANY `<!DOCTYPE`, and real Nmap always writes a bare `<!DOCTYPE nmaprun>` header, so the reader had never accepted genuine Nmap XML - the synthetic fixtures omit it. The check now rejects `<!ENTITY` declarations and any DOCTYPE carrying an internal subset, and accepts only a bare (optionally SYSTEM-id) DOCTYPE, which `xml.etree.ElementTree` neither fetches nor expands. Security tests cover: entity rejection, internal-subset rejection, bare-header acceptance. Alternatives: post-processing strips the header (rejected: mutating capture bytes), or keeping the blanket ban (rejected: forbids all real Nmap output).

**SCAN-02. DECIDED - real captures committed with provenance; zero findings stated honestly:** two real Nmap captures from the owner's own loopback-bound lab (Juice Shop 20.2.0 on 172.28.0.12:3000, Windows SMB/RPC + Python 3.12.10 SimpleHTTP on 172.28.0.10:8000) executed via `vulnassess scan --execute` with an empty canary access log, and committed under `tests/fixtures/nmap/` with provenance rows. `tests/test_real_captures.py` parses them. Both captures contain zero explicit CVE evidence: the vulners NSE ran keyless and found no nameable vulnerable software. The pipeline imported both hosts and services, inferred context from real service evidence (`file_share 0.8` from the quoted `445/tcp microsoft-ds`), and produced an honest empty ranked queue - raw absence is not remediated or inflated (see rescan policy). Unlocking CVE-level evidence requires a free Vulners API key (`~/.nmap/vulners.key`) or Nikto/ZAP provisioning; both remain optional human actions.

**UI-18. IMPLEMENTED - additive analytics layer on the risk stage:** research into professional threat-prioritisation surfaces (EPSS x CVSS quadrant framing, risk-formation waterfalls, exploit-intelligence strips, workflow-aligned motion) produced four additions, all rendered from stored values with no rescoring: a threat strip (stored counts: findings, CVEs, KEV, internet-facing, top EPSS percentile, animated count-up), a quadrant map (stored CVSS base vs stored EPSS percentile, KEV-ring and internet-facing fill distinctions, an explicit lane for findings with no EPSS row instead of a fake percentile, points open the existing inspector), a risk waterfall (the stored arithmetic formation of the highest risk: environmental x 10, exploitation multiplier, KEV boost, cap - labelled with the weights), and a motion layer (IntersectionObserver staggered reveals, door hover lift, stage-link progress fill, all disabled under prefers-reduced-motion). Nothing existing was removed or reworded; export parity tests extend to the new figures, and the sandbox arithmetic self-check still reports 211/211 vectors and 144/144 sandbox cases matching Python. Alternatives considered: client-side recomputation for the map (rejected: UI-16 confines arithmetic to the sandbox), and a pipeline-flow ribbon (deferred: no analytical content beyond decoration).

**UI-19. IMPLEMENTED - formation engine and hero layer strengthen the risk stage:** the UI-18 additions were strengthened after review: the threat strip became a hero with a band-composition meter (Critical/High/Medium/Low segments animated from the store), the quadrant gained danger/watch zone fills, crosshair guides and drop-in point animation, and a new formation engine pairs a 240-degree risk gauge (stroke-dashoffset driven by a CSS variable set on reveal) with a four-station beam diagram (Base -> Context -> Threat -> Risk, flowing dashes, values and terms straight from the store). All values remain stored-only; the sandbox stays the only arithmetic surface; prefers-reduced-motion disables every animation; the offline exports embed the same module and re-hash their CSP. Verification: full gate green, 55 UI tests pass, in-page sandbox self-check 211/211 vectors and 144/144 sandbox cases match Python, dial animates from 0 to the stored risk on reveal.

**TEST-02. IMPLEMENTED - UI self-provisioning heals stale databases:** an external review reported 41 test failures caused by `data/vulnassess.db` existing without the demo run; `_provision_demo_database` only checked that the file existed. It now verifies the runs table and the demo run, deletes a stale, partial or foreign database (including WAL/SHM sidecars) and rebuilds via `run_demo.py`, then ensures the `verify` runs row. Verified by dropping the runs table and rerunning: 55 UI tests pass after self-healing. Related staleness corrected: the README limits paragraph and evidence table now state that two real loopback captures exist with zero explicit CVE evidence (they previously said there was no real scan evidence), and HANDOFF.md gained a scope note that its machine-state section describes the operator machine only - fresh clones carry no gitignored `data/` and no machine tools, and inventories differ between machines (this one: Nmap yes, Java/Docker no).

**EVID-01. IMPLEMENTED - the evidence ladder advanced on every fillable front (2026-09-19):** multi-host lab evidence: three loopback lab hosts scanned (nginx 1.20.0 on 172.28.0.11:80, Python 3.12.10 SimpleHTTP on 172.28.0.10:8000, OWASP Juice Shop 20.2.0 on 172.28.0.12:3000), each bound to its single loopback address and netstat-verified. Real CVE-bearing findings: the nginx capture (Nmap 7.99.1 + keyless vulners) carries three explicit CVE findings (CVE-2026-42945/42055/42533, base 8.1) with real EPSS enrichment (99th/93rd/91st percentile), ranked 74.7/72.5/71.6 High. Committed as tests/fixtures/nmap/real-lab-172.28.0.11-nginx.xml with provenance. Real ZAP capture: ZAP 2.16.1 daemon + spider + passive scan against Juice Shop produced the official JSON report (278 findings); parse_zap_json verified against it; committed under tests/fixtures/zap/ with provenance; ZAP findings rank through the honest native-fallback path (no invented EPSS). Persisted evaluation: the full frozen-cohort chain ran on lab3 (snapshot -> 25-finding cohort-freeze -> ranking-eval) producing a hash-bound evaluation artifact (evaluation_hash b6ddf459...) attached to the report's evidence ledger; evidence_status stays NOT RUN because the truth is a labelled synthetic echo, not expert judgment. LLM rationale: Ollama + llama3.2:3b installed; explain stored real llm rationales for lab3 - wording only, scores byte-identical by design. Tooling incidents: Nmap 7.80 (i686) developed a deterministic segfault in its vulners path; upgraded in place to 7.99.1 + Npcap 1.79; 7.99.1 requires -sT for loopback raw scans until an Npcap driver reload (reboot), so the .11 capture used the documented manual route with -sT; orchestrator scans resume after reboot. Remaining blockers are human-only: expert rankings/labels/context truth and the Vulners API key.

**UI-20. DECIDED - one renderer, multiple evidence modes:** the four-stage workbench is the sole active interactive interface. `run_visual_simulation.py`, `vulnassess visualize`, live `vulnassess ui` and `ui --export` now share `UiApplication` plus `export_html`; the simulation differs only by building an explicitly synthetic run first. The historical eight-stage replay remains unreferenced source history, not a second product. The active Evidence stage replaces door controls with explicit finding cards and the tour traces one finding. Offline analytics no longer emit or mutate inline styles: proportional bars use CSP-safe SVG or repeated units and the gauge uses an SVG presentation attribute, preserving hash-pinned `style-src` without `unsafe-inline`. Alternatives considered: maintain both UIs or weaken CSP; rejected because they create divergent behavior and conceal blocked presentation code.

**UI-21. DECIDED - adapt proof-first hierarchy, not TypeSafe AI branding:** use the reference site's transferable interaction principles on the Risk stage: one thesis per viewport, oversized stored proof values, sparse technical framing, strict label/value typography and restrained stage-entry motion. Keep VulnAssess's professional token palette, evidence density, four-stage analyst navigation and read-only semantics; copy no brand assets, wording, fonts, colours or marketing composition. The Risk thesis and run metrics gain hierarchy while finding controls and provenance remain immediately inspectable. Reduced-motion removes the new transition. Alternative considered: restyle the workbench as a landing page; rejected because an operational security viewer must optimize repeated evidence inspection rather than conversion.

**UI-22. IMPLEMENTED - context ledger, chain of custody and command palette:** styling alone did not make the research legible, so three data-grounded surfaces were added, all rendered from stored values with no rescoring. (1) Context ledger on the Risk stage: for the highest-risk scored finding it shows the published CVSS vector beside the context-adjusted vector with changed tokens marked, then one row per stored `env_modifications` entry giving the metric, published value, adjusted value, the weights rule that applied and the driving context feature with its value, source, confidence and verbatim evidence quote; a rollup lists every scored finding with published/environmental scores, delta and rewrite count. Rule attribution is derived by matching each stored modified metric against the metric sets declared in `config/weights.yaml` (`internal_when_av_network`, `waf_present`, `auth_required_when_pr_none`, role/test-environment requirements), so the displayed cause comes from configuration rather than a hardcoded narrative. (2) Chain of custody in every inspector panel: a six-hop lineage from captured raw file and record index, to canonical finding id and host/port, to CVE match method and confidence, to the context features used, to base-to-environmental rescoring, to stored risk, band, threat multiplier and weights hash. (3) Command palette (Ctrl/Cmd-K): a keyboard-driven modal searching stages, hosts and findings from the embedded bootstrap only, with arrow/Enter/Escape navigation, aria combobox semantics and no network access; selecting a finding opens the existing inspector through the existing hash state. Vector strings are split into tokens for display only - no score is computed outside the sandbox, preserving UI-16. Verified: 251 tests and 348 subtests pass; the offline export contains the ledger, 3 attributed metric rows, 36 chain hops and the palette with 0 inline styles, so the hash-pinned CSP is unaffected. Alternatives considered: computing the rule attribution in the browser (rejected: keeps arithmetic and interpretation server-side from stored data), and a static prose explanation of environmental changes (rejected: it would not be traceable to the stored modification set). DEFERRED: presentation styling for the three new sections (they currently inherit base table/list styling) is the next increment.

## Grounded local analyst - 2026-09-21

**AI-01. USER-DIRECTED - replace the bootstrap priority imitation with target-level local analysis:** the user rejected an instant six-row ridge-regression model as materially inadequate and required a real model operating on the complete idea. Remove that bootstrap model, its artifact and its UI route. The explicit Context-stage action now invokes the already installed local `llama3.2:3b` through Ollama with the selected host's complete stored services, scanner findings, context, CVSS, EPSS, KEV and deterministic scores. Model output is advisory and transient: canonical scores and records remain unchanged. The response must be valid JSON, use the bounded analyst shape, and cite only finding/evidence IDs present in the request; malformed output or unknown citations fail closed. Scanner/model text is delimited as untrusted and rendered with DOM text nodes. No model runs during page load or offline export. Verified on the live loopback UI: the database target completed local CPU inference in 49.36 seconds and returned a cited remediation action; the full quality gate passes. Rejected: retaining the bootstrap predictor as a competing product model, allowing AI to manufacture scores, or displaying unvalidated free-form prose.

## Independent workflow visualization - 2026-09-21

**WF-01. USER-DIRECTED - Make-style canvas over the real project flow:** the user requested a complete node-and-connection visualization independent of the current notebook UI. Add `/workflow` and isolated local HTML/CSS/ES modules, sharing the existing record APIs. Cover authorized targets, scanner ingestion, normalization/storage, local feeds, enrichment, context, optional learned roles, deterministic risk, priority, rationale, reports, analyst output, expert evaluation and re-scan comparison. This serves PROJECT.md Stage 7 and cross-cutting ranking/evaluation auditability: the viewer can trace the inputs behind a priority rather than reading a wall of tables. Conflict / resolution / why: UI-20's sole-interface statement predates the explicit request for a distinct visualization; retain its shared backend/assessment renderer but add a new view, not a second pipeline. The independent circle-node visual vocabulary uses new scoped neutral tokens and local SVG paths, not external libraries, downloaded imagery or copied Make assets. Alternatives: restyle the four-stage page or animate a replay; rejected because the user explicitly rejected the existing UI style and needs real dependency relationships.

**WF-02. DECIDED - dependencies are not execution evidence:** nodes say stored records, current configuration, no attached output or transient analyst-request state. They never become complete merely because selected; no timers, fake throughput, made-up counts or automatic model calls. Target/finding selections filter existing records and preserve stored score values. The local analyst is downstream of evidence and ranking with no edge back to scoring; its button reuses the existing AI-01 endpoint, with run/host-bound transient state, text-only output and explicit errors. Testing uses mocked analyst failures; no real Ollama request or scanner is run for this change. Optional report, evaluation and re-scan nodes remain visibly unattached rather than deriving metrics or asserting fixes. Alternatives: infer artifact existence from scores, execute the whole pipeline from the canvas or recalculate metrics; rejected under the remaining data, scoring and execution boundaries. The project venv lacked pytest, so full tests used the already-installed system interpreter; no provisioning or dependency change occurred. Validation and screenshots are recorded in docs/ui.md.

## Workflow design review - 2026-09-22

**WF-03. USER-DIRECTED - Integration Card visual reference, directional workflow:**
the user selected ShadcnSpace's Integration Card at
[its 21st.dev preview](https://21st.dev/@shadcnspace/components/integration-card), requested dark styling
close to the reference, and delegated the layout choice after comparison. This
serves PROJECT.md Stage 7 and cross-cutting context/ranking auditability: larger
readable nodes and a selected evidence path make the inputs behind a priority
inspectable. Retain the 18 existing stage identities and dependency edges. Adopt
dark raised icon tiles, compact navigation, scoped color tokens and selected-edge
tracing, with a Canvas / Stages switch and a readable list by default below
961 CSS pixels. Keep node details, native scrolling, keyboard focus return,
target/finding filtering and the existing explicit analyst boundary. Motion
indicates the selected dependency only, never execution, and respects reduced
motion. The run summary counts existing arrays, not completed stages.

Conflict / resolution / why: WF-01's pale circular presentation is superseded
only for this independent workflow by the user's approved dark reference. The
assessment renderer, APIs, model fields, scores, scope and offline export remain
outside this redesign. A literal single-hub copy was rejected because it erases
pipeline direction; hiding optional stages was rejected because missing outputs
must remain visible. Installing the React component and its dependencies was
rejected in favor of the existing offline modules and local icons. No template
source or brand assets are copied. Reference installation commands were
**not run by the agent**. Other templates still require separate user review.

TESTED WITH MOCKS: the available regression suite passed; VERIFIED: browser and
loopback smoke evidence is quoted in docs/ui.md. MISSING: Ruff, Pyright and
pytest-cov; this decision does not assert a complete quality gate.

**WF-04. USER-DIRECTED - soften the workflow palette, retain the accepted layout
(2026-09-22):** the user found the background too dark and accepted the rest of
the workflow. Lift the near-black canvas to neutral charcoal, lighten tile faces
and connectors, and reduce shadow opacity through workflow-scoped tokens only.
This serves PROJECT.md Stage 7 by improving readability of the existing evidence
path; it makes no research-performance claim. Alternatives: switch to a full
light theme or redesign the graph again; rejected because the request is a small
appearance refinement, not a new layout or mode. No HTML, JavaScript, scoring,
record, dependency or assessment-theme change belongs to this follow-up.
VERIFIED: live color/contrast and viewport measurements are quoted in docs/ui.md.
TESTED WITH MOCKS: nine existing UI asset tests passed. The required gate remains
blocked by the previously named missing tools.

## Project-first explanation website - 2026-09-22

**UI-23. USER-DIRECTED - explain the project before exposing its records:** the
user identified the visitor's task as understanding and exploring the project,
explicitly dropped the Doors direction, supplied
[Hero by Berat](https://21st.dev/@beratberkayg/components/hero-1), and requested
desktop-first work. This serves PROJECT.md Stage 7 and cross-cutting ranking
auditability: explain why deployment context matters, then let the visitor
inspect the evidence behind an existing priority. Use a project introduction,
a guided comparison and links into the accepted workflow. Preserve the detailed
assessment behind explicit `#stage-*` links and in print.

Conflict / resolution / why: UI-20 and UI-21's operational-first entry predates
the user's explicit explanatory-website request. Change the default presentation,
not the pipeline, scoring model, stored records or approved workflow. Repeating
the Doors/orbit/card-stack composition was rejected because it obscured the
project's purpose. A separate React/shadcn application was rejected because it
would add a second frontend and require unapproved provisioning. Adapt the supplied
hero composition in the existing offline HTML/CSS/JavaScript, with original
decorative bitmap artwork embedded in exports. Reference installation commands
were **not run by the agent**; no new dependency is requested by this decision.

**UI-24. DECIDED - a guided example must come from existing records:** compare
two different hosts only when stored CVE, base vector, base score, EPSS percentile
and KEV membership match. Reveal the recorded context and priorities in three
user-controlled steps; never calculate new scores for the story. Label synthetic
provenance and distinguish equal stored values from a controlled historical-feed
experiment. Preserve source evidence in disclosures. No suitable pair means an
explicit unavailable message, not an invented example. Alternatives: fixed
demonstration numbers or picking a visually dramatic pair with different threat
inputs; rejected because either would undermine the context-attribution research
question. This display does not establish inference accuracy or ranking quality.

**UI-25. USER-DIRECTED - explanation sections connect to the existing analyst:**
add plain-language local-analyst, priority/reason/source and questions sections.
Let visitors select only hosts in the current stored assessment; link that host
to the workflow's existing analyst node. Opening the link must not execute the
model. The existing explicit AI-01 action remains advisory, transient and separate
from deterministic scoring. Offline exports disable these live actions and retain
the explanation. Use native select/disclosure controls, visible keyboard focus,
restrained button depth and reduced-motion-aware arrow movement.

Control-level reference review considered
[Interactive Hover Button](https://21st.dev/@dillionverma/components/interactive-hover-button)
and [Accordion Space](https://21st.dev/@shadcnspace/components/accordion-space).
Use the interaction ideas, not their component code, dependencies or a new page
template. The hover-button embedded preview was blank during capture; exact
reference behavior is not claimed. Alternatives: automatic analysis on navigation
or a fabricated answer preview; rejected because they would blur execution and
evidence boundaries. This decision extends presentation only, not AI-01's scope.

**UI-26. USER-DIRECTED - defer the globe only:** the user selected option 2 after
the local COBE renderer/provisioning blocker was reported: continue the useful
website sections and leave the globe for a separately approved artifact. A remote
CDN, sibling-package copy or imitation renderer is not a provisioning workaround.
Decorative geography is not needed to inspect context or evaluate ranking, so this
deferral does not block the research question. MISSING: approved local renderer
bundle with exact dependency versions, provenance, license, independently approved
hashes and dated vulnerability review. No globe installation or model execution
was performed for this increment; verification and remaining gates are recorded
in docs/ui.md.

## Doors as a section and explicit analysis - 2026-09-22

**UI-27. USER-DIRECTED - restore the useful doors metaphor as one section:** the
user now requests parts of Doors with a clear depiction, not the previous whole
interface. This serves PROJECT.md Stage 7 and context/ranking auditability: one
selected recorded system, its stored role/exposure, and one selectable door per
finding lead to the exact source and stored priority. Reuse the existing local
building/door drawings and band mapping. Unknown context and absent findings stay
explicit. Synthetic records remain labelled; a door does not establish an
exploitable entrance and an unknown role does not imply low importance.

Conflict / resolution / why: UI-23 dropped Doors as the organizing interface;
the latest user request permits the metaphor inside the explanatory website.
Keep the project-first hero and approved workflow, not the old Doors page, orbit
or a second dashboard. A decorative collection of invented buildings/findings
was rejected because it would break the connection to evidence. The drawings
depict existing records; they do not score, infer context or establish research
performance.

**UI-28. DECIDED - preserve selection through the workflow round trip:** all
project workflow links retain the selected recorded host, and a door link also
retains its finding ID. The return link restores that host/finding in the doors
section, or the host in the workflow section when no finding is selected. Shared
host controls and input summaries follow the restored selection. Use fragment
state only; no assessment query shape or API fields change. Alternatives:
unfiltered links or independent unsynchronized selectors; rejected because they
can show a different system's evidence after a visitor follows a priority.

**UI-29. DECIDED - run the existing analyst explicitly, not an invented pipeline:**
interpret the request for a model-running section within the existing AI-01
boundary. Offer the existing local analyst for a selected system or all systems
in the stored assessment, using the same endpoint sequentially. Review the exact
target list before starting. Reject duplicate starts and mismatched responses;
stop later requests after a failure, and let the user stop after the current
request without claiming to cancel inference already running. Responses remain
transient, cited and rendered as text; stored scores and model code stay untouched.
The earlier Context-stage action now opens this same review flow. A small shared
client supplies validation to both the project and workflow; offline exports
embed it but disable every execution control.

Alternatives: automatic execution when visiting a section, parallel inference,
a new backend batch route, or training/running a second ranking model; rejected
because none is needed to explain existing evidence, and these would expand the
execution/interface boundary. This choice does not authorize scanner orchestration,
feed refresh, rescoring, training or additional model types. Those are not hidden
behind an "all models" control. No dependency or fixed schema change is made.

TESTED WITH MOCKS: sequential, duplicate, stop, failure, response-identity and
citation cases are covered by the existing synthetic workflow check. Browser
execution checks ultimately used an in-page fetch fake. VERIFIED: an earlier
browser-route interception failed and one local analyst request returned an
Ollama-unavailable error; that request is not described as mocked or successful
inference. The incident, missing service and quality prerequisites are recorded
in docs/ui.md. Future browser model checks must use in-page fakes, not rely on
route interception being retained through a timed-out check.

## Globe land map under the viewer CSP - 2026-09-23

**UI-30. DECIDED - allow `data:` images only, and keep inline styles blocked:**
PROJECT.md Stage 7 (Report). The vendored Cobe 2.0.1 globe loads its land map
from an embedded `data:image/png`. The server CSP had no `img-src`, so
`default-src 'self'` blocked it and the globe showed no continents. The CSP now
adds `img-src 'self' data:`, which the offline export already allowed with
`img-src data:`. Scripts, styles and connections are unchanged, and
`unsafe-inline` is still absent.
Cobe also writes label visibility into an inline `<style>`, which `style-src
'self'` blocks on every frame. The adapter detaches that element and copies its
`--cobe-visible-*` values onto the globe root through CSSOM. Labels on the far
side now hide, and the per-frame CSP violations stop.

Alternatives rejected: adding `'unsafe-inline'` to `style-src` (weakens the page
policy); editing the vendored library, or extracting its texture to a patched
static file (breaks parity with upstream 2.0.1). No dependency, API, schema or
scoring change.

**UI-31. USER-DIRECTED - the globe depicts the recorded assessment, not CDN
traffic:** PROJECT.md Stage 7. The user rejected the copied 21st.dev content
(edge regions, "req/s" counters) and asked for project context. Markers are now
the recorded systems of the selected run. Each label gives the hostname or IP,
the inferred role and the stored top band, and marker colours use the band
tokens. Arcs join systems with the same CVE, vector, base score, EPSS and KEV,
which is the `_project_story` like-for-like rule. The arc label shows the base
score and the two stored bands. The readout names the run and its provenance
(synthetic or source unlabelled), and states that positions are illustrative.

Conflict / resolution / why: a globe implies geography, but lab systems have
private addresses and no location. Rejected: geolocating addresses (impossible
for RFC1918, and it would be invented evidence); placing systems on arbitrary
real cities (reads as geolocation). Chosen: a deterministic layout disclosed as
illustrative. The globe spins a full 360 degrees; labels on the far side hide,
and the recorded systems are front-facing when the page loads. The random traffic counter is removed
as fabricated data. No run shows continents only, with an explicit notice.
Reduced motion stops the spin. No backend, API, schema or scoring change.

**UI-32. USER-DIRECTED - desktop scroll parallax on the hero:** PROJECT.md Stage
7. The user asked for a proper scroll animation on the hero, after reviewing the
21st.dev scroll heroes: Container Scroll Animation, Scroll Morph Hero and Parallax
Scrolling. A first version pinned the hero and slid the globe section over it as
a rounded, shadowed sheet. The user rejected it as a mobile-app pattern that
doesn't suit a desktop product; it was removed. A second version, a generic
layered fade-and-tilt parallax, was rejected as boring.

Current: a scroll-scrubbed desktop scene that plays the research thesis from
stored records. The hero is held on screen for about 190vh of scroll. Nothing
slides over it, and the page scrolls on normally afterwards. The beats are:
1. The title dissolves into one card for the stored like-for-like weakness
   (`tour_finding` and its partner: same CVE, vector, base, EPSS and KEV).
2. The card splits across the two recorded systems.
3. Each card shows its stored role, exposure and Environmental modifications,
   and the Environmental score moves from the base to the stored value.
4. The priority meters fill to the stored risk and band, and "Not the same
   priority." links to the evidence.
Final numbers equal the stored values; the scene says "stored scores, not
recalculated here" and labels the run synthetic or recorded. There is no scene
without a pair, under 900px width, or with reduced motion; the hero then stays
as it was. Native CSS/JS only, text via textContent, no model call.

**UI-33. USER-DIRECTED - 21st.dev interaction components, rebuilt natively:**
PROJECT.md Stage 7. The user asked for good hover effects, buttons and components
from 21st.dev instead of a restrained style. The React/Tailwind/framer-motion
sources cannot be imported, since they need dependencies, a build chain and
downloads. Their behaviour was re-implemented in plain CSS and JS on the current
project page:
- Primary buttons, after Magic UI / designali's Shiny Button and Border Beam: a
  rotating conic beam just outside the button (CSS `@property` angle), a shine
  sweep on hover and a lift.
- Framed panels (model panels, doors, door records, scene cards), after
  Aceternity's Glowing Effect: a masked conic border glow in the signal and
  critical tokens that faces the pointer when it comes within 70px.
- List rows (outcomes, analyst path, workflow steps, FAQ): a spotlight that
  follows the cursor.
- Text links: an underline that draws in with the arrow moving.
- Header navigation, after Cnippet's letter swap: each label's own letters
  shuffle deterministically and then settle, with `aria-label` keeping the real
  name.
Constraints: colours come from existing tokens, with no inline styles (CSSOM
only) and no `unsafe-inline`. The global reduced-motion rule stops the beam and
the transitions, and the letter swap is skipped. The old workbench is untouched
at the user's request.

**UI-34. USER-DIRECTED - a plain-language scenario replaces the hero scroll
scene:** PROJECT.md Stage 7. The user rejected the pinned two-card scene (UI-32)
because showing two technical "surroundings" cards didn't explain anything to a
non-technical visitor. They asked for a small scenario that can be understood by
looking at it. The scene, its sticky track and its script are removed, and the
hero scrolls normally. A new `#project-scenario` section follows the hero as
three illustrated steps on a timeline:
1. "Mon 09:00": two identical computers, each showing the same 9.8/10 warning.
2. "09:01": one is open to the internet, the other is inside the office.
3. "09:02": the order is "Fix first · Company database · Critical", then "Fix
   next · Staff test page · High".
The art is inline SVG line drawing, and the timeline draws in once when the
section first scrolls into view (IntersectionObserver). The steps carry the
UI-33 glow.
Evidence boundary: the section is labelled "An illustration of the synthetic
demo run". The outcome matches the stored demo pair: the internet-facing
database is Critical, and the internal test web frontend is High. "Company" and
"staff" are illustrative wording, not recorded facts. Rejected: a
scroll-scrubbed version of the same story (the user called the pinned scroll
stupid) and stock illustrations (downloads, licensing).

**UI-35. USER-DIRECTED - the hero planet travels to the globe:** PROJECT.md
Stage 7. The user specified the scroll animation: the planet on the hero's
horizon moves down to become the background of the scenario, then shrinks into
the small Cobe globe. A pinned, scroll-scrubbed scenario was tried first and
reverted; the user said the animation belongs to the hero.
Implementation:
- A fixed, `contain: strict` layer holds a CSS planet: one radial gradient whose
  stops copy the measured brightness profile of `project-horizon.png`. That
  profile is a rim circle of radius 2000, centred at (800, 2732) in the
  1600x1050 image, with a 1px rim, a 50px bright band and a 240px falloff.
- The planet is resized in pixels every frame, not scaled, so its edge stays
  sharp at any size.
- Handover from the artwork: at 4px of scroll the lower part of the artwork is
  masked away. Captures match the rim row exactly, glow within 3 grey levels
  and body within 1, in both themes.
- Behind the scenario, the rim sits at 70% of the viewport and dims to 65%.
- Landing: the size settles before the position, and the position tracks the
  visible rim so the planet never leaves the screen. Motion ends at 80% of the
  landing; the last 20% crossfades in place onto Cobe's measured rim (0.797 of
  the canvas radius, same radius and centre), and Cobe fades in as the planet
  fades out.
- Every frame is a pure function of scroll position, so scrolling back up
  reverses it exactly. Reduced motion and widths under 900px keep the static
  artwork and globe.
Rejected: scaling a raster planet (blurred rim, expensive blurred shadows);
pushing the planet sideways to avoid text (a visible jump). Text that can cross
the planet gets a soft halo instead.

## Standalone export asset bundling - 2026-09-23

**UI-36. DECIDED - embed the existing globe and fonts in offline HTML:**
PROJECT.md Stage 7 (Report) and cross-cutting reproducibility. The purpose is
to let reviewers inspect the same stored assessment without a running server;
this is not new evidence for the ranking hypotheses.

Chosen: extend the existing explicit module bundler with the local Cobe adapter
and its vendored renderer, isolating their names in function scopes. Refuse an
unexpected import/export shape rather than silently emitting a broken bundle.
Embed the three existing WOFF2 fonts as data URLs. Keep exact script/style hashes
and `connect-src 'none'`; allow only `data:` font sources.
Rejected: external module/font requests (break standalone operation), a new
bundler dependency (unnecessary provisioning), and removing the globe (changes
the shared view). No canonical model, API, scoring, dependency or live UI change.

TESTED WITH MOCKS: the added assertion in
`TestUiExport.test_export_is_self_contained` first failed on the unresolved
`import { initialiseCobeGlobe } from './cobe-globe.js';`. After repair, the
isolated-copy command `python -m pytest -q -p no:cacheprovider
tests/test_ui.py::TestUiExport tests/test_ui.py::TestUiAssets
tests/test_ui.py::TestAnalystChoices` returned
`38 passed, 17 subtests passed in 9.72s`. The export test also runs
`node --input-type=module --check` on the emitted JavaScript. These checks use
synthetic stored records, not real scanner/feed/model integration evidence.

VERIFIED: `python -m vulnassess ui --run demo --export <local HTML path> --json`
against the isolated database returned `read_only: true`, `run_id: demo` and
`EXPORT_EXIT 0`. Browser `page.reload()` and DOM/canvas probes on that file at
1440x1000 and 390x844 returned `errors: []`, `blockedFetches: 0`, `csp: []`.
All three fonts reported `loaded`; the desktop canvas sample had 4096 nonzero
bytes, and the mobile draw-time sample had 256 nonzero RGB pixels. Selecting
the Light and Dark buttons returned `themesWorking: true`. Fetch was replaced
with a non-forwarding guard; no model or scanner integration was exercised.

TESTED WITH MOCKS: the broader isolated run called
`pytest.main(['-q', '--tb=no', '-ra', '-p', 'no:cacheprovider'])` with socket
creation, connection and DNS blocked. It returned
`8 failed, 295 passed, 375 subtests passed in 48.77s`, with zero skips. Five
failures attempted sockets; three assert the previously removed UI. They remain
unresolved and were not weakened or suppressed to make this checkpoint green.

MISSING: `python scripts/check.py` reported
`GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright, pytest + coverage`.
Source coverage remains unmeasured. `tests/fixtures/nikto/` still has no real
human-captured Nikto JSON. That absence does not prevent testing offline asset
bundling, but prevents a claim of real Nikto integration verification.

## Full two-prompt pipeline recheck - 2026-09-23

**RECHECK-01. DECIDED - actual discovery and normalized persistence:** PROJECT.md
stages 1-4. An exit-zero Nmap process without the requested host is failed
discovery, not a completed assessment. Preserve its exit code, timing and raw
path. The existing scan command now imports successful captures and retains all
outcomes in the existing run summary; later web imports retain Nmap services.
Apply the explicit named-target requirement to the older runner and importer as
well as the main orchestrator. Rejected: counting every skip as success, treating
a CIDR as target authorization, or leaving successful scans outside the store.
No command shape, scope entry, SQL layout or exit code changes.

**RECHECK-02. DECIDED - enforce the already-recorded model boundary:** PROJECT.md
stage 5 and RQ1. MODEL-06/OPERATIONS-01 authorize shadow candidates only, even
after a promotion attestation. Canonical profile construction and the pure
scoring function now reject unapproved learned/LLM context. Training, prediction,
evaluation and shadow recommendations remain available. Label templates leave
independent groups unfilled; loading rejects null/blank groups instead of making
`run:IP` look like reviewed independence. Rejected: silently enabling learned
scoring, silently ignoring a model argument, or inventing independent hosts.
Conflict / resolution / why: the requested canonical trained-context flow needs
the human-approved context-source ADR; this pass does not fabricate that approval.

**RECHECK-03. DECIDED - bounded, truthfully partial analyst cases:** PROJECT.md
stage 5. Clean all model-facing strings, escape delimiters, include the required
untrusted-data prefix, and never reuse a citation when its budget is exhausted.
Use stored-risk ordering with stable finding-ID ties and expose included/omitted
finding, service and intelligence counts. Partial coverage forces an uncertainty
notice and conservative confidence. Preserve scanner provenance, match confidence,
feed dates and weight hashes in included evidence. Rejected: pretending an
oversized case was fully reviewed, silently dropping rows, or increasing an
unmeasured context window until a demo passes. A bounded partial analysis still
does not meet the original complete-case acceptance requirement.

**RECHECK-04. DECIDED - injectable providers and shared grounding guards:**
Keep the default provider local-only. A typed provider boundary preserves the
injected source identity; it is not a cloud-provider implementation or approval.
Validate a case before contacting its provider. Reject unsupported CVEs/numbers
and malformed citations, including in corpus supervision. Bound streamed events,
wire bytes and decoded content; require explicit completion and transmit the
requested output schema. Rejected: false Ollama provenance, trusted streaming
content, citation-only claims of factual truth, and corpus-only validation bypasses.
These guards do not prove semantic entailment, useful reasoning or live inference.

**RECHECK-05. DECIDED - preserve known threat inputs and isolate baselines:**
Cross-cutting risk ranking and RQ2/RQ4. Missing CVSS must not erase observed EPSS
or KEV. Keep the native-severity base and apply the existing configured KEV boost
and exposure floor; do not apply an EPSS multiplier to a native fallback. Severity
baselines use recorded native-severity provenance rather than final adjusted risk;
absent EPSS remains unscored rather than being treated as an observed zero. Validate
all required host context and calculate all scores before writing score rows.
Rejected: discarding known threat data, contaminating baselines with KEV/context,
and silently omitting findings without a context profile. Weights, thresholds,
CVSS version policy and canonical fields are unchanged. This is a correctness
repair, not a measured improvement against expert rankings.

**RECHECK-06. DECIDED - network-free tests and visible shadow uncertainty:**
Cross-cutting reproducibility and PROJECT.md stage 7. Reuse the existing in-memory
HTTP harness for assessment-route tests and retain their assertions. Pytest blocks
Python socket connection/bind/send and DNS operations by default; that is not a
sandbox or permission for network-capable child processes. The detailed report
includes all shadow predictions, including rule agreements, with coverage, OOV
features, confidence, margin, abstention and model hash. Rejected: hiding low-coverage
agreements, live sockets in unit tests, or weakening assertions to obtain a green gate.

**RECHECK-07. NOT APPROVED - remaining product contracts and research inputs:**
Writable intake/resolution and its identity record, canonical model activation,
and durable structured-analysis/report bindings still need the prescribed review.
No new authorization, cloud data flow, dependency provisioning, model-quality claim
or unseen-environment result is implied. The complete evidence, remaining failures,
and both prompts' acceptance checks are recorded in HANDOFF.md. Concurrent commits
6f51bb5/b3e5dae were preserved; the removed offline-export bundling is reported as
a regression, not silently restored during this backend-focused pass.

**RECHECK-08. DECIDED - preserve and validate incoming model infrastructure:**
Remote checkpoint 5b13059 added feature-family ablation and optional training-run
registration. These were retained when rebasing the unpublished recheck. The
ablation CLI now forwards its declared training options and rejects conflicting
family selectors. Any synthetic labels classify the registered dataset as
synthetic, rather than allowing one human-tagged row to label a mixed dataset
`real_authorised`. Rejected: silently ignoring hyperparameters, overstating data
provenance, or dropping the incoming work. Registration remains draft metadata;
it is not independent test evidence, authorization verification or model promotion.

## 2026-10-02 — finding-scoped context applicability

**CONTEXT-CONTROL-01. DECIDED — preserve observations; scope score credits:**
PROJECT.md stage 5 and RQ1/RQ2. Keep raw host features and scanner findings
unchanged, but derive an isolated finding-scoped scoring view. Host, port,
protocol, HTTP-service identity, quote alignment and the existing confidence
threshold fence web-control credits. With no service fingerprint, a URL alone
must identify the literal recorded IP/port; no DNS guess, fetch or scope mutation.
Reject login/403-only authentication credit; require a finding-bound 401 challenge
and WWW-Authenticate signal. TLS is scoped to the affected service. Scanner titles
are interpretations, not raw response quotes. Rejected: a host-wide web signal
lowering unrelated SSH/Redis priorities, or rewriting raw evidence to make a quote
match. Existing rule/manual-only scoring, weights, canonical model fields,
signatures and storage layouts remain unchanged. Pure counterfactual host
comparisons remain available, without borrowing another host's controls.

**CONTEXT-CONTROL-02. DECIDED — persist limits beside the deterministic score:**
Use the existing extensible score-input field for original/effective controls,
versioned applicability decisions, reason codes, source quotes and limitations.
Only an actually applied metric earns the applied status. Show the decisions in
the offline report and prevent rationale facts from reintroducing a withheld
host-level WAF. Same-finding signals remain spoofable; configured mitigation
assumptions are labeled unverified, not confirmed remediation. Historical scores
are not silently rewritten or claimed to have this audit. Rejected: changing the
score schema, inventing verified mitigation, AI-adjusted weights, or claiming
expert-ranking improvement from synthetic tests. Verification and deferred graph,
critic and evaluation work are documented in context-control-applicability.md.

**CONTEXT-GATE-01. DECIDED — repair readiness without weakening validation:**
Keep the fixed structured-analysis schema and validation semantics; explicitly
type its local mutable deep copy according to its existing dynamic JSON return
contract. Narrow existing endpoint guards so nullable metadata cannot be used as
an established endpoint. Require batch coverage metadata to be a dictionary with
a non-boolean, non-negative integer count bounded by the collected finding count;
otherwise NeedsReview, not a crash or fabricated coverage summary. Tests first
reproduced seven unsafe coverage cases; the new guard and existing boundary tests
pass without changing scope or score authority. Rejected: type ignores, changed
score/citation constraints, or inventing a count to make a report finish. No new
dependency, network execution, or public interface is introduced.

**CONTEXT-CONTROL-03. DECIDED — bind TLS provenance to the affected service:**
Review found a two-TLS-service case where the scoring audit could cite the first
host-level TLS banner for the second service. Derive the effective feature quote
from the matching service while preserving the original profile and its quote
in observed_controls. No new TLS score mapping is introduced. A synthetic test
first failed on the wrong quote and now passes; an additional native-fallback
test confirms an eligible WAF signal does not falsely claim an applied metric.
Rejected: reusing the first banner across services, or overwriting original
host observations. No raw file, schema field, or score weight changes.

**CONTEXT-GATE-02. DECIDED — isolate mechanical format cleanup:**
Normalize pre-existing Ruff-format failures in a separate changeset, not by
relaxing the lint/format/type/coverage gates. An AST comparison of all 18 tracked
formatting-only Python diffs found zero semantic differences. Keep test assertions
and all scanner/provider paths unchanged. The final integrated gate uses an 85%
coverage floor (above the required 75%); the unrelated Windows-blocked Hypothesis
plugin is excluded, not any project tests. Rejected: lowering thresholds, skipping
failing assertions, dependency downloads, or calling formatter output behavioural
verification. Exact executions and limits are in context-control-applicability.md.

## 2026-10-02 — bounded AI assessment safety foundation

**AI-BOUNDARY-05. DECIDED — raw canaries cannot be erased by parsed output:**
PROJECT.md stage 5 and I2. Reject a model generation when its raw capture contains
the standing injection sentinel, even if the provider returns valid structured
JSON. Keep detection sticky for that attempt in both analyst and CLI rationale
paths. A known support-association correction remains separately audited, never
a way to retry a canary response. Reject malformed evidence IDs as explicit
boundary errors without formatting arbitrary model objects. Rejected: accepting
parsed JSON over a raw warning, overwriting a warning with a clean capture,
weakening quote/score checks, or treating a validator crash as a useful outcome.
No score, authorization, schema, storage or provider contract changes. Actual
test-first executions and limits are in ai-boundary-increment-1.md.

**AI-PLAN-01. PROPOSED — local-only, human-approved planning contract:**
PROJECT.md stages 1-2; supports evidence coverage for RQ1/RQ2 and the requested
verification/fusion roadmap. Recommend an additive, versioned plan with bounded
server-owned profiles, server-issued evidence IDs, explicit editable approval,
canonical content hashes and atomic execution binding. Preserve current scanner
paths; never turn missing tool readiness or changed scope into silent plan edits.
Use a bounded in-memory approval registry and existing hash-only audit files,
not a new SQL layout. Rejected: autonomous launch, arbitrary flags, imported
JSON as approval authority, unreviewed cloud calls and forced execution of
inapplicable tools. Conflict / resolution / why: the user requested broader AI
participation, while the fixed-contract policy requires a human-approved ADR
for new interfaces. This entry records the concrete proposal, not that approval.
Full contracts, acceptance checks and limits are in ai-scan-plan-contract.md.

**AI-PLAN-02. DECIDED — implement the reviewed, bounded proposal path:**
PROJECT.md stages 1-2, supporting evidence coverage for RQ1/RQ2 and the user's
broader verification/fusion roadmap. Conflict / resolution / why: the repository
retains a rationale-only prototype and an ADR approval prerequisite; the current
human request explicitly asks to proceed beyond that procedural pause. Treat
that as implementation direction for the planner, not fabricated formal approval,
permission to call a model/scan, or authority to change scope or scores. Reuse
existing providers rather than introducing another model integration; cloud
proposals require the existing explicit evidence-sharing choice, while the local
default remains local and no provider was called by the agent. No dependency,
credential, canonical model, score formula or SQL-layout change. Rejected:
autonomous launch, arbitrary flags, planner-derived scores, and hiding missing
observations behind a guessed endpoint. Plan authority is single-user loopback,
in-memory, one-use and bound to target, scope, evidence and fixed profile content.

**AI-PLAN-03. DECIDED — enforce plan deviations without destroying evidence:**
Share discovery's time budget with the requested-port subprocess; recheck the
scope hash immediately before each approved scanner subprocess. Reject stale
hashes, replay, changed context, target/order deviations and exhausted budgets.
Do not silently add a Redis probe to an approved web plan when fresh observations
contradict prior HTTP evidence. A missing or failed approved step ends the plan
as needs_reapproval, while existing scan evidence and evidence-only reports are
retained. AI availability never changes a completed scanner plan into failure.
Rejected: consuming approval during a cooldown refusal, retrying invalidated
authority, silently substituting tools, or marking dispatch as successful scan
completion. Test-first reproductions, remaining limitations and runtime UI
verification are in ai-scan-plan-increment-2.md.
# AI-EVIDENCE-01 — Typed follow-up evidence, separate from canonical findings

Date: 2026-10-02. Status: implemented on review branch; not merged.

The user's ordered increment 3 requires bounded AI evidence requests with explicit
human approval. Use three fixed operations (TCP connection, HTTP HEAD, verified
TLS inspection), server-observed ports and a pinned literal IP. Approval is
one-use, hash-bound, expires after ten minutes and rechecks the existing exact
target scope fence. The model cannot provide URLs, commands, flags or credentials.

Use exclusive-create local evidence artifacts and append-only audit events, avoiding
a canonical database/scoring schema migration. A source ID, origin, timestamp and
raw hash accompany every observation into the analyst request. Runtime claims
still pass the existing citation/content/score boundary. Rejecting a probe records
the human reason; transport failure preserves existing scan evidence.

Alternatives considered: arbitrary tool calls would expand execution authority;
silently converting observations into findings would cross the evidence/scoring
boundary; skipping the workflow review would violate the requested increment.
No new dependencies, provider accounts, scope entries or live-scanner claims are
introduced. See `docs/ai-evidence-increment-3.md` for contracts and verification.

## QA-95-01 — Whole-package coverage floor, without weakened safeguards

Date: 2026-10-10. Status: implemented and verified locally on the review branch;
not merged or remotely verified.

Serves PROJECT.md stages 1-8 and the cross-cutting evaluation/reproducibility
component: stronger regression evidence protects the inputs, provenance and
validation used to evaluate context-aware ranking. It does not establish RQ1-RQ4
accuracy, ranking gains or operational safety on real targets.

Conflict / resolution / why: the user's requested 95% target is interpreted as
whole-package statement coverage, replacing APPLY-02's 75% minimum only after a
clean full-suite run passed at 95.17%. CI, Makefile, scripts/check.py and current
quality instructions now agree. Historical reports retain their original numbers.
Rejected: exclusions, skipped tests, relaxed validators, or interpreting code
coverage as 95% project completion. No interface, dependency, scope, score formula,
credential or production database changes.

Added isolated boundary and persistence tests; one test exposed a timezone-naive
cache timestamp crash. Reject such timestamps as not fresh before subtracting
them from an aware clock. Rejected: assuming an unknown timezone or reporting
malformed freshness metadata as current.

Full command/output, delta and integration limits: `coverage-95-verification.md`.

## QA-95-02 — Saved intelligence corruption and revision boundary tests

Date: 2026-10-11. Status: added on the `codex/coverage-95` review branch.

Serves PROJECT.md stages 4, 6 and 7 and the cross-cutting reproducibility
component. Ranking comparisons require a stable, correctly bound intelligence
snapshot; a valid content hash alone does not establish valid snapshot semantics.

Add seventeen isolated synthetic cases for malformed JSON, incorrect schema/run
binding, malformed fields, corrupt latest revisions, missing-intelligence
disclosure and matching-state revision identity. Exercise the real SQLite and
history implementation in memory. These cases establish code-path contracts,
not real scanner, feed or model accuracy. No new real fixture is required for
this pure history-contract increment.

Rejected: falling back to an older valid revision when the latest is corrupt,
trusting a hash without validating its content, or inflating statement coverage
through exclusions. Existing code correctly enforces the tested cases, so no
runtime, schema, scoring, scope, dependency or validator changes are needed.
Keep the whole-package 95% gate; do not represent this as 95% product completion.

Verification and remaining limits: `coverage-95-history-followup.md`.

## CLAIMS-01 — Research success requires valid truth and tie-preserving metrics

Date: 2026-10-17. Status: implemented on the review branch; release verification
is recorded separately in the technical reference, not implied by this decision.

Serves PROJECT.md's cross-cutting evaluation/reproducibility component and stage 7.
Preserve equal numeric priorities as tied blocks in evaluation, including frozen
cohort filtering and ablations. Keep flat stable-ID orders for presentation only.
NDCG uses expected gain within each tied score block, including cutoff crossings;
critical-queue recall includes the whole terminal tied block. Canonical scores
and configured weights are unchanged.

Validate expert truth before metrics can coerce duplicate/invalid identities.
Synthetic truth, incomplete method populations, and undefined required metrics
cannot establish H2/H3. Distinguish a single expert from degenerate multi-expert
concordance. A failed stability check raises before publishing a success artifact;
audit loading checks the repeat evidence as well as the outer hash.

Rejected: treating finding IDs as scientific preferences, accepting a VERIFIED
string without inspecting the declared truth, or accepting a hashed but internally
contradictory stability artifact. Supplied reviewer IDs remain declarations, not
authentication or proof of independent ground truth.

## CLAIMS-02 — Targeted refresh must not score unrelated historical cache rows

Date: 2026-10-17. Status: implemented; external integration tested with injected
transports only. Serves stages 4, 6 and 7 and ranking-input reproducibility.

After a successful targeted sync, saved/live targeted matching receives a read-only
view limited to the requested CVEs. Missing requested NVD/EPSS rows remain missing;
unrelated records are neither decoded nor deleted. Offline snapshot consumers keep
full-catalog matching. Saved refresh validates retained prerequisites before cache
access. The view alone does not certify a publisher request or row authenticity.

Rejected: relabelling the entire cache as newly fetched, clearing unrelated CVEs,
or narrowing offline full-catalog matching. Those alternatives either misstate
freshness or destroy legitimate evidence/coverage. No score formula, dependency,
scope, credential or publisher endpoint changed.

## CLAIMS-03 — Partial collection survives reporting, replay and AI review

Date: 2026-10-17. Status: implemented; local verification is separate from any
claim that live tools or providers ran. Serves stages 2-4 and 7.

Keep successfully collected evidence when a requested endpoint/Nikto/protocol check
fails, but carry a partial collection outcome and its failed-check detail through
the live summary, checkpoints, replay, browser overview and history. AI failure
remains independent. A final AI receipt cannot change core collection identity or
upgrade its status, even if its content hash is recomputed.

Replay checks retained host/context prerequisites before completion events and
derives tool states from retained coverage. Missing legacy status is not automatic
success. Keep the established stage-state vocabulary: a generated report may be
complete while the overall scan is partial. Unknown stage states would break the
browser event contract and were rejected during integration review.

Rejected: discarding useful baseline evidence, silently calling partial coverage
complete, weakening AI validation, or adding an incompatible stage enum. No public
command signature, canonical schema, scope rule or numerical score policy changed.

## CLAIMS-04 — Public description must disclose actual network and evidence paths

Date: 2026-10-17. Serves stage 7 and honest reproducibility/privacy claims.
Correct the README's contradictory assertion that runtime never reaches the network:
the source contains targeted publisher lookups and consented cloud-model transports.
Replace stale universal readiness/test-count claims with dated verification links;
distinguish CVSS Environmental support from the project's inference method, full
versus partial coverage, current imports versus executable scanners, and missing
real Nikto provenance from synthetic examples. Preserve existing functionality.

Rejected: leaving a false offline/privacy claim in the public entry document while
qualifying it only in a buried technical guide. The edit does not change outbound
permissions, source behavior, dependencies, vendor editions, or credentials.

Verification follow-up for CLAIMS-01 through CLAIMS-04: the clean local official
gate passed with 2,147 tests and 510 subtests, no failures/skips, 99.90% statement
coverage, clean Ruff lint/format, and zero Pyright errors. Whole-package 95% remains
the floor. The optional workstation-blocked Hypothesis plugin alone was disabled;
no project tests were skipped. Commands, actual output, wall-time anomaly,
unchanged source fingerprint, missing real Nikto evidence, and integration limits
are recorded in TECHNICAL_PROJECT_REFERENCE.md section 40.8. This is not a remote
CI, deployed-server, real-provider, independent-research, commit or push claim.

## CLAIMS-05 — Protocol conventions and record counts are not execution evidence

Date: 2026-10-17. Serves stages 2-5 and 7: valid tool selection and honest context,
coverage and priority publication. Implementation verification follows separately.

Use one shared protocol interpreter for CLI, live web eligibility and planner
endpoint construction. Require a supported TCP HTTP service label; a common web
port or substring is not enough. Select HTTPS from a TLS flag or supported label,
not 443/8443 alone. Nmap ingestion no longer turns a port number or an explicitly
table-derived HTTPS guess into a positive TLS control. Strict boolean Service.tls
reads preserve the existing wire type instead of coercing strings/numbers to facts.
Keep scanner classifications distinct from independently verified handshakes.

Build summary coverage from retained metadata; absent metadata stays unknown rather
than claiming the light profile or absence of a Nessus import. Count only recorded,
target-bound priorities; reject duplicate/orphaned records, invalid identities,
non-finite/out-of-range values and unsupported bands before publication. Missing
scores remain explicitly unscored. Reject orphaned enrichment links rather than
inflate the enriched-finding count. The empty-case display fixture now supplies a
consistent empty set; its existing no-CVE assertion is retained and strengthened.

Rejected: scanning guessed protocols, marking TLS from port conventions, inventing
default coverage, or calling every finding a completed priority. No authorisation,
canonical scoring formula, dependency, provider, scanner-profile or schema-field
change. The zero/Low missing-severity-basis and file-mtime capture-date issues are
newly identified follow-ups, not repairs claimed by this decision.

CLAIMS-05 verification: official local gate passed with 2,265 tests and 515 subtests,
zero failures/skips, 99.89% statement coverage, clean lint/format and zero Pyright
errors. The 211-file source/config/test/script fingerprint remained unchanged during
the run. Actual commands/output and synthetic-versus-real limits are recorded in
TECHNICAL_PROJECT_REFERENCE.md section 40.9. No source push, server restart, real
scanner/protocol probe, provider call or independent accuracy claim follows.

## DOCS-REFERENCE-01 — Separate technical and accessible project references

Date: 2026-10-17. Serves PROJECT.md stage 7 and the cross-cutting research
reproducibility component. The user explicitly requested two Markdown documents:
an extensive implementation reference and an explanation suitable for other readers.

Expand TECHNICAL_PROJECT_REFERENCE.md and PROJECT_GUIDE_FOR_EVERYONE.md, link them
from README.md, and distinguish the baseline commit from the dirty working tree.
Describe real source capabilities, fixed boundaries, preview-only features,
unfinished work, and independent evidence requirements. A module, green node,
historical successful check, or high coverage percentage is not a completion claim.

Rejected: a single jargon-heavy guide, duplicated unqualified feature lists, and
describing the previous green checkpoint as verification of subsequent changes.
The two-audience explanation helps reviewers trace the proposed context-ranking
contribution to evidence without claiming the research hypotheses have succeeded.

The documentation refresh changed no runtime logic, dependency, scope, credential,
canonical score, or public interface. Existing source/test edits were preserved.
The full local gate returned 2,270 passed, 16 failed, 515 subtests passed, zero skips,
and 99.89% statement coverage. Pyright passed; Ruff lint/format and pytest failed.
The failures remain visible in technical-reference section 40.10. A separate focused
missing-severity run passed nine cases; it does not establish full integration.

Local Markdown target/anchor/fence checks and CLI help executed. Live scanners,
feed retrieval, real providers, remote CI, commit, and push were NOT RUN. An
independent real Nikto JSON fixture with completed provenance remains MISSING.
Policy/source discrepancies are documented, not silently resolved or approved.

## CLAIMS-06 — Missing severity is an unscored finding, not a Low priority

Date: 2026-10-17. Serves PROJECT.md stages 4-7 and trustworthy ranking input.
Implementation is local and uncommitted; the complete gate result is recorded
separately in technical-reference section 40.11, not assumed by this decision.

Require a usable CVSS v3.1 vector or an applicable configured native fallback
before constructing a ScoreBreakdown. Missing/unknown severity-table entries no
longer select the minimum entry. Raise IntelUnavailable rather than manufacturing
zero or a threat-only priority. A genuine computed zero remains valid. Published
arithmetic, weights, valid fallback values, canonical fields and scope are unchanged.

Live/saved analysis retains unsupported findings separately, with their identity
and missing-input reason, while supported findings keep their deterministic scores.
The collection outcome remains independent. Strict recorded ranking computes all
results before writes and refuses unsupported inputs without replacing prior scores.
Validate unscored annotations for binding, duplication, reason and contradiction
with scored IDs. Do not discard unsupported findings or let AI invent their number.

Overview, brief, live summary, saved review and printable report expose unscored
findings. Known historical priorities with explicit missing severity fields receive
a warning; their stored values and evidence remain unchanged. Minimal DTOs that
omit inputs and genuine zero values are not guessed invalid. The stored workbench
also carries a severity-review notice.

Rejected: assigning Low from missing evidence, KEV-only manufacture of a severity
basis, dropping unscored records, rewriting historic priorities, weakening the AI
validator, or changing the numeric formula to fit a demonstration. Four old test
expectations that codified the defect now assert explicit rejection and unchanged
input evidence; new mixed, genuine-zero, publication and no-partial-write cases
cover the intended contract. External branches remain TESTED WITH MOCKS.

## CLAIMS-07 — Capture chronology comes from recorded provenance, not file times

Date: 2026-10-17. Serves stages 3-4 and 7 and reproducible assessment identity.

Record the UTC collection-completion timestamp in new live manifests before AI.
Initial receipts retain that declared time rather than relabelling the collection
with receipt-publication time. Legacy receipts retain their recorded local timestamp;
its existence is not authentication of a scanner's original start/end. Validate
declared timestamps and receipt times as timezone-aware ISO strings. Invalid declared
time, corrupt receipts, and manifest/receipt disagreement fail closed.

Saved-CVE discovery uses recorded dates, not directory or manifest modification
time. One undated legacy capture remains usable with unknown date/source and a
visible warning. Multiple undated candidates cannot claim a newest capture. When
dated candidates coexist with undated candidates, disclose that the latter cannot
be compared. Equal recorded timestamps have an explicitly disclosed stable-ID
presentation tie, not invented chronology. Keep a bounded 100-directory discovery
budget and refuse overflow instead of silently excluding a newer capture.

Verify selected evidence against its hashes and parse the same checked case bytes,
both for legacy replay and receipt-backed review. Do not reopen case.json between
hash verification and parsing. Discovery still isolates unreadable unrelated
manifests; identified selected corruption cannot silently fall back to an older
valid case. Replays disclose unknown dates and keep intelligence refresh separate.
Opening a saved artifact never restores execution approval.

Rejected: filesystem dates as scan facts, re-dating old evidence on AI refresh,
arbitrary newest selection among undated captures, or trusting a receipt hash
without its manifest/evidence binding. Existing permission tests now intercept the
actual bounded binary read, and intentionally ordered synthetic fixtures declare
their chronology rather than relying on mtime. Full verification and remaining
limits are recorded in the technical reference; no real scan/provider proof follows.

CLAIMS-06 / CLAIMS-07 verification follow-up: after preserving the UI import wall
and moving presentation-only interpretation to score_facts.py, the official local
gate passed with 2,316 tests and 520 subtests, zero failures/skips, 99.83% statement
coverage, clean Ruff lint/format and zero Pyright errors. The measured 274-file
source/input fingerprint remained unchanged across the run. Section 40.11 records
the command, output, first integration failure and final result. No real integration,
remote CI, commit or push was performed. The independent real Nikto fixture remains
MISSING. A separate synthetic diagnostic reproduced loose HTTP control eligibility;
that defect remains open rather than being hidden behind this passing gate.

## CLAIMS-08 — Control eligibility uses the shared protocol boundary

Date: 2026-10-17. Serves PROJECT.md stages 5-7 and the context-ranking research
component: unsupported protocol assumptions must not earn Environmental reductions.

Replace the loose HTTP-name prefix in finding-scoped control eligibility with
the shared exact TCP/HTTP classifier already used for scanner selection. Preserve
the literal imported-URL fallback only when no matching service fingerprint is
present; a URL cannot override a contradictory observed service. Preserve raw
control observations and withhold ineligible score inputs rather than rewriting
the profile. WAF/authentication mappings and numeric weights are unchanged.

Record the corrected input-eligibility semantics as finding-scoped-controls-v2.
Historical v1 scores stay unchanged and retain their uncertainty when described;
do not turn their recorded signal into an assurance of proven mitigation merely
because the current policy identifier changed. The report assertion now checks
v2 for newly computed results, and a separate regression preserves v1 history.

The new protocol/control regression first returned 22 failures and 24 passes,
including both unsupported names earning credit and supported tls/http labels
being rejected. After implementation, the 187-case focused control/protocol/
severity set passed. Final whole-project verification is recorded separately.
Synthetic logic proves this boundary, not real service identity or mitigation.

Rejected: another duplicated prefix list, treating conventional ports as protocol
proof, accepting arbitrary HTTP-like labels, weakening existing evidence binding,
silently reusing the old policy version, or changing the risk formula. No scope,
model authority, dependency, canonical field or public command shape changed.

## CLAIMS-09 — Summary construction cannot infer successful collection from absence

Date: 2026-10-17. Serves stages 3-4 and 7 and honest completion reporting.

A summary with no collection outcome records unknown, not complete. Explicit
complete/partial values are preserved; malformed, Boolean, numeric or unsupported
values raise ConfigError. The unknown value belongs to summary metadata only;
it does not extend the existing scanner-stage or collection-result vocabulary.
Actual new/replayed execution paths already provide their checked outcome.

Initial regression output was nine failures and two passes. After the repair,
169 related summary/replay/live cases passed. Missing history must not be upgraded
to success, but valid limited evidence remains visible. This changes no scanner,
scope or scoring logic. Rejecting malformed metadata is preferable to inventing
success or discarding all valid evidence because an outcome was never recorded.

## CLAIMS-10 — Final review summaries remain bound to retained evidence

Date: 2026-10-17. Serves stages 4-7 and the reproducibility/evidence component.

Freeze all non-AI summary content across the evidence checkpoint and final AI
review, not only the outer result identity. Permit only the six intended AI fields
to change. Validate available summary counts, priorities, unscored findings, target,
context, coverage, intelligence and local-device facts against retained records.
Missing legacy fields stay missing/unknown; their absence is not a recorded zero
or successful coverage. Do not recalculate a historical score under new weights.

Compare strict JSON content so false cannot stand in for zero, and non-finite
numbers cannot become accepted canonical facts. Check AI status/attempts against
the outer result. Nonempty AI summary content needs its retained analyst source;
rejected/unavailable output cannot be smuggled into a final summary. Batch totals,
omissions, count and absence of cross-batch reasoning must remain consistent with
retained findings/batches. The initial AI boundary remains responsible for claim
semantics; this receipt verifier is not another model or score engine.

Subagent red reproduction returned 106 failures and three passes. Parent review
added 14 failing cases for self-consistent but impossible AI coverage metadata,
then repaired the missing checks. Focused integration returned 481 passes, followed
by 303 passes after the additional coverage guards. Full-gate evidence is recorded
separately. Existing fixtures and assertions were not relaxed to pass.

Rejected: trusting recomputed hashes as evidence of semantic consistency, freezing
only top-level counts while letting their summary contradict them, silently filling
legacy gaps, or importing live/scoring/model engines into history verification.
No raw evidence, stored score, approval authority, canonical field, dependency or
scope changed. These checks establish internal consistency, not authenticated
capture provenance, cryptographic authorship or correctness of a stored score.

Integration follow-up: the first whole-project run reached 2,556 passes and one
failure in the saved-review escaping fixture. That fixture declared validated AI
prose without retaining its analyst source. Supply the matching synthetic source,
preserve every existing escaping assertion, and add an assertion binding the
summary to that source. The production guard and its negative tests remain strict.
Historical v1 description now explicitly names its legacy eligibility policy,
rather than implying that v2's strict HTTP classification was verified retroactively.

CLAIMS-08 to CLAIMS-10 final verification: the official local gate returned 2,557
passed and 520 subtests passed, no failures/skips, 99.78% statement coverage,
clean Ruff lint/format and zero Pyright errors. The 276-file source/input hash was
unchanged across the run. Actual output, earlier failure, corrected fixture and
integration limits are recorded in technical-reference section 40.12. The separate
H1 metadata-provenance defect remains open. No commit, push, server restart or real
scanner/provider/expert experiment was performed; independent Nikto capture
provenance remains MISSING.

## DOCS-REFERENCE-02 — Finish the extensive and plain-language references

Date: 2026-10-17. Serves PROJECT.md stage 7, explanation and reporting, and the
cross-cutting reproducibility/evaluation component. The current user request is
two Markdown files, not another runtime feature increment.

Keep the technical reference extensive and source-oriented, while making the
companion guide readable by teammates, teachers, reviewers and operators without
code knowledge. Add explicit reading routes, a route/effect navigation map,
authority distinctions and practical vocabulary. Preserve the historical checks
but remove unnecessary test-construction detail from the accessible explanation.

Read-only source reviewers identified claims requiring correction: exact grouping
can match missing endpoint values; audit attachments do not receive universal full
schema/semantic validation; native fallback does not apply EPSS/Environmental
adjustments; external vantage is rule-labelled despite its metadata origin;
timestamp consistency is not complete stage chronology; re-scan outcome labels are
conservative candidates; and the HTTP follow-up is a literal-IP plaintext root
HEAD request. Describe these limits instead of silently repairing or advertising
them as more capable implementations.

Rejected: one jargon-heavy document, copying the roadmap as a completed inventory,
turning historical coverage into a detection-accuracy claim, or continuing unrelated
runtime repairs during the documentation request. Existing source/test work is
preserved; no schema, dependency, scope, credential, scoring or command change is
made. The H1 provenance defect remains open, and a real independent Nikto fixture
with completed provenance remains MISSING.

VERIFIED: local CLI help, Markdown paths/anchors/fences/chapter checks, common
secret-pattern checks and diff whitespace checks. The 276-file source/input
fingerprint still matches the separately recorded 2,557-test local gate. The gate
was NOT RUN again for documentation-only edits. Technical-reference section 32.6
records the command scope and limits. No scan, publisher/model call, installation,
commit, push or deployment was performed.

## CLAIMS-11 — H1 eligibility follows evaluated prediction provenance

Date: 2026-10-17. Serves PROJECT.md stage 5 and RQ1/H1: an owner-supplied or
model-derived answer must not establish zero-manual-tag rule inference.

Inspect role, exposure and applicable labelled controls for the truth cohort.
Manual feature sources and generated scope-tag evidence set manual_tags_used;
manual/model/llm sources or scope metadata make H1 ineligible. Check provenance
even when external-vantage exposure carries the existing rule source label and
the manual dictionary is empty. Preserve predictions, controls, evidence, scores,
descriptive accuracy and the complete truth denominator. Unused environment tags,
unlabelled extra profiles and separate shadow predictions do not contaminate
otherwise rule-only evaluated inputs.

Ineligible evaluations retain descriptive metrics but have NOT RUN evidence status
and null H1 pass/fail fields. Missing profiles and synthetic truth cannot establish
H1. Validate the existing declared types rather than coercing truth identities,
Boolean controls, shadow confidence/abstention or profile labels. Recheck mutable
truth-control mappings and reject duplicate truth hosts. A document-level synthetic
comment downgrades interpreted label_source to synthetic without changing the
input file or original provenance. Reject duplicate YAML keys, invalid encoding
and malformed mappings as controlled input errors. No new public field, signature,
command, table, configuration or dependency is introduced.

Initial regressions returned 54 failures and 12 passes. Further tests reproduced
18 shadow/synthetic/encoding failures, eight malformed shadow collection/identity
failures, eight unsupported context-label failures and five duplicate/mixed-key
truth failures before the respective repairs. One new integration assertion first
assumed all fixture roles were known; it now checks the actual full denominator
including unknown-role abstentions, not an invented perfect accuracy. The tests
explicitly simulate declared-human metadata and do not constitute human truth.

Rejected: hiding contaminated hosts, recomputing profiles to obtain better results,
letting shadow-model accuracy stand in for rule accuracy, changing .85/.95 targets,
relabelling canonical context or altering existing scores. These guards verify
declared provenance and coherence, not the identity or independence of reviewers.
Full-gate verification is recorded separately after final source integration.

## CLAIMS-12 — Rehashed context artifacts must remain semantically coherent

Date: 2026-10-17. Serves stage 7 and research reproducibility. A matching local
digest alone must not publish a contradictory claim of completed H1 evaluation.

Context attachment loading checks supplied flags, status/provenance, host/group
counts, metric denominators, supported labels, confusion counts, class metrics and
H1 thresholds/pass decisions. VERIFIED results require the existing supporting
metric fields; dropping their evidence is not an accepted successful artifact.
Eligible H1 requires VERIFIED evaluation evidence. Sparse legacy NOT RUN results
remain unknown without invented provenance or predictions. Existing stability
checks remain intact. No changes to canonical scores or stored assessment inputs.

Delegated red tests returned 118 failures/11 passes, then eight failures/133 passes
while extending the guards. Parent review added 16 artifact failures plus 20 valid
evaluator/rounding cases and eight invalid context-label cases. Two synthetic
comparison fixtures had used role labels as exposure classes; they were corrected
to the actual exposure vocabulary while preserving their pass/fail, missing-data,
immutability and descriptive-metric assertions. The validator was not weakened.

Rejected: trusting a recomputed hash as proof of semantic consistency, allowing
ineligible results to carry pass/fail conclusions, accepting missing metrics as a
verified result, or silently promoting incomplete legacy attachments. Validation
of supplied arithmetic does not authenticate reviewers, reconstruct unavailable
truth, bind every artifact to an independently trusted cohort or prove actual
inference quality. Those remain separate research requirements. No real scanner,
publisher, model or expert experiment, installation, commit or push was performed.

CLAIMS-12 scope follow-up: read-only review traced an additional cross-artifact
gap. An internally coherent old context evaluation can still attach under the same
run after stored profiles change, because missing optional snapshot/cohort bindings
are accepted and the old full per-host input mapping was not retained. This was
not runtime-reproduced in the frozen-source gate and is not claimed repaired.
Next: a stale-evaluation/current-provenance regression and read-only subset guard;
keep exact historical identity limitations explicit rather than overstate what
internal arithmetic checks establish. Grouping-instance identity remains separate.

CLAIMS-11 / CLAIMS-12 final verification: 405 focused tests passed. The official
local gate then passed Ruff lint/format, Pyright with zero errors/warnings, and
2,844 tests plus 520 subtests, zero failures/skips, with 99.64% whole-package
statement coverage and the unchanged 95% floor. The 278-file source/input hash
remained 28f6ccef002e3a41c4cac7d1ceb791e7149ebc2a7fcd38b24e9483890478ed88
through the run. Section 40.13 records actual output and the 676.47-second test
duration; existing role-training/ablation calls were the longest reported tests.
No restart, exclusion, assertion weakening, real integration, commit or push was
used to obtain the result. This checkpoint adds 287 tests, not proof of empirical
H1 effectiveness or closure of the separate attachment-binding gap. The active
audit continues with that concrete counterexample and other unfinished claims.

## CLAIMS-13 — A context artifact must match or qualify its report-state relationship

Date: 2026-10-17. Serves PROJECT.md stage 7 and research reproducibility. The
previous context validator checked internal arithmetic, not whether an old result
described the current stored assessment under the same run ID.

Before publishing a VERIFIED context attachment, reconcile its evaluated subset
using recorded truth count and unlabelled hosts. Require selected profiles to have
observed hosts, eligible current role/exposure provenance, and matching prediction
marginals. For partially labelled controls, require a feasible clean-source subset
rather than assume every control or every host was evaluated. Reuse the evaluator's
provenance and observation semantics; never synthesize host truth to perform this
check. Contradictions raise ConfigError before HTML is written and preserve stored
evidence, profiles, scores and the original artifact bytes.

Aggregate compatibility cannot establish historical per-host identity. An unbound
artifact keeps its original evaluation data, but its report-state evidence row is
NOT RUN with an adjacent unbound qualification and visible limitation. An existing
snapshot_hash binding can retain VERIFIED correspondence only when checked against
fresh current state, whether or not a report snapshot option was supplied. Recheck
profile contents at that point, rather than reuse an earlier snapshot check after
the underlying inputs might change. This remains a point-in-time consistency check,
not a transaction-wide concurrency guarantee or authentication of a reviewer.

Require artifact run identifiers to be nonempty strings; integers/Booleans cannot
be converted into matching string IDs. No command, schema field, signature, table,
dependency, target scope or canonical scoring rule is added or changed. The current
context-eval producer still lacks a recorded immutable input binding: its unbound
result is therefore qualified, not silently promoted to a bound research result.
Future producer/protocol expansion must follow the existing interface approval.

Initial report regressions returned 29 failures/one pass, then 34 failures/two
passes after adding positive binding and same-marginal cases. Two identifier
coercion cases failed separately while the actual HTML warning test passed. A
simulated input change between snapshot validation and attachment verification
reproduced another failure before the fresh-state check. Initial integrated checks
returned 174 passes, then 553 passes and 409 subtests before that final race case.
Final focused/full verification is recorded separately after integration.

Rejected: trusting run ID or a self-consistent digest as full assessment identity,
inventing per-host truth, treating unchanged aggregates as proof of unchanged
inputs, dropping descriptive metrics, blindly including unused manual controls,
or weakening the existing artifact validator. A hash still establishes content
consistency, not independent provenance or successful empirical hypotheses.

## CLAIMS-14 — External-vantage metadata is manual exposure provenance

Date: 2026-10-17. Serves PROJECT.md stage 5 and the automatic-context research
boundary. Newly built exposure features derived from scope.tags.vantage=external
now use the existing manual source, not rule. Preserve the same exposure value,
confidence, quote, segment and numerical score for otherwise identical inputs.
Address-derived exposure remains rule. Historical profile JSON and stored score
inputs are not relabelled or rewritten; the H1 legacy quote guard stays in force.

Delegated red verification returned 20 failures/eight passes. All 28 new cases
then passed, including 12 scoring combinations, unrelated metadata, actual profile
construction and historical in-memory JSON preservation. The 86-case focused
context/scoring set plus 40 subtests passed. The parent updated the existing new
provenance assertion to require manual for the actual constructor; separate legacy
rule-labelled scope-quote cases remain unchanged. No numeric, scope, schema,
interface, dependency or configuration change was made.

Rejected: leaving human metadata disguised as observation, modifying confidence or
rank to make a test pass, adding another source enum, or rewriting historical
artifacts. Correct provenance makes the research claim inspectable without claiming
that the exposure estimate or the risk mapping has been independently validated.

CLAIMS-13 / CLAIMS-14 focused integration: 576 tests and 409 subtests passed in
75.54 seconds, zero failures/skips. Ruff lint/format passed for the changed files;
scoped Pyright reported zero errors/warnings. Additional negative cases cover
malformed stored inputs, duplicate/orphan profiles, missing/negative control
observations and feasible-but-unbound applicability mappings. No full-gate result
for these newer changes is asserted by the previous 2,844-test checkpoint.

Verification-scope follow-up: the earlier aggregate fingerprints explicitly
covered selected source/input directories, not every root/support/document file.
For this increment's complete run, also freeze all tracked/nonignored working
files and avoid documentation edits until the process completes. Compare both
aggregates afterward. Final guide/result updates are separately checked and must
not be described as part of an earlier frozen input. Fingerprints establish
content identity over their named scope, not a trusted operator or secure host.

CLAIMS-13 / CLAIMS-14 full-gate follow-up, completed by 2026-10-18: the installed
Python 3.12 `-u -B scripts/check.py` run passed Ruff lint, format (272 files),
Pyright (zero errors/warnings/informations), and pytest at the unchanged 95%
whole-package floor. Output: 2,934 passed, 520 subtests passed in 334.75 seconds;
99.63% statement coverage, zero failures/skips. Only the optional workstation
Hypothesis plugin was disabled. Both pre/post aggregates matched: 280 scoped
files e471b1ea3d7939553c7036c035ceb3f1f0621cd76a4a728a39c17852b95ba3d3;
389 tracked/nonignored input files
9185dcf31848ee85692128a2ef620ad1d3e4c135f9e57c91238b903d5abd8647.
The later result/document edits and CLAIMS-15 are not part of this checkpoint.

## CLAIMS-15 — Cohort manifests reject type confusion before hash validation

Date: 2026-10-18. Serves cross-cutting evaluation/reproducibility and PROJECT.md
stage 7. The loader formerly coerced schema/cutoff with int() and identifiers,
hashes and collection elements with str(). Distinct raw values could reuse a
valid manifest digest after normalisation: schema 1.9/true/"1" to 1, cutoff 10.9
to 10, and numeric-looking identities/digests to strings. Truth and evidence
checks are separate; this is not claimed as proof of forged independent review.
Malformed reviewer/approval fields also raised uncontrolled AttributeError, while
malformed maps could fail outside the intended ConfigError boundary.

Enforce existing declared types in CohortManifest before operations and require
JSON arrays/maps before construction. Remove lossy scalar/element conversions;
keep valid manifest hashes and all existing fields/signatures/version unchanged.
Non-string optional metadata is invalid even when status is NOT RUN. Preserve
the existing nullable metadata policy and VERIFIED size/approval requirements.
No scoring, scope, dependency, schema extension or authentication claim is added.

Initial synthetic regression run: 71 failed, 20 passed in 2.54 seconds. After
repair: 168 focused cohort/research tests passed in 3.66 seconds, zero skips or
failures; scoped Ruff lint/format and Pyright passed. Tests include unchanged
original hashes after coercible edits, rehashed malformed inputs, constructor
type checks, valid round trips, and CLI exit 2 without traceback/partial output
or file changes. Complete verification of this newer tree is pending.

Rejected: accepting bool/float/text as a supported schema or cutoff, coercing
identities before comparison, catching AttributeError and silently continuing,
changing valid hashes, adding new protocol fields or claiming declared reviewer
strings establish independent approval. The research question requires a stable,
auditable evaluation contract, not the appearance of a passing artifact.

## CLAIMS-16 — Review-driven legacy provenance and model-binding repairs

Date: 2026-10-18. Serves PROJECT.md stages 5/7 and research reproducibility.
After the user delegated reviewer choice, the specialised security-review tool
was unavailable. One general read-only agent performed an explicitly labelled
fallback audit, not a specialised review or certification. It reproduced two P2
issues: CR/LF target names escaped the historical scope-metadata regex, and an
artifact declaring model A could bind a model-B snapshot when supplied via the
report option. The completed 2,934-test gate did not catch these paths. It found
no new partial-HTML-publication path; this does not claim the CLI never performs
Store initialisation/migrations before rejecting an attachment.

The user explicitly requested fixes and regression verification for both. Retain
existing scope/schema contracts; correct the declaration checks rather than ban
otherwise accepted target names or change canonical scoring. Legacy metadata
detection must include multiline names. Model declarations must not be replaced
by the report snapshot, and contradictory declarations must fail before report
publication. Preserve matching-model and genuinely rule-derived positive cases.

Rejected: ignoring independently reproduced counterexamples because coverage is
high, treating a supplied snapshot as authority to rewrite an artifact's declared
model, relabelling stored historical evidence, changing target permissions, or
claiming the fallback audit established the entire project is secure. Regression
and complete gate evidence will be recorded after execution. No second review is
claimed or launched without a separate request.

CLAIMS-16 verification follow-up: parent reproduction returned 29 failures and
177 passes in 70.44 seconds before implementation. The regex now recognises
multiline names; no accepted scope shape or target permission changed. A context
artifact's model_hash is string-or-null, must match a supplied report snapshot,
and is always used when rebuilding the current binding. Legacy absent/null
declarations remain compatible with null identity, not a declared non-null model.
Contradictory model declarations also fail for unbound VERIFIED artifacts.

After implementation, 625 focused context/report/cohort/research tests passed in
87.67 seconds, zero failures/skips. Scoped Ruff lint/format and Pyright passed.
The new CLI rejection tests preserve existing HTML and canonical assessment
records; they do not claim Store initialisation can never migrate a database.
A separate complete frozen-input gate is pending; no second independent review
or real scanner/model/expert verification is asserted.

CLAIMS-15 / CLAIMS-16 complete verification, 2026-10-18: installed Python 3.12.10
ran `-u -B scripts/check.py` with temporary PYTEST_ADDOPTS appending
`-p no:hypothesispytest -q --durations=8 --tb=short`. Ruff lint passed, all 273
files were already formatted, and Pyright returned zero errors/warnings/info.
Output: `3059 passed, 520 subtests passed in 733.46s (0:12:13)`; 99.63% statement
coverage (10,802 statements, 40 missed); `GATE PASSED`, zero failures/skips.
No project tests were excluded or floor/socket guard reduced. This adds 125
cases to the prior 2,934-test checkpoint; rounded coverage is unchanged.

The scoped pre/post input aggregate matched for 281 files:
b20c37156cd75d21f4c9981963968b5e5e86cb4ee67aa3a597e6ba2c4a68cf7a.
The tracked/nonignored working-input aggregate matched for 390 files:
81ebd4eaf6ef45547a292415f51eff449d983811ee8ad74792db7a234f2f39a2.
Both comparisons completed before any result/document edits. Subsequent changes
are confined to existing README/guides/decision log and separately checked, not
included in the frozen full-input aggregate. No source/test/config code changed
after this gate. The broader audit remains active; neither the passing gate nor
the read-only fallback review certifies the project, empirical accuracy or live
integrations. Missing real Nikto provenance and the input-binding producer/grouping
limitations are not erased. No commit, push, restart or installation was performed.

## CLAIMS-17 — Unknown instances and overlapping CVEs are review candidates

Date: 2026-10-18. Serves PROJECT.md stage 4 and reproducible evidence grouping.
The existing implementation equated absent URLs/endpoints and auto-unioned any
same-instance overlapping CVE pair, allowing A -> A+B -> B and pairwise-overlap
triangles to masquerade as one duplicate issue. Foreign enrichment ownership and
malformed CVE identifiers were not checked before using them as group identity.
Initial synthetic regressions returned 38 failures/four passes; another 16
malformed-ID cases failed before correction.

Require an established nonblank host, bounded actual integer port, TCP/UDP,
nonblank whitespace/control-free matching URL, and identical nonempty complete
CVE sets before auto-grouping. Preserve ambiguity/partial overlap as explicit
review links through the existing free-text candidate method/reason fields.
Reject foreign enrichment finding IDs and malformed identifiers without rewriting
raw evidence. Keep group-ID hashing, numerical confidence constants, schemas,
public signatures, tables, scope and canonical ranking unchanged. No model acts.

Rejected: connected components, pairwise clique rules or merely a common CVE as
proof that a compound record describes only one issue; guessing a missing URL;
silently deleting uncertain findings; or claiming a heuristic confidence is a
validated probability. Compound records cannot be safely split into new canonical
issues under the current one-source-once preview contract. More semantic/instance
support needs its own reviewed design, not an invented identifier.

Positive merge fixtures now establish explicit matching URLs while preserving all
their assertions. New negative cases cover the old absent-instance behaviour.
Input-order permutations, exact valid groups, candidate visibility and untouched
temporary database/score state are tested. A mistaken singular Store call in the
new test was corrected to the existing plural API, not treated as a product bug.
Focused results: 73 passes, then 119 passes; the expanded 62-case identity suite
also passed. Complete integration/gate evidence will follow.

## CLAIMS-18 — A grouping attachment needs consistency and current correspondence

Date: 2026-10-18. Serves PROJECT.md stages 4/7. A self-consistent preview hash must
not excuse impossible counts, missing/duplicate source coverage, forged group
identity, unknown candidate endpoints or a claim that preview changed ranking.
Existing free-text reason/method fields remain free text; no fixed allowlist or
new field/schema is introduced. Preserve sparse lower-status legacy unknowns
without promoting them. A VERIFIED report attachment must also agree with the
current recomputed read-only preview, not merely copy a real snapshot hash.

A separate agent owns only audit.py and one new synthetic artifact-integrity
test file; the parent owns matching, related positive fixture corrections and
existing documentation. No network/scanner/model/install or Git mutation is
authorised. Implementation and verification are pending. The earlier 3,059-test
gate remains a dated checkpoint, not verification of these new changes.

CLAIMS-17 follow-up: seven malformed raw-source-ID cases reproduced blank-ID
acceptance or uncontrolled type/hash errors. Reject non-string/blank finding IDs
before dictionary/hash operations; no valid UUID/fingerprint is rewritten. The
grouping/core focused set then returned 112 passes in 15.17 seconds. New tests
also verify candidate explanations in actual generated HTML and an unchanged
temporary database/score queue across preview execution. Full integration and
the complete gate still need the parallel attachment work to finish first.

CLAIMS-18 implementation follow-up: the agent completed audit.py and its single
new synthetic test file, recorded 259 failures/21 passes before the internal
validator, then 27 failures/eight passes in targeted attachment cases. Its green
runs returned 800 passes in 140.61 seconds and 429 passes in 16.37 seconds. No
other files were edited by it; the parent reviewed the added validator/report
code and closed the agent before the complete-tree freeze.

Parent integration reproduced another six failures: late assessment drift after
an initial supplied-snapshot check, and invalid model-ID types. Rebuild the fresh
snapshot even when one was supplied, compare the bound identity, and recompute
from the exact captured findings/enrichments inside that object. Do not mix that
binding with a later series of live reads. Declared model identity remains
string-or-null and must agree with the selected report context. The current
producer's absent optional model field can still use its supplied snapshot's
identity without a new public field. This is not a transaction-wide concurrency
or authentication guarantee. No second independent review is claimed.

## CLAIMS-19 — Group comparisons are scoped to deterministic service blocks

Date: 2026-10-18. Serves PROJECT.md stage 4. An operation-count regression with
200 unrelated services observed 39,800 service comparisons before indexing.
Partition records by their exact declared host/port/protocol representation
before comparing candidate pairs. Existing candidate/group ordering and source
IDs remain deterministic; malformed non-JSON service values fail with a named
ConfigError. No network resolution, new fields, weights, public signatures or
canonical score changes occur. The strengthened test observes zero cross-service
comparisons afterward. This measures operations, not a real throughput benchmark.
Dense same-service workloads can still be quadratic and need separate budgets
and scalability evaluation rather than an unsupported performance claim.

Rejected: adding more machines/providers to hide unnecessary all-pairs work,
dropping records to speed up the preview, truncating candidate lists silently,
or claiming this index solves every large-data case. Parent final focused
integration returned 521 passes in 120.21 seconds; the operation-count/error
subset passed three cases afterward. Scoped Ruff/Pyright passed. The complete
frozen-tree gate for CLAIMS-17 through CLAIMS-19 is still pending.

CLAIMS-17 through CLAIMS-19 complete verification, 2026-10-18: installed Python
3.12.10 ran `-u -B scripts/check.py`, with temporary PYTEST_ADDOPTS appending
`-p no:hypothesispytest -q --durations=8 --tb=short`. Ruff lint and format passed
(275 files already formatted), Pyright returned zero errors/warnings/info, and
the final output was `3466 passed, 520 subtests passed in 745.73s (0:12:25)`;
`GATE PASSED`, zero failures/skips. Coverage was 99.59% (10,953 statements,
45 missed). The 95% floor/socket guard remained active, and no project tests were
excluded. Compared with the preceding gate: 407 more cases, 151 more statements,
five more missed statements and a 0.04-percentage-point coverage decrease. Do
not misrepresent that as a coverage improvement or 100% verification.

Before result/document edits, both pre/post aggregates matched: 283 scoped inputs
bca54550df406621a757fe9c2fb5afdcc111bd6faefe76a265cef5f91775016c;
392 tracked/nonignored working inputs
d3b612922369fd4f89652b132c3748fcc5d8bd77f4e753b990528002f59c1476.
Only existing documentation is updated afterward; it is separately checked and
not included in the frozen full-input claim. No source/test/config code changed
during or after the run. Logical SQL dumps and score records were compared in
the read-only tests, not physical SQLite-file bytes. Real scanner/independent
labelled grouping evaluation is still missing, and dense same-service work may
still be quadratic. The source-traced snapshot-validator lead remains a separate
next audit, not a reproduced or repaired claim. No commit, push, restart,
installation or real network/provider/model call was performed.

## CLAIMS-20 — Snapshot identity needs typed records and owner relationships

Date: 2026-10-18. Serves PROJECT.md stage 7 and cross-cutting reproducibility.
A recomputed hash previously excused malformed arrays/records, duplicate host or
finding identities, foreign ownership, and untyped score/context declarations.
The first synthetic reproduction returned 85 failures/10 passes. Validate the
existing snapshot structure, declared types, unique identities and relationships
after checking its hash, including finding/host, profile/host, enrichment/finding,
score/finding/host and rationale/finding. Exports validate before publication;
expected malformed-data errors become ConfigError, not partial success/traceback.

Stored JSON readers also coerced booleans, fractional indices, text numbers and
truthy strings before snapshot validation. Require their declared types first,
preserving valid integer-to-float serialisation. Require actual arrays/objects
before tuple/dict conversion can turn object keys into CVE/reference lists or
pair arrays into metadata maps. Numeric regressions returned 23 failures/one
pass before those guards. Eight further collection-reader failures reproduced
lossy conversion. A ninth failing export test initially edited the old global
finding table; correct it to the actual run observation read path and assert the
update count. That test correction is not another product defect.

Rejected: hash-only acceptance, silently repairing malformed records, changing
IDs/fingerprints, recomputing canonical scores during import, requiring every
partial assessment to be complete, or relabelling original capture run IDs as
the current run. Optional legacy absence remains unknown and valid records are
not mutated. This is structural consistency, not authentication, raw-file
verification, formula recomputation or proof of capture origin. No new public
fields/signatures/schema/table, dependency, scope or weight changes are made.
New cases live in tests/synthetic/test_synthetic_assessment_snapshot_integrity.py.
Complete-tree gate evidence remains pending for this increment.

CLAIMS-20 focused follow-up: after the collection guards and corrected run-row
test, the installed Python `-B -m pytest` command over the new snapshot and
promotion-input suites, snapshot/cohort/research/audit-report/governance and core
compatibility tests returned `243 passed in 23.60s`, zero failures/skips. Scoped
Ruff lint passed; formatting was normalised without changing test assertions.
The previously recorded 210-pass run predates the added collection cases.

## CLAIMS-21 — Promotion declarations use the bounded shared JSON boundary

Date: 2026-10-18. Serves research reproducibility and stage 7 evidence. The
role-model promotion loader previously read unbounded JSON text with permissive
duplicate-key/nonfinite decoding. Reuse the existing shared local JSON reader,
which rejects network-share paths, excessive size/depth/nodes, duplicate keys,
nonfinite numbers and malformed encoding with a named ConfigError. Keep existing
manifest validation and promotion requirements unchanged; a parsed declaration
does not establish genuine independent approval or enable model scoring inputs.

The delegated coding task owns model_governance.py and one synthetic test file;
its 50 cases initially returned 25 failures/25 passes and then all passed. The
parent reviewed the implementation and tests. The old unreadable-manifest test
now mocks Path.open, the actual byte-reader seam, instead of the obsolete
Path.read_text seam; rejection assertions are unchanged. Reject an independent
parallel loader with subtly different budgets or a permissive fallback. The
parent's first integrated snapshot/manifest set returned 210 passes in 17.70s.
No independent review or real model approval is claimed by those tests.

## CLAIMS-22 — Offline gate execution must not invoke an updater

Date: 2026-10-18. Serves cross-cutting reproducibility and section 0b. DEVIATION:
the delegated task reported that an ordinary installed Python Pyright-wrapper
invocation attempted an automatic PyPI version lookup. This violated the
no-network execution instruction; no package was installed. The user was told.
The task's later pinned/socket-guarded check reported zero attempts and zero
type errors, but that does not erase the original lookup or prove old gates
were wholly offline. Historical test/type/pass counts remain factual; their
pytest socket guard did not independently establish updater behaviour in a
separate checker subprocess. This qualification also applies to earlier blanket
no-network wording in this log and the guides.

Do not invoke the Python wrapper again. A bounded gate repair will locate the
already-installed Pyright JavaScript bundle and Node runtime, launch it directly
with a network-denying preload, and fail with MISSING rather than bootstrap or
download a runtime/bundle. Tests must replace original network APIs with
fail-fast stubs before loading that guard, so a broken guard cannot make the test
attempt network. No new dependencies or remote CI execution is authorised.
Implementation and complete-gate verification are pending; this is not a claim
of OS-level sandboxing or complete project offline certification.

CLAIMS-22 implementation follow-up: the separate coding agent changed only the
offline launcher/preload, check.py, Makefile, the CI checker invocation and one
synthetic gate-test file. Parent reviewed them and closed the agent. Discovery
uses package metadata, requires both installed JS entry files and an existing
Node executable, replaces child-only NODE_OPTIONS with the known denial preload,
and defaults the checker's Python interpreter to sys.executable. Explicit
interpreter overrides remain supported. Missing prerequisites return 127 and
the gate reports MISSING; PATH-only executables no longer satisfy python -m
module checks. CI provisioning is untouched and remote CI was not executed.
The missing .pre-commit-config.yaml is not silently created or claimed repaired.

VERIFIED parent checks: the synthetic gate suite returned `28 passed in 3.20s`;
the actual direct installed checker then found three Unknown-type errors in the
new schema helpers. Add explicit typed views only after runtime type checks;
do not suppress diagnostics or remove validation. Scoped Ruff lint/format then
passed (eight files already formatted), and the direct installed checker returned
`0 errors, 0 warnings, 0 informations`. Stubbed Node tests exercise the denial
paths safely; neither they nor the Python socket guard establish OS isolation.
The expanded original provenance regression returned `625 passed in 57123.47s
(15:52:03)`. The cause of that unusually long elapsed time was not investigated;
it is not a performance benchmark. The complete current-tree gate is next.

CLAIMS-20/22 first complete gate, 2026-10-18: Ruff lint/format (279 files) and
the direct installed Pyright check passed with zero errors/warnings/info. Pytest
returned `4 failed, 3669 passed, 520 subtests passed in 754.38s (0:12:34)`.
Coverage was 99.46% (11,204 statements/60 missed), but the gate correctly FAILED;
coverage does not cancel failing tests. Both frozen-tree comparisons matched:
288 scoped files 8901ff31f6a38bbc0926d4b8ff2726579eca6db0cc012ccdd0adcaddbefd435e;
397 working inputs 67127d1832a6897e13f6e270165037db579bf72c0113cec426e8af562b5c5d19.

Conflict / resolution / why: the four failures exposed an existing, desirable
remediation contract in test_remediation_versions.py. Invalid legacy optional
range-boundary metadata becomes unknown; it must never be guessed into an
inclusive/exclusive boundary or a vendor-fixed-release recommendation. Restore
that exact Enrichment.from_json behaviour rather than weaken/delete its existing
assertions. The new snapshot importer still rejects wrong-typed explicit boundary
metadata; move the newly added reader expectations to that actual strict import
boundary and add positive legacy-unknown preservation cases. No existing test
assertion was changed. Canonical KEV, score, confidence, index and port guards
remain strict. This documented legacy exception cannot be described as rejecting
every malformed stored optional field. A fresh complete gate is required.

CLAIMS-20 through CLAIMS-22 corrected-tree verification, 2026-10-18: the final
focused set returned `294 passed in 22.87s`. The installed Python 3.12.10
`-u -B scripts/check.py` command, with temporary PYTEST_ADDOPTS appending
`-p no:hypothesispytest -q --durations=8 --tb=short`, then returned:

```text
PASS    ruff lint
279 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 11202     59    99%
Required test coverage of 95% reached. Total coverage: 99.47%
3679 passed, 520 subtests passed in 675.06s (0:11:15)
PASS    pytest + coverage
GATE PASSED
```

Zero failures/skips. The optional workstation Hypothesis plugin was disabled,
not project tests. Keep the socket guard and 95% floor. Pyright ran through the
installed direct bundle with the Node denial preload; it did not invoke the
Python updater. This does not certify OS isolation or erase the earlier lookup
deviation. No dependencies, public fields/signatures/schemas, numeric weights,
canonical formula, scope, raw evidence or existing remediation assertions changed.

Both pre/post fingerprints matched before documentation edits: 288 scoped files
156cbdd36e5b6f4cbf39547cc4cc95e76ec205041d89c67d41c6f05d633edff7;
397 tracked/nonignored working inputs
d8bdad5df2523799509bec28b393a281e87c11612d76a896d04f143bdb5cdb84.
Only existing documentation changes afterward and is separately checked, not
included in that frozen full-input claim. Relative to CLAIMS-19 this adds 213
cases (135 snapshot, 50 promotion input, 28 tooling), 249 measured statements,
14 more missed statements and a coverage decrease from 99.59% to 99.47%.
Separate read-only coverage output identified 14 missed snapshot statements and
22 missed audit statements. A pass is not full branch verification or research
effectiveness. The broader audit stays active; no second independent review,
remote CI, real scanner/provider/model call, install, commit or push was run.
MISSING: completed human-captured Nikto JSON/provenance under tests/fixtures/nikto/
and .pre-commit-config.yaml. Missing hooks/real inputs prevent complete acceptance,
not this bounded code-regression result.

## CLAIMS-23 — Snapshot scores must correspond to their retained evidence

Date: 2026-10-18. Serves PROJECT.md stage 7 and research reproducibility. A valid
snapshot hash and typed records did not establish cross-record correspondence:
a score could select an unknown or another finding's CVE, contradict its selected
enrichment's KEV/EPSS/vector, or carry context inputs different from the retained
host profile. An explicit match could name a CVE absent from its scanner finding.
The corrected new synthetic regression command returned `23 failed, 1 passed in
6.78s`, including CLI success where rejection was expected and SQL-row exports
that accepted contradictory inputs. The first test attempt had an exposure
mutation that made no change and the wrong CLI option spelling; those five setup
errors were corrected before counting the reproduced boundary failures.

Require selected CVEs to resolve inside their own finding's enrichment set;
explicit matches must remain scanner-named, while range matches need not be.
Compare supplied KEV/EPSS/version-vector declarations with that selected record.
Compare retained role, exposure, manual and observed-controls inputs with the host
profile when supplied. Do not equate true with numeric 1; valid integer/float
confidence representations remain compatible. Per-finding applied controls are
not blindly equated with all observed controls. Missing legacy input metadata
stays missing, not fabricated. Do not recompute or overwrite scores, change the
fixed formula, authenticate capture origin, or claim mathematical correctness
from these relational checks. No public field/signature/schema/table change.

Rejected: silently replacing scores with current values, resolving CVEs from a
different host/finding, allowing contradictory typed values merely because both
hashes were recomputed, or claiming a complete arithmetic replay without its
historical policy inputs. Parent first snapshot/core integration passed 173
cases. The resource-limit/snapshot/boundary subset later passed 87 cases.

The expanded report/context integration returned `28 failed, 839 passed in
148.32s`: its context-attachment fixture changed profiles while retaining old
bound score inputs. Those tests intentionally exercise context provenance,
including model/llm-labelled profiles that cannot enter canonical ranking.
Use the existing supported legacy-unbound score shape in that fixture, retaining
its nonempty queue, every numeric/identity field and all existing assertions.
Add fixture assertions that only input binding was omitted. Current fully bound
score/context rejection and non-mutation have separate new regressions; this
does not waive either production guard or authorise model-derived scoring.
Full integration and the complete gate remain pending.

## CLAIMS-24 — JSON resource limits apply to actual bytes and overflow values

Date: 2026-10-18. Serves stage 7 and cross-cutting reproducibility. The shared
reader statted a path but then read all bytes. Growth/replacement between those
steps bypassed its stated byte cap. JSON float overflow (1e1000) also bypassed
the NaN/Infinity token hook and could survive in uninterpreted metadata.
The disjoint coding agent reproduced `12 failed, 25 passed in 2.65s`, then its
37-case synthetic suite passed in 8.09s after correction. Parent reviewed both
changed files and closed the agent; report validators below the shared helpers
were outside its write scope and unchanged by it.

Retain the early stat rejection, open the local file once, read at most cap+1
bytes and reject excess actual bytes before decoding. Reject nonfinite floats
during the existing structure traversal, including nested arrays and unknown
metadata. Finite unknown metadata and valid UTF-8/BOM input remain intact.
The raw-byte bound is not a total heap/time bound: depth/node checks still happen
after decoding, and concurrent in-place writes are not made atomic. Literal UNC
path refusal remains; this is not OS-wide filesystem/network containment.

The agent's consumer run returned one failure/124 passes because an existing
test mocked the obsolete Path.read_bytes seam. Parent changed only that mock to
Path.open, preserving its rejection assertions; new tests also cover stream-read
errors and descriptor closure. No dependencies, network calls, installs, scanners,
models, credentials, commits or pushes were used by this increment. No new
Markdown file was created. Complete-tree verification is still pending.

CLAIMS-23/24 integrated follow-up: the resource/snapshot/boundary subset passed
87 cases in 12.11s; the repaired context-attachment plus complete-input score
suite passed `113 passed in 88.11s`. A read-only rg search for
`assessment_snapshot|load_json_payload` selected 32 existing/new Python test
modules; running them with the installed Python `-B -m pytest`, `-q
-p no:hypothesispytest --tb=short` returned `1251 passed in 303.02s (0:05:03)`,
zero failures/skips. This is an explicitly selected consumer run, not the whole
project suite. Ruff lint/format passed (281 files already formatted), and the
direct guarded full Pyright invocation returned zero errors/warnings/info.
No ordinary Python Pyright wrapper, network, real integration or remote CI was
invoked. All agents were closed before the next complete-tree freeze/gate.

CLAIMS-23/24 complete verification, 2026-10-18: installed Python 3.12.10 ran
`-u -B scripts/check.py` from the authoritative repository with temporary
PYTEST_ADDOPTS appending `-p no:hypothesispytest -q --durations=8 --tb=short`,
restored afterward. Terminal output:

```text
PASS    ruff lint
281 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 11256     61    99%
Required test coverage of 95% reached. Total coverage: 99.46%
3746 passed, 520 subtests passed in 793.29s (0:13:13)
PASS    pytest + coverage
GATE PASSED
```

Zero failures/skips. The optional workstation Hypothesis plugin was disabled,
not project tests; the socket guard and 95% floor remained active. No ordinary
Python Pyright wrapper was invoked. Before documentation edits, both aggregates
matched: 290 scoped inputs
31625804d02ae684b5632b7ec82a38c03006cabe296a88bfaa1e86cc95708692;
399 tracked/nonignored working inputs
2c2d7e8143b19a67c31a60f2886ed30561ec10e7a87ae0e3fdebe67ba5049baa.
Only existing documentation changes afterward and is checked separately; no
source/test/configuration/script code changes after this passing checkpoint.
Relative to CLAIMS-22: 67 added cases (30 score binding, 37 resource limits),
54 added statements, two more missed statements and coverage down 0.01 points
from 99.47% to 99.46%. Read-only coverage output lists 16 missed snapshot and
22 missed audit statements. This is not complete branch verification, arithmetic
replay, authenticated history or empirical effectiveness.

VERIFIED missing-prerequisite probe: installed Python `-B -c` using only
`importlib.util.find_spec('pre_commit')` returned `pre_commit module present:
False`; .pre-commit-config.yaml is also absent. No installation/hook execution
was attempted. MISSING completed human-captured Nikto JSON/provenance under
tests/fixtures/nikto/. These are genuine remaining acceptance gaps, not a reason
to invent provisioned tools or real evidence. The broader goal remains active;
no actual scanners/providers/models, remote CI, commits or pushes were run.

## CLAIMS-25 — Reproduce retained score arithmetic without rewriting it

Date: 2026-10-18. Serves PROJECT.md stage 7 and cross-cutting deterministic ranking
and research reproducibility. Structural/link consistency did not detect wrong
risk, band, base/environmental numbers, multipliers, modifications or effective
controls. A risk could be changed along with its band and still pass the hash
verification CLI. New synthetic tests returned 21 failures: 15 accepted-invalid
or export/CLI regressions plus six expectations for the not-yet-built private
diagnostic helper. Do not count missing-helper tests as independent product bugs.

Reuse the existing pure cvss31 and scoring implementations; do not change their
formula, tune weights, introduce a scorer dependency or treat replay as independent
CVSS conformance. Check retained v3.1 vector/number consistency and, when the
retained weights hash matches, risk/band consistency. Full current-policy replay
requires the retained policy, weights, finding/enrichments, profile and service
observations. Compare official numeric fields and semantic control decisions;
unknown input annotations and harmless explanation wording remain untouched.
Vector ordering may differ without changing meaning. Reject contradictions with
a finding-specific ConfigError; never update a stored score or partially publish
a replacement report.

Historical weights/policies, missing retained fields and unsupported CVSS 4.0
arithmetic remain explicitly unreplayed. Do not infer them from current global
configuration. Supplied contradictions still fail even when another field is
missing. Missing legacy metadata cannot waive declared metric-value types.
No new public field/signature/schema/table/CLI shape is introduced: the arithmetic
summary is a private helper, and official identifiers, raw evidence and numbers
are preserved. Hash matching identifies supplied content; it does not establish
approved weights, genuine capture origin or real-world risk accuracy.

Rejected: a second handwritten formula, filling historical unknowns with current
defaults, mutating old priorities into matching values, guessing v4 results from
v3 data, and declaring a repeat of the same code an independent standards audit.
The parent's first core/snapshot integration passed 203 cases. Its final dedicated
arithmetic suite passed 34 cases, covering invalid numerical data, legacy unknowns,
partial-metadata omission, equivalent vector order, narrative freedom, v4 refusal,
CLI fail-closed output, encoded-input and SQL-state preservation. One import-order
lint issue was mechanically sorted; diagnostics were not suppressed.

## CLAIMS-26 — Report arithmetic status is separate from capture evidence status

Date: 2026-10-18. Serves stage 7. A content hash or fully executed test gate must
not imply that all numerical priorities were reproduced. Add a score-arithmetic
component using only the existing report-row schema. Full nonempty replay is
VERIFIED with an explicit current-implementation/reproduction-only caveat.
Partial, unavailable, unsupported, empty and no-snapshot cases stay NOT RUN,
show counts and retain their limitations. Do not promote the assessment's capture
evidence status. Use the exact loaded snapshot after the existing live-state
correspondence check, not a later sequence of independent store reads.

The disjoint coding agent changed only collect_report_audit and one new synthetic
report test file. Its initial row tests returned 11 failures/three passes; the
expanded final suite passed 24 cases, including actual helper/HTML/CLI/SQL-state
integration. Parent reviewed the code/tests and closed the agent. Isolated mock
tests now require the real helper to exist; they no longer install a placeholder
attribute. Existing HTML and frozen bytes survive rejected arithmetic. Untrusted
limitation text is escaped. No report root field or existing status was replaced.

Parent arithmetic/report integration returned `58 passed in 11.61s`. Full guarded
Pyright returned zero errors/warnings/info; Ruff lint/format passed (283 Python
files already formatted). A broader consumer run and the complete frozen-tree
gate remain pending. No scanners, feeds, providers, models, credentials, network,
installs, commits or pushes were invoked. No new Markdown file was created.

CLAIMS-25/26 consumer integration follow-up: the 34 Python modules selected by
the existing rg snapshot/JSON-reader search returned `1309 passed in 303.26s
(0:05:03)`, zero failures/skips. The final arithmetic/report pair returned
`58 passed in 11.61s`. Full direct guarded Pyright returned zero errors/warnings/
info and full Ruff lint/format passed (283 files already formatted). No old
assertion was weakened, skipped or removed. All agents are closed. The next check
is the complete frozen-tree lint/type/test/coverage gate; current local source
presence or selected tests do not establish that result in advance.

CLAIMS-25/26 complete verification, 2026-10-18: installed Python 3.12.10 ran
`-u -B scripts/check.py` from the authoritative repository, with temporary
PYTEST_ADDOPTS appending `-p no:hypothesispytest -q --durations=8 --tb=short`
and restored afterward. Terminal output:

```text
PASS    ruff lint
283 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 11364     65    99%
Required test coverage of 95% reached. Total coverage: 99.43%
3804 passed, 520 subtests passed in 734.97s (0:12:14)
PASS    pytest + coverage
GATE PASSED
```

Zero failures/skips, no project exclusions, and no lowered floor/socket guard.
Only the optional workstation Hypothesis plugin was disabled. The direct guarded
Pyright launcher was used, not the Python wrapper. Both pre/post aggregates matched
before result edits: 292 scoped inputs
29ee4fcd7bacb71cd6c9447628f5fc452565661955f53701f4372c9a5f98d360;
401 tracked/nonignored working inputs
8d671a882a8b387fecf8e7a594d86cc2c231480e382dc9610a8f3a144c590ee6.
Only existing documentation changes afterward and is separately checked; no
source/test/script/configuration code changes after the pass. Relative to CLAIMS-24:
58 added cases (34 arithmetic/24 report), 108 added source statements, four more
missed statements and coverage down 0.03 points from 99.46% to 99.43%. The read-only
coverage report lists 20 missed snapshot and 22 missed audit statements. Neither
complete branch verification nor independent arithmetic conformance is claimed.

The missing hook runner was rechecked without launching it: `Get-Command
pre-commit` found no PATH command; selected Python `find_spec('pre_commit')` was
False. MISSING .pre-commit-config.yaml, the approved pre_commit runtime and completed
human-captured Nikto JSON/provenance under tests/fixtures/nikto/. Independent
empirical/conformance validation is NOT RUN; historical input/policy reconstruction
and v4 arithmetic remain unverified. These do not invalidate this bounded regression
result, but they prevent full project/research acceptance. The broader goal stays
active. No real scanners/providers/models, network, installs, remote CI, commits
or pushes were run by this increment.

## CLAIMS-27 — Validate canonical inputs before assigning a priority

Date: 2026-10-19. Serves PROJECT.md's cross-cutting deterministic ranking and
reproducibility component and stage 7. Snapshot replay was not sufficient: direct
scoring could still accept an undeclared role/exposure, truthy nonboolean control,
coerced manual criticality or foreign context/enrichment ownership before export.
Reject these inputs at the pure scoring boundary with ConfigError. Check declared
feature containers, values, confidence, evidence and rule/manual sources; require
profile/finding host agreement and enrichment/finding ID agreement. Check numeric
enrichment inputs and any provided v3.1 base against its vector before worst-match
selection. Reject mixed-owner selection. Batch scoring validates even empty
batches and does not discard malformed candidates as merely unsupported severity.
No scope, schema, signature, table, numerical formula or weight was changed.

Risk primitives reject non-finite numbers, booleans masquerading as numbers,
numeric strings and out-of-range severity inputs. KEV/exposure flags require
actual booleans. Band classification rejects non-finite/non-numeric inputs rather
than labelling NaN Low. Finite out-of-range helper band mapping and the historical
low-level no-basis math remain compatible; canonical score still requires a
severity basis and does not assign unsupported findings a fabricated zero/Low.
This is typed-input validation, not evidence authentication or a complete proof
that every possible in-memory Finding/Service/configuration is valid. Settings
validation remains the prerequisite for the weight configuration.

Conflict / resolution / why: the pre-existing environmental helper test safely
ignored malformed optional criticality. Preserve that assertion and safe helper
behaviour, remove numeric-string/fraction/boolean coercion and bound valid
criticality to integer 1-5; official score rejects malformed criticality entirely.
One prior cross-host control test deliberately passed another host's profile into
score. It now additionally requires score rejection, while retaining the same
no-MAC-credit and foreign-control reason checks directly against the pure
eligibility/environmental helpers. Several other scoring fixtures used unrelated
default enrichment IDs; bind them to their real synthetic finding IDs. The
two-machine comparison now uses a finding on each machine and binds the identical
intelligence to that finding. Original numerical, missing-severity, control and
immutability assertions remain. No skip, xfail, lowered floor or diagnostic ignore.

Rejected: catching errors only during export, truthiness/int coercion, replacing
bad context with unknown, silently dropping candidates, mutating stored scores,
loosening the new owner guard to accommodate invalid test setup, or changing the
formula. Those would preserve the false completion claim instead of fixing it.
The initial direct-boundary red run showed failures and was interrupted when its
extreme criticality case reached the old unbounded loop; no complete red-run count
is claimed. The new bounded rejection test completes. The first broader caller
check returned 20 failures/620 passes/409 subtests: invalid test relationships and
an export diagnostic that lost its stage label. These failures remain recorded.
Follow-up control/snapshot/missing-severity integration passed 188 cases.

## CLAIMS-28 — Controlled stored-profile errors and rejected-rank immutability

Date: 2026-10-19. Serves the same ranking/report boundary. A worker was dispatched
for disjoint Store/CLI integration but terminated with a usage-limit error and was
closed; no worker implementation or independent approval is claimed. Parent
reproduced 12 failing stored-input cases (six others passed), then implemented the
fix. Store.profile and Store.profiles now validate JSON/container shapes and the
payload host against the SQLite row owner before decoding Features. Expected
decoding failures become a ConfigError naming context_profiles, run and host,
not a traceback. No recovery defaults, dropped rows, writes or migration.
Snapshot construction retains its assessment-snapshot diagnostic context around
upstream ConfigError too; the pre-existing export assertion remains unchanged.

New synthetic tests exercise malformed profile JSON/shapes, wrong ownership,
CLI exit 2 with empty stdout/no traceback, and a later invalid profile after other
findings have already been computed. The existing compute-before-persist design
needed no pipeline change: rejection preserves the entire SQL dump and the
six-score queue byte-for-byte. Valid repeated rank JSON remains identical.
Direct/Store boundary integration returned `155 passed in 24.28s`. Full Ruff
lint/format passed (285 files); direct guarded Pyright returned zero errors,
warnings and information. These are local synthetic/mocked checks, not real
scanner/feed/model verification. The complete frozen-tree gate is pending.

No dependency changes, real scanners/providers/models, publisher/credential
operations, network calls, installs, remote CI, commits or pushes were used by
these tests; inputs were synthetic/mocked. No new Markdown file was made.
MISSING: .pre-commit-config.yaml, approved pre_commit runtime and completed
human-captured Nikto JSON/provenance under tests/fixtures/nikto/. Independent
empirical/standards validation and historical-policy identity remain NOT RUN.

CLAIMS-27 follow-up before final verification: a separate read-only synthetic
diagnostic reproduced another direct scoring gap: the raw finding named only
CVE-1999-9001, but an explicit enrichment selecting CVE-1999-9002 received risk
98.0. The first full-gate attempt was deliberately interrupted (not passed)
before changing code. Two new tests failed and one legitimate CPE-match test
passed. Canonical scoring now requires explicit CVEs to belong to the finding's
own canonical CVE tuple; valid cpe_range matches need not be named by a scanner.
Malformed identifier containers cannot satisfy membership via substring or keys.
No CVE, source evidence or match method is rewritten. A later caller check found
three remediation fixtures using explicit enrichment with an unnamed CVE; name
that CVE in the fixture and retain the before/after numerical equality assertion.
All tests were rerun after this correction; that result follows separately.

CLAIMS-28 follow-up: a stored quote-type matrix exposed eight additional decoding
failures (12 other cases already passed): truthy booleans/integers reached
Feature.evidence.strip before a controlled exception. The second in-flight gate
was interrupted, not passed. Profile decoding now validates nonblank string
quotes across role, exposure, controls and manual features before constructing
them. No stringification, truncation or evidence replacement. All 20 quote cases
also assert empty CLI stdout, exit 2 and unchanged SQL dump. The final pure-input,
Store/CLI and remediation integration returned `198 passed in 60.68s (0:01:00)`;
full Ruff lint/format (285 files) and guarded Pyright passed again. A new full gate
will be tied to fresh before/after fingerprints; the interrupted gates are not
evidence of a complete pass.

CLAIMS-27/28 final verification, 2026-10-19: selected Python 3.12.10 ran
`-u -B scripts/check.py` with temporary PYTEST_ADDOPTS appending
`-p no:hypothesispytest -q --durations=8 --tb=short`, restored afterward.

```text
PASS    ruff lint
285 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 11502     66    99%
Required test coverage of 95% reached. Total coverage: 99.43%
3986 passed, 520 subtests passed in 893.17s (0:14:53)
PASS    pytest + coverage
GATE PASSED
```

Zero failures/skips; no project tests excluded or floor/socket guard reduced.
Direct guarded Pyright bypassed the updater wrapper. The 182 added cases are
144 direct-scoring/38 Store-CLI cases. Relative to CLAIMS-26: 138 added source
statements, one added miss, identical rounded coverage; not a percentage
improvement or complete branch verification. The canonical scorer's 284
statements were covered. Both aggregates matched before result edits:
294 scoped inputs, 1b9a94bbf7ff31b5b096daed9581098355381c6293b05d010b7b7018e67085db;
403 tracked/nonignored inputs, 831f6ecf7d97d4b16eec16f5836a16f40550900dfc88618166821375fbd6ed34.
Only existing documentation changes afterward, checked separately. No code,
test, script or configuration changed after the pass. One read-only synthetic
fixture-order check confirmed the invalid host's finding is third, after two
valid computations, so the rejected-rank case reaches beyond the first finding.

The user additionally requested actual product startup. The normal CLI was
launched on loopback port 8765 against existing data/vulnassess.db and the saved
scanme-2026-09-24 run. Only the child process's PostgreSQL override was removed;
no credential value was exposed or changed. Startup printed
`VulnAssess: http://127.0.0.1:8765/`. An actual browser opened the overview,
stage list and canvas; two services/zero findings and context/coverage limits
were visible. Browser error logs returned `[]`. No scanner, model or publisher
request was made, and stored data/fixture-only intelligence was not presented as
a new live assessment. A generated screenshot stays in ignored data/; the local
server/tab remain available to the user. This loopback startup/read check was
explicitly user-requested, not permission for external network calls.

STATUS: locally verified increment, broader goal active. BRANCH / COMMIT:
codex/coverage-95, baseline 6f523f6 plus existing/new uncommitted work. BUILT /
CHANGED: scoring/store guards, snapshot error wrapping, synthetic regressions,
fixture relationships and existing reference updates. DECIDED / DECISIONS:
CLAIMS-27/28 enforce declared inputs and ownership without changing numerical
policy or rewriting evidence. EVIDENCE: executed gate and local browser;
boundary cases TESTED WITH MOCKS/synthetic inputs. MISSING remains real Nikto
JSON/provenance, .pre-commit-config.yaml and approved pre_commit runtime.
DEFERRED / NEXT: semantic explanation fidelity, historical-policy identity and
independent integration/standards/empirical validation. No commits/pushes.

## CLAIMS-29 — Bounded rationale rewrites and faithful threat wording

Date: 2026-10-19. Serves PROJECT.md stages 5/7 and explanation/reproducibility,
not new model authority. Reproduction: the original dedicated suite returned
31 failures/nine passes. A real evidence ID, reachable quote and no invented
number still allowed unsupported current compromise, control absence, wrong
role/exposure/band, probability/percentile confusion and irrelevant citations.
Two truthy non-string responses also escaped as attribute errors. These are
synthetic/mocked reproductions, not evidence about any real model's accuracy.

Choose a bounded, typed fact-slot rewrite check rather than a blacklist-only
claim of general semantic verification. A sentence must fit supported priority,
subject/fact or inferred-context forms, using complete supplied fact phrases.
Do not treat source-title words as a vocabulary authorising new conclusions;
the whole title can only appear as a quoted recorded finding. Preserve control
scope/uncertainty, distinguish CVE-catalogue listing from asset compromise,
and reject unsupported relationships, negation, actions, identifiers and content.
The remaining syntax is not an arbitrary bag of permitted words. Format/length
failures return before grammar processing. Reserved markers cannot be supplied
by a model. URLs are rejected case-insensitively without rejecting the literal
word http in a reported title. Valid paraphrases within the bounded forms remain
usable; otherwise deterministic fallback is marked Needs review. No finding is
removed and no canonical number is affected.

Each generated rewrite remains inferred, and every factual slot used must cite
its complete server-issued fact block, not just a generic label such as verdict:.
Accepted validation metadata retains the wording-policy version, facts used
and a detached copy of checked claim IDs/quotes. This uses the existing open
Rationale.validation mapping; root fields, signatures, enums, tables, command
shapes and configuration schemas are unchanged. A marker is provenance metadata,
not a signature or authentication of historical state. The existing audit still
records every call's model/prompt/input/output hashes, decision and outcome.
The existing structured caller's bounded allowance changes from 300 tokens to
600 and context from 2048 to 4096 for the additional full-block citations;
no real model was run and practical output/latency success is NOT RUN.

The shared pure score-fact description now says matched CVE listed in a retained
CISA KEV snapshot, not that this host is actively exploited. EPSS is described
as relative percentile rank with explicit integer rounding, not an absolute
probability or low likelihood. Missing retained intelligence remains explicit.
The scorer's default legacy control description no longer asserts behind a WAF
as a proven mitigation. Only newly generated wording changes; existing raw
evidence, scores and historical reasons are not rewritten. Historical rationale
text has not been retrospectively approved by this new policy. Shared wording
does not authenticate the inputs or establish the accuracy of context inference.

Conflict / resolution / why: old positive tests explicitly accepted right-now
exploitation/no protection with no supporting facts. Replace those positive
strings with faithful ones and keep their acceptance, attribution, storage and
numeric-immutability assertions. The partial-facts format test now only restates
its actual band/exposure. The fake client now cites complete supplied fact blocks;
new tests deliberately remove or truncate individual quotes to ensure rejection.
The former low-percentile test now requires relative-ranking wording and rejects
likelihood language. No assertion was weakened, no skip/xfail added, no floor
lowered. Bounded source-only rewrite checks are preferable to silently accepting
unsupported prose or claiming an unavailable general entailment oracle.

Dedicated final suite: `84 passed in 0.44s`. Broader pre-final consumer check:
`272 passed, 424 subtests passed in 17.20s`; that preceded the detached-proof
regression. Full Ruff lint/format and guarded Pyright passed before the last
proof-metadata edit; the complete final gate follows. No dependencies, real
models/scanners, publisher/credential operations, network calls, installs,
commits or pushes. No new Markdown file. Real-model utility/false rejection,
historical narrative validation and context-truth authentication remain separate
work, not declared finished. MISSING still includes real Nikto capture/provenance,
.pre-commit-config.yaml and the approved pre_commit runtime.

CLAIMS-29 compatibility follow-up: the first complete-gate attempt reported a
failure and was interrupted, not passed. A bounded diagnostic returned one
failure/10 passes and identified the old legacy-description assertion requiring
behind synthetic-filter. Keep its original purpose (recorded control must remain
visible), require recorded signal plus applicability/mitigation unverified,
add a no-behind assertion and prove the original score JSON is unchanged. Bind
the provided profile to the score's actual host. This resolves the old wording
conflict instead of restoring a stronger unsupported claim or deleting a test.
No other source/algorithm change was required by this failure. A fresh full gate
follows; the interrupted run's partial checks are not used as acceptance.

The actual structured rationale request also lacked I2's exact untrusted data
follows prefix, although the old build_prompt test checked it. A new test
capturing FakeModel.prompts failed on that missing prefix, then the live-call
builder was corrected before the envelopes. The test checks all seven trust
envelopes and warning-before-data ordering on the actual structured call. No
real model or network was invoked. This is not presented as prompt-injection
effectiveness measured on a real model.

Final pre-gate integration returned `258 passed, 424 subtests passed in 8.11s`,
including all 85 dedicated fidelity cases and the corrected legacy-control
assertion. These tests precede a fresh complete frozen-tree gate, not a claim
that the interrupted run passed. The new prefix is part of the hashed user
prompt; neither audit schemas nor canonical numerical inputs were changed.

CLAIMS-29 final verification, 2026-10-19: `python -u -B scripts/check.py`
completed with `4071 passed, 520 subtests passed in 564.94s (0:09:24)`,
`Total coverage: 99.42%`, and `GATE PASSED`. Ruff lint and format passed;
guarded offline Pyright returned zero diagnostics. Pre/post scoped source
fingerprints matched at 295 files / SHA-256
`15b796c6cf839a98780c5252c45f8a0f74bd00cc6906f5172b75cb8e36a8cbaa`;
the complete 404-file working-input fingerprint also matched at
`be62b527cce0beddfb2a302793991e545d7bff284c0a72f5c99b5a53ae57085a`.
This verifies that increment's offline checks, not real model utility or an
end-to-end scanner run. A separate diagnostic still shows explanation facts can
use a later context profile instead of the score's retained context; that binding
issue remains open and this gate does not establish authenticated context truth.

### CLAIMS-30 — 2026-10-19: separate simulated/live overlays from stored records

Serves PROJECT stages 2, 4 and 7: execution-state provenance and truthful reporting
on `codex/coverage-95`. The user challenged the static product experience. Browser
inspection showed SIMULATED PREVIEW / NO SCAN OR MODEL CALL. Clicking Refresh
changed the header to STORED ASSESSMENT but kept simulated node completions and
the simulated execution rail. That is a reproduced presentation/integration bug,
not a model failure. Source tracing additionally confirmed separate live capture,
SQL assessment and printable-report paths; repairing presentation does not join
those lifecycles or establish production readiness.

Choose explicit display-state reset before loading stored records: invalidate a
sleeping preview, remove prior live result/error overlays, clear the inspector,
and render a loading or unavailable source label. Refuse refresh during an actual
live scan or stored-analysis batch instead of disrupting it. Retained raw evidence,
stored records, canonical scores and the prior stage object are not modified.
Rejected alternative: update only the badge or mark missing modules complete;
both conceal which source is actually being displayed. No scope, fixed interface,
scoring policy, credentials, dependencies, scanner launches or publisher/model calls
are changed. The computer-use skill is used only for local browser verification.

Eight synthetic regressions exercising the actual JavaScript loader failed before
the repair (`8 failed in 0.85s`). Afterwards, source-switch and existing unscored-UI
regressions returned `14 passed in 1.19s`. These use a fake DOM and local Node,
not real scanner/provider proof. Browser reload, Preview flow, then Refresh
confirmed STORED ASSESSMENT, Scanner evidence stored, Context stored, and Stored
records / no pipeline execution, with no simulated execution rail. This correction
is deliberately not reported as completion of the full assessment product. A fresh
gate follows. Automatic orchestration/AI policy expansion and fixed persistence
contract changes still require the specified human review; do not invent approval.

CLAIMS-30 final gate: `python -u -B scripts/check.py` returned Ruff lint PASS,
Ruff format PASS (287 files), guarded offline Pyright zero diagnostics, and
`4079 passed, 520 subtests passed in 757.82s (0:12:37)` with zero failures/skips,
`Total coverage: 99.42%`, `GATE PASSED`, exit 0. Python measured statements remain
11,579 / 67 misses; the eight added JavaScript-loader regressions do not make
this a JavaScript coverage claim. Pre/post scoped 296-file SHA-256 matched at
`76476de37d28341063806c86b82fd5bb5989098efe18c4af658b62d6ca0be296`;
complete 405-file working-input SHA-256 matched at
`5713b9b251333da9dc5fdff7377fc17d713ed6d01fe284b24cc13eb35424f850`.
Subsequent edits update only these existing documentation checkpoints.

Real saved-data diagnostic, not a test fake: `load_saved_cve_case` on the retained
Redis target raised `Multiple saved captures have unknown chronology; recorded
capture time is required`. Browser `/captures` returned `No saved review checkpoints
yet`. Explicit read-only inspection of `assessment-40tb2mgg` matched retained file
hashes and current `score_available` returned one CVE-2022-0543 priority at 100 /
Critical, with four services and an absent capture timestamp. This establishes
only historical component recomputation, not automatic replay success, independent
capture authenticity, fresh publisher data, new scanner execution or model output.
Do not manufacture timestamps or silently pick one ambiguous legacy capture.
Legacy selection/history access and unified capture/SQL/report lifecycle remain
open integration work. Browser proof is retained in ignored data/workflow-source-switch-2026-10-19.jpg.
No new Markdown file, install, scope edit, credential operation, external call,
commit or push was performed. The active unfinished-claims audit is not complete.

### CLAIMS-31 — 2026-10-19: bind rationale facts to retained score context

Serves PROJECT stages 5/7 and deterministic-risk traceability on codex/coverage-95.
The preceding audit lead was reproduced: a score for an internet-facing database
could receive a validated model sentence describing an internal workstation after
the supplied current asset profile changed. Twenty-seven new synthetic assertions
failed before the repair. Choose the score's retained role/exposure/controls/manual
features as explanation inputs, validating their shapes, sources, finite values,
finding/host ownership and required current control decisions. Reject absent or
malformed retained context before any provider call; publish a Needs review notice,
not unbound historical prose. Legacy control-policy decisions cannot be promoted
into current affected-endpoint eligibility. Keep the facts' retained-input basis
and the input hash in existing open validation/audit mappings. No model, schema,
public signature, score formula, weights, canonical value or evidence is changed.

Rejected alternatives: borrow the newest profile, or silently recompute the score
while explaining. The former lies about the original calculation; the latter
mutates history and confounds the research comparison. Raw-source authenticity,
context accuracy, and general historical-prose verification remain separate claims.
Actual read-only inspection of assessment-40tb2mgg now returns database /
internet-facing explanation facts even when deliberately supplied diagnostic
later metadata says workstation / internal; the stored score JSON is unchanged.
No scanner, publisher or model was contacted by that diagnostic.

Two more red tests reproduced silent partial success in explain_run: an orphan
later score was skipped after earlier rationale work. The implementation now
checks every finding/profile association before any provider call or write. The
old no-fabricated-orphan test keeps that assertion and is strengthened to require
an actionable ConfigError plus identical database contents, instead of empty-success
counts. No assertion is deleted, skipped, weakened or coverage floor reduced.
The new correspondence suite has 39 cases; focused explanation/control consumers
passed 185 cases/15 subtests. A later combined selection passed 203 cases. Those
are pre-final offline checks, not the complete gate or real-model acceptance.

The new test file now redirects fake-model audits into isolated synthetic test
paths. Its initial red run used the existing default audit path for some fake-model
responses; those ignored hash-only fake-model audit records were not removed or
represented as real provider executions. Subsequent tests use isolated paths.

### CLAIMS-32 — 2026-10-19: read-only access to unreceipted legacy captures

Serves PROJECT stages 4/7: evidence recovery and truthful assessment reporting.
The main page remains at /; workflow and history remain separate entry points.
A permitted parallel read-only audit confirmed five locally consistent legacy
captures missing new review receipts. The worker reached its usage limit after
partially editing capture_history.py; the main agent reviewed those changes,
completed routing/rendering/tests and owns final integration. No independent
completed code review is claimed.

Choose private HTML listing/detail helpers behind the existing /captures routes.
Keep public listing/load signatures and /api/captures schema-v1 receipt behavior
unchanged. The old files are individually inspectable, not retroactively certified:
unknown chronology, collection status and AI status stay unknown; no receipt,
configuration, publisher refresh or approval is fabricated. The HTML detail checks
bounded manifest-listed bytes, confined names, hashes, present collection types and
host/finding links, then escapes all displayed historical values. Retained scores
are labelled not revalidated. A present receipt, including an orphan final or
dangling symlink, must take the strict reader and cannot fall back to legacy mode.

This preserves docs/live-capture-recovery.md's verified JSON contract without an
interface expansion. Rejected alternatives: return legacy data as schema-v1 JSON,
select an undated capture by filesystem timestamps, backfill a review receipt, or
automatically import it into SQL. Explicit replay selection and a unified durable
capture/SQL/report lifecycle still require their own reviewed implementation.

The read-only audit also reproduced schema_version=True/1.0 being treated as 1 and
malformed present payload collections escaping controlled handling. Receipt schema
versions now require actual int 1; present collections are shape-checked. A new
deep-JSON test reproduced an uncaught RecursionError; JSON/read-comparison errors
now fail closed as review errors. Historical absent fields remain absent.
The new legacy suite has 34 synthetic cases, including restart reads, two ambiguous
undated captures, strict API preservation, receipt fallback denial, ownership,
symlinks/traversal, escaping, file/count/aggregate budgets and controlled corruption.
Its initial routing check returned three failures/18 passes; it now participates
in the 203-pass combined selection. The aggregate-byte test uses explicitly mocked
small buffers, not an actual oversized capture or a scanner result.

VERIFIED actual local processing: all five existing captures rendered through
the new HTML reader; before/after hashes of the raw files matched. The receipt-only
API listing still contains zero records. After restarting the owned loopback server,
browser navigation showed all five legacy entries and opened the retained Redis
CVE-2022-0543 record with its original 100 / Critical value labelled not revalidated.
The existing main page was also opened and retained; no scanner, publisher or AI
call was made. Full gate verification follows after freezing the combined tree.
No new Markdown file, dependency, scope/credential change, commit or push.
MISSING remains real Nikto capture/provenance, .pre-commit-config.yaml and approved
pre_commit runtime. These repairs do not establish overall project completion.

### UI-RESTORE-01 — 2026-10-19: preserve the original scroll-driven planet journey

Serves PROJECT stage 7: preserve the explanatory project presentation. The human
redirected work specifically to restoring the existing top-to-bottom effect, not
redesigning the page. No markup, CSS, page copy, assessment data, score or scope
was changed in this increment. The prior broader goal remains unfinished.

VERIFIED browser observation: at desktop width the journey was hidden and had no
transform despite motion being enabled; reloading activated the existing effect.
The initializer returned permanently when first loaded below its 900px breakpoint.
Choose re-evaluation on resize, media-query changes and project/workbench routing,
preserving the original position/size/crossfade formula. Reject removing reduced
motion support or replacing the effect with a new layout. Disabling motion or
entering the workbench clears the hero/globe handoff properties instead of leaving
the globe hidden. No dependency or fixed interface changes.

TESTED WITH MOCKS: after correcting two new harness errors (duplicate variable name
and Windows newline extraction), the old implementation failed seven recovery
cases and passed two original desktop/scroll cases. After the implementation change,
`python -B -m pytest -p no:hypothesispytest
tests/synthetic/test_synthetic_planet_journey.py tests/test_ui.py -q --tb=short`
reported `101 passed, 72 subtests passed in 12.31s`. These are synthetic DOM and
offline UI tests, not scanner/model acceptance. `node --check
vulnassess/ui/static/app.js` succeeded. Actual loopback browser scrolling changed
the planet transform from `translate(-997.8px, 413.4px)` at scroll 0 to
`translate(-893.4px, 350.6px)` at scroll 491.36; a screenshot of the visible
transition is retained under ignored data/planet-scroll-restored-2026-10-19.jpg.
A temporary viewport override did not change the observed IAB viewport; it was
reset. Responsive recovery is therefore unit-tested, not claimed browser-verified.

VERIFIED gate attempt: `python -u -B scripts/check.py`, with invocation-local
PYTEST_ADDOPTS `-p no:hypothesispytest -q --maxfail=1 --tb=short`, reported Ruff lint
PASS, format PASS (290 files), guarded Pyright `0 errors, 0 warnings, 0 informations`,
then `1 failed, 368 passed, 15 subtests passed in 41.21s` and `GATE FAILED:
pytest + coverage`. The pre-existing in-progress capture-history change rejects
the chronology fixture's missing finding ID in
test_hash_bound_receipt_time_survives_a_copy. This is the same failure reproduced
before the UI request; it is not caused by the planet script. No successful current
whole-package coverage result or project completion is claimed. The earlier combined
CLAIMS-31/32 gate was interrupted after failures; their final gate remains pending.
Deferred: repair that fixture/validation compatibility under the broader task,
then run the full unfailfast gate. No unrelated repair was folded into this
explicitly narrow UI request, and no commit/push was made.

### CLAIMS-33 — 2026-10-19: establish real-data inputs without inventing model accuracy

Serves PROJECT stages 4/5/7 and cross-cutting evaluation. The human requested
establishing external-data and personal-device behavior, noting that provider keys
had already been supplied. Credentials alone neither establish runtime success nor
override the current local-only/deferred-model policy. An explicit asynchronous
choice requests approval for an existing local model test or a one-off Groq test
using only retained lab evidence and redacted protection states. No model call,
cloud disclosure, scan, publisher refresh or download has been made while awaiting
that choice. Do not claim independent accuracy from a successful provider response.

VERIFIED fresh local collection: `python -B -c "import json; from
vulnassess.self_defence import collect; print(json.dumps(collect()))"` completed
at 2026-10-19T06:50:42Z. The nine checks observed Defender and Domain/Private/Public
firewalls enabled, Remote Desktop and SMB1 disabled, an update restart pending,
and Secure Boot/encryption unknown. The active profile was Private; 25 listener
records and the latest recorded hotfix date 2026-10-14 were returned. This is a
read-only configuration observation, not malware detection or patch completeness.
The original collector result is retained only under ignored
data/verification/real-data-2026-10-19/self-defence-observations.json; no current
network scan or historical capture was fabricated to accompany it.

VERIFIED read-only retained-evidence processing: the confined history reader and
analyst.build_case/build_prompt accepted assessment-40tb2mgg with one CVE-2022-0543
finding, 14 evidence items, four services and a 12,513-character request below the
14,000-character budget. All its findings/services/intelligence fit that request.
The retained score remains 100/Critical, not revalidated by this check. The capture
has unknown chronology and no publisher receipt; its retained intelligence dates
are 2026-09-27/28, not fresh October evidence. A read-only SQLite query found the
separate cache dated 2026-10-01/02; no cache or old capture was refreshed. Local
hash correspondence does not prove independent provenance or current target state.

Repair the known gate incompatibility by strengthening the synthetic discovery
helper's positive fixture with an explicit finding ID. Keep strict production
finding-ID validation and all chronology/adversarial assertions unchanged. Rejected
alternative: allow missing finding IDs in retained assessments to make the fixture
pass. `python -B -m pytest -p no:hypothesispytest` on capture_time,
saved_case_discovery, legacy_capture_view, capture_history, self_defence and analyst
reported `183 passed in 11.32s`. TESTED WITH MOCKS for scanner/provider behavior;
VERIFIED executed command/output, not external scanner/model acceptance.
Ruff lint passed and 290 Python files were already formatted. Full gate follows
on the frozen tree. Independent human-labelled model accuracy remains MISSING;
existing model manifest presence is not proof of a running Ollama service.

### WEB-01 — 2026-10-19: useful website metadata without unnecessary data retention

PROJECT stages 3/5/7: improve response-specific context from the existing explicitly
approved HTTP HEAD request, not introduce an unapproved crawler or new scan plan.
The human requested useful website information while avoiding unnecessary data.
Choose a pure typed projection and deterministic precautions over retaining full
headers/page bodies or letting a model infer unsupported protections. Dependencies,
scope, fixed models/signatures, scoring and approval fields remain unchanged.

The existing probe previously saved all response headers in raw_hex, including
Set-Cookie secrets, even though the display omitted some values. It also retained
full redirect destinations. The HTTP branch now discards the body immediately,
validates bounded header syntax, and retains explicitly labelled website_metadata.v1
JSON bytes: response status, declared media family, security-header presence/value
recognition, cookie attribute counts, redirect category and challenge presence.
Cookie names/values, full URLs, server banners, policy nonces and arbitrary values
are not retained. Existing evidence is never rewritten. Raw_sha256 for new HTTP
records hashes the retained projection, not the original network response; the UI
now accurately labels it retained evidence SHA-256. Older records stay readable.
The pre-existing redirect test's exact-wire assertion and displayed-host assertion
conflicted with the requested privacy change: they were replaced with explicit
projection equality checks and secret/destination absence assertions; pinned-IP,
one-HEAD, no-redirect and observation-secret assertions remain. No assertion was
removed simply to pass and no coverage requirement was lowered.

Response-level explanations distinguish observed attributes from effective policy,
sensitive cookie purpose, whole-site authentication and confirmed vulnerabilities.
Interim responses, malformed/folded headers and exceeded budgets fail closed. The
probe still performs one literal-IP HEAD /, not SNI/virtual-host inspection, HTTPS
policy verification or a site crawl. These limitations are explicit in the record.
No generic vulnerability, CVE or score is created from missing response headers.

Each metadata statement receives a server-issued evidence ID for model input.
The first model-wiring test reproduced complete omission under the prompt budget:
repeating capture metadata fourteen times was too expensive. The producer now
retains one request identity with separately citable evidence IDs; it includes the
whole group or reports that request omitted. Legacy short observations preserve
their shape. Zero-finding advice may cite approved supplemental observations without
borrowing an unrelated service citation; scope, unknown-control and claim guards
remain. Canonical context and scores are never modified by follow-up advice.

TESTED WITH MOCKS: the new 32-case synthetic suite covers privacy, cookie attribute
ambiguity, redirects, headers, malformed/oversized responses, immutable persisted
projections, one-use approval, model citation completeness, whole-request budget
omission and validated precaution-only advice. Initial combined new tests returned
2 failures/30 passes (model budget); final combined metadata/evidence/analyst/UI
selection reported `201 passed in 8.76s`. No real network, scanner or model was
executed, no new Markdown file was created, and no existing capture was modified.
MISSING: a reviewed human-captured HEAD response/provenance for real integration
acceptance, plus existing Nikto fixture and pre-commit prerequisites. The full gate
will run on the frozen tree and its console output is retained under ignored data/.
This is a follow-up capability upgrade, not completion of the full live website
assessment, persistence lifecycle or independent model-accuracy study.

Follow-up adversarial review found a quoted cookie Path could contain a fake Secure
token. The first shell diagnostic failed due to quoting and was not reproduction
evidence. A new pure test then returned `1 failed, 6 passed, 26 deselected` and
reproduced the falsely recognised attribute. Quoted cookies/attributes now remain
unverified rather than reporting protection; the suite has 33 cases. The in-flight
gate was deliberately interrupted before editing and is not a pass. The repaired
combined selection passed 202 cases. A new complete gate is started below with a
new source fingerprint and durable console log, without lowering any assertions.

VERIFIED complete gate: `python -u -B scripts/check.py`, using installed Python
3.12.10 and invocation-local PYTEST_ADDOPTS adding `-p no:hypothesispytest -q
--durations=8 --tb=short`, reported Ruff lint PASS, format PASS (292 files),
guarded Pyright `0 errors, 0 warnings, 0 informations`, and:

```text
TOTAL                                 11784     79    99%
Required test coverage of 95% reached. Total coverage: 99.33%
4194 passed, 525 subtests passed in 967.38s (0:16:07)
PASS    pytest + coverage
GATE PASSED
```

Zero failures/skips; source coverage is not model accuracy or real integration.
The metadata module's 57 Python statements were exercised; no branch-completeness
or universal privacy guarantee is implied. Console output is retained at ignored
data/verification/website-metadata-final-gate-2026-10-19.log. Pre/post gate hashes
matched for all 410 tracked/nonignored working inputs:
622f922b5fbed4b0580e8fd6d56a5304728201fe86f9465fbda4fc00e649d840.
Only existing documentation is updated after that frozen-code check.

VERIFIED local startup: `python -u -B -m vulnassess --db data/vulnassess.db
--config config ui --run scanme-2026-09-24 --port 8765` printed
`VulnAssess: http://127.0.0.1:8765/`; listener inspection confirmed 127.0.0.1:8765.
The PostgreSQL override was removed only from the launched child environment,
without showing or changing any credential. The computer-use skill's browser
inspection was blocked by the browser URL policy; no alternate access path was
attempted and no visual verification is claimed. No real website, provider or
publisher was contacted. The existing main page/layout was not redesigned.
Branch codex/coverage-95, baseline commit 6f523f6 plus preserved uncommitted changes.
No commit/push; broader assessment lifecycle and real-model acceptance remain open.

### WEB-02 — 2026-10-19 — Separate public website metadata check (approved scope expansion)

Human approval: after the explicit proposal for a separate Public Website Check
with HTTP/HTTPS metadata only, public-destination validation, no deep scanners or
internal discovery, the human replied "yeh sure go for it..". This authorises
implementation of that mode, not execution against unspecified third parties.
Serves PROJECT stages 1, 3 and 7: input, bounded observation and contextual reporting.

Conflict / resolution / why: the lab-only brief remains the default for scanners.
This narrow exception adds /website-check and same-origin POST
/api/public-website/check, request {target, confirm_metadata_only:true}, response
public_website.v1. No canonical models, CLI, scope.yaml, tables, scores, evidence
requests, cloud-provider permissions or existing lab authorisation are changed.
These additive website UI/API interfaces are part of the approved separate mode.
The existing source hardening and uncommitted changes remain preserved.

Choice: one hostname-correct root HEAD request over HTTP/80 or HTTPS/443, validated
TLS and minimal metadata. Reject credentials, query/fragment, nonstandard ports,
non-public DNS answers and canaries; connect to a checked literal address without
re-resolution. No redirect following, crawler, vulnerability probes, body storage,
cookie values, certificate subject/SAN storage, automatic AI call or risk score.
All DNS answers are checked, including IPv6 and mixed public/private responses.
DNS has a bounded single-worker wait; a timed-out worker cannot spawn a queue of
additional lookups. UI action is same-origin confirmed, serialised and rate-limited.
TLS failure is explicit incomplete coverage, never an insecure retry.

Rejected: widening allowed_cidrs, falling through to lab scanner execution, arbitrary
ports, or filtering by purported information severity. These would conflate a
website metadata request with network authorisation. Public response metadata is
not a confirmed CVE or evidence of internal topology. Root-only coverage, one CDN
address and lack of model analysis remain explicit. Existing metadata minimisation
is reused, but its literal-IP explanatory wording is not reused for hostname HTTPS.

Verification pending: offline policy, fake transport and same-origin endpoint tests,
then the full quality gate. Network transport is not run by the agent. MISSING:
human-provided real capture/provenance for the new public mode. No dependency added,
no real website/model contacted, no PDF export, no commit/push in this increment.

The architecture test's explicit transport registry adds only public_website.py
for its socket import, matching the approved new transport. All existing forbidden
imports/assertions remain; new tests assert public-mode acceptance does not
authorise deep scanning and DNS/canary refusals happen before sockets. This is an
intentional reviewed architecture change, not deletion of the network wall. The
initial full gate was interrupted before making this test-registry change and is
not counted as a completed gate; the final full run is recorded separately.

The first completed full run found a new CSS integration defect:
TestUiAssets.test_no_hardcoded_colours_outside_tokens rejected website-check.css.
It reported 1 failed, 4259 passed, 530 subtests, 99.34% Python statement coverage
in 969.09 seconds; GATE FAILED. All 129 statements in the new transport were
exercised, but that did not establish an application pass. The stylesheet now
uses the existing colour and font tokens without changing their values. The
original UI assertion is preserved. Targeted UI tests and a new full gate follow.

VERIFIED final gate: installed Python 3.12.10 ran `python -u -B scripts/check.py`
with invocation-local PYTEST_ADDOPTS `-p no:hypothesispytest -q --durations=8
--tb=short`. Ruff lint PASS, format PASS (294 files), offline Pyright
`0 errors, 0 warnings, 0 informations`, followed by:

```text
TOTAL                                 11942     79    99%
Required test coverage of 95% reached. Total coverage: 99.34%
4260 passed, 530 subtests passed in 542.04s (0:09:02)
PASS    pytest + coverage
GATE PASSED
```

Zero failed/skipped tests; no assertions removed or coverage floor lowered.
Console: ignored data/verification/public-website-token-repair-gate-2026-10-19.log.
The new public transport exercised 129/129 Python statements; this is not branch
coverage, live-integration verification or model accuracy. TESTED WITH MOCKS:
66 new public-mode cases plus existing metadata/API/UI/wall regressions cover DNS,
literal pinning, IPv6 restrictions, canaries, data minimisation, TLS failure without
insecure retry, limits, consent, rate/concurrency fences and unchanged deep scope.
The repaired focused UI/public selection reported 79 passed, 17 subtests passed.
`node --check vulnassess/ui/static/website-check.js` passed separately.

VERIFIED local UI restart: `python -u -B -m vulnassess --db data/vulnassess.db
--config config ui --run scanme-2026-09-24 --port 8765` printed
`VulnAssess: http://127.0.0.1:8765/`. The PostgreSQL override was removed in the
child shell only. The public page is linked from the main and workflow pages.
NOT RUN: real public website, DNS, TLS or AI transport, or visual browser acceptance.
The browser security policy previously denied inspection; no alternate access
path was attempted. MISSING: human-provided public-mode capture/provenance.
Network collection and AI quality are not established by fake transports.

STATUS: implementation plus complete offline gate verified. Branch codex/coverage-95,
baseline 6f523f6 with preserved local changes; no commit/push. BUILT public metadata
mode; CHANGED new transport, new static page/client/styles, loopback routing,
navigation, synthetic tests and explicit transport registry. DECIDED/DECISIONS:
WEB-02 separates metadata access from deep authorisation, rather than broadening
scope.yaml. DEFERRED/NEXT: human real-response and visual acceptance. Full-site
crawling, AI-generated public reports and PDF/architecture export are not part of
this approved increment; canonical scoring and the existing deep path are unchanged.

### SCAN-STARTUP-01 — 2026-10-19 — Missing Nmap data and masked graph failures

Human requested repair of the displayed light-scan exit 1 and separately requested
project author-metadata cleanup. Serves PROJECT stages 1/3/7: readiness, safe
execution and truthful reporting. The retained assessment-xu95gj6p/nmap.xml records
zero scanned hosts and finished exit=error: Unable to open /etc/protocols. Registry
discovery points to a temporary portable install containing nmap.exe and DLLs but
not nmap-protocols, nmap-services or nmap-service-probes. The source problem is an
incomplete local installation, not target authorisation or model failure.

Windows preflight now checks readable, nonempty data files after the existing
version check, respecting Nmap's existing NMAPDIR override. Missing data names
exact paths and refuses readiness before the scan starts. This checks presence,
not authenticity or semantic correctness of installed scanner data. No installation,
download, synthetic provisioning or real scan is authorised by this fix. A human
must supply the complete approved scanner artifact; it remains MISSING here.

Runtime failures now emit an explicit scanner error and preserve bounded control-
stripped stderr/stdout, with defensive XML finished/errormsg fallback. Malformed
or declaration-bearing XML does not become diagnostic evidence. Timeout and launch
errors remain failures; no scan result or AI finding is manufactured. Canvas node
aggregation prioritises errors over later skipped substages; terminal finalisation
does not invent a second failed stage when the scanner already reported failure.

Tests: 10 new synthetic/fake transport/Node cases and existing preflight/live tests
returned 50 passed after one diagnostic-whitespace mismatch was reproduced and
fixed by normalising controls and spaces. Existing successful-version discovery
tests explicitly mock the new data check so they still isolate discovery/version;
the new tests assert version success with missing data is NOT ready. No assertions
removed or floor lowered. Current local data inspection executed without scanning.
Full gate follows; real successful Nmap execution remains NOT RUN/MISSING data.

### AUTHOR-PRIVACY-01 — 2026-10-19 — Owner-requested identity normalisation

The owner explicitly requested that the remaining previous family Git identity be
replaced with their own identity across the project. This is commit metadata
normalisation at the owner's request, not independent proof of original authorship,
ownership of dependencies or assignment of third-party copyright.

Before changing refs, Git created and verified a complete original-history.bundle
at C:/Users/aksha/Downloads/DE_Project/.private-author-recovery-20261019-01/.
Rewriting happened in an isolated local bare repository using Git fast-export/import,
without cloning/downloading or touching working files. The first isolated attempt
stopped because fast-export omits symbolic aliases; source refs were untouched.
The repaired procedure preserved aliases and verified every referenced file tree
before atomically updating direct refs. No index reset, stash or worktree checkout.

VERIFIED: 21 local/remote-tracking refs retain identical file trees; working-file
digest and porcelain/index state matched before/after the metadata rewrite.
All 265 reachable commits now have author Akshay Damle with
214477382+codezxsWIN@users.noreply.github.com. Committers are that same identity on
263 commits and the original GitHub service identity on two commits. No previous
family identity remains in reachable author/committer records or commit messages.
Future local Git name/email match the canonical identity. Git connectivity fsck
passed. HEAD changed from 6f523f61685fc7dbaede26ad81d903813017607d to
c40039d12fffdfc44f8a6a891569ec5c3991050f; content trees and commit count did not change.

Four current documentation files had personal usernames in historical local paths.
Those usernames were explicitly redacted, not replaced with fictional owner paths;
each document explains the redaction. Historical source deck bytes and third-party
licence/credit notices were not changed. No new copyright-ownership claim was added.

Recovery bundle and original local reflogs/unreachable objects intentionally retain
the original metadata. This is recoverable history normalisation, not forensic data
erasure. Older committed file contents may retain historical local path strings;
the metadata rewrite did not silently rewrite source evidence or historical blobs.
Actual remote repositories were NOT updated: remote-tracking refs are local records,
not live GitHub verification. Any later publication needs an explicit backed-up,
lease-checked history-rewrite plan; do not casually force-push all refs or the backup.

### PUBLIC-RELEASE-01 — 2026-10-19 — Reviewed team snapshot publication

The human requested publication of the entire current project to
github.com/codezxsWIN/de_Demo_recent, with canonical owner authorship and no previous
family name. Visibility was checked: destination public, privwork private. The
human explicitly selected "Keep it public and publish the reviewed project files".
This approval covers reviewed source publication, not keys, raw scans or backup data.

Destination main initially contains one README-only commit already authored under
the canonical owner identity. Preserve that commit and use a normal fast-forward
push. Publish the complete current nonignored file snapshot, not the older source
history whose historical file blobs may retain personal paths. The original local
repository, all ongoing changes and the external recovery bundle remain intact.
No force-push or backup-history publication is part of this release.

Before publishing: inspect the file set and supplied PDF for personal-name and
credential-pattern matches, omit ignored local data, compare per-file hashes,
run the full offline gate in the clean release checkout and verify remote main
matches the published commit. The earlier Nmap/startup gate was interrupted at
the human's request and is NOT a pass. The complete release-checkout gate follows.
The team quickstart now distinguishes supplied source/fixtures from per-machine
runtime prerequisites and explains how to build a fresh synthetic demo database.
Local Nmap provisioning remains MISSING; no scanner installer or binary is bundled.

Release verification completed 20 October 2026 in the clean publication checkout.
The first full run had one failure: an older synthetic executable-preflight test
implicitly depended on host scanner data. The test now explicitly isolates the
version probe; the separate startup-data tests still enforce missing-data rejection.
No production guard, coverage floor or assertion was weakened. Focused regression
verification passed 28 tests. The subsequent full scripts/check.py gate PASSED:
Ruff lint, Ruff format (295 files), offline Pyright (zero errors/warnings) and
4,270 tests plus 530 subtests, 99.34% Python statement coverage (769.86 seconds).
Local logs: data/verification/public-release-gate-2026-10-19.log (failed first run)
and data/verification/public-release-gate-repair-2026-10-20.log (passed rerun).
Logs remain ignored local verification artifacts, not published source.

All 416 source files matched the release copy by SHA256 before staging. The reviewed
credential/personal-name patterns had no matches, including the supplied PDF's
metadata and extracted text. This is a bounded review, not a guarantee of absence
of all possible sensitive data. The fresh synthetic demo completed without copying
the maintainer's local database. Credentials, generated databases/reports, raw live
data, scanner binaries and the recovery bundle remain excluded. Existing whitespace
in imported fixtures and historical documents was retained; a staged diff check
reports those pre-existing whitespace warnings, not a clean whitespace audit.
No real scan, model-provider call or feed refresh was performed for this release.

### CI-OPTIONAL-01 — 2026-10-20 — Optional browser-tool dependency boundary

Cross-cutting reproducibility/quality gate: GitHub Actions run 39324536049 failed
on both Python 3.11 and 3.12 at Pyright because the optional capture-history browser
smoke script statically imported playwright.sync_api. Playwright was installed on
the maintainer's machine but was not a declared core/CI prerequisite. The remote
tests did not run; the earlier local passing gate was not remote verification.

Resolve the optional package only when the explicitly invoked browser smoke needs
it. A missing package exits with a clear MISSING prerequisite message; an unrelated
transitive import failure is re-raised rather than concealed. The browser and its
runtime are never installed automatically. Rejected adding Playwright to the core
CI dependencies, excluding the script from type checking or suppressing missing
imports. The workflow and its 95% coverage floor are unchanged. Six synthetic
tests cover absent package/submodule, broken transitive dependency, existing API,
help and invalid-origin paths without launching a browser or making network calls.

VERIFIED locally: 34 focused browser/offline-gate tests passed; Ruff lint and format
(296 files) passed; offline Pyright returned zero errors/warnings. The application
package is unchanged from the 4,270-test release checkpoint. A complete remote
matrix rerun is required after publication; do not label it green before observing
both jobs. This change does not constitute actual browser visual verification.

### AI-CONTROL-GUIDANCE-01 — 2026-10-20 — Field-local unknown-control guidance

Serves the grounded-explanation/AI-boundary component. A human-approved browser
web-lab run completed collection and five fallback priorities, but Google output
was withheld for an unsupported auth_required assertion. Original prose was not
retained, only audit hashes and the validator diagnostic; the exact sentence cannot
be reconstructed and a validator false positive is not established. One diagnostic
replay of retained evidence passed all three batches before this change, showing
intermittence rather than a proven deterministic repair.

Added field-local text descriptions to every generated claim schema, including
score variants, explaining that unknown controls are not absent and that missing
headers do not establish missing authentication. Wire fields, validators, scope,
canonical scores, model choice and unsafe-claim retry policy are unchanged. This is
generation guidance, not a semantic schema guarantee or a promise of model accuracy.
Rejected bypassing the validator, automatically retrying unsafe claims until one
passes, or displaying invalid prose. The rejected original remains Needs review.

Eight synthetic tests cover compact/uncompacted and score-bound/unbound requests,
immutable schema constants, and all four unknown-control rejection paths. Local
focused verification: 100 tests passed; each unsafe example was rejected after one
model call and retained unchanged input scores. A post-change Google replay of the
same retained case also validated all five findings in three batches; no scanner
was launched for that replay. Quarantined diagnostic responses stay in ignored
data/verification, never rendered as accepted findings. Full gate and a fresh
browser-path verification are pending at this entry; do not report them as passed.

Subsequent browser-path verification PASSED against the same currently authorised
web endpoint after its cooldown: 16 executed, four not applicable, zero failed.
Google included all five header findings across three validated batches. New local
capture assessment-vxdo6e6f passed review/manifest hash verification. Its canonical
finding/risk/band/weights tuples equal the rejected run's tuples. Original capture
assessment-fh9hpjp_ remains Needs review; it was not overwritten or upgraded.
No CVE was confirmed by the live scan, so no live CVE enrichment is claimed.
Screenshot and diagnostic outputs remain ignored local artifacts. These two
post-change successes (one replay and one fresh browser run) do not establish a
statistical reduction in failure rate, a guarantee, or production readiness.

Final offline scripts/check.py verification PASSED: Ruff lint, Ruff format (297
files), offline Pyright (zero errors/warnings), 4,284 tests plus 530 subtests and
99.34% Python statement coverage. The full suite took 947.65 seconds. Local log:
data/verification/analyst-control-guidance-gate-2026-10-20.log. No dependency,
scope, validator or scoring changes were needed. Changes remain on the local
codex/analyst-control-guidance review branch until separately published.

## AI-WORKFLOW-REPLAY-01 — 2026-10-20

Pipeline stage 5 (AI security analyst) and stage 7 (evidence-backed reporting).
The user's scanme capture completed collection but Ollama exceeded its 180-second
generation deadline. A separate successful Google report did not repair the UI.
Inspection found that the stored-target JavaScript transport rejected Google and
Groq Qwen despite the server supporting them; the live analyst inspector rendered
the unrelated stored-assessment selection; and AI-only replay expired with the
ten-minute scan cooldown. These are separate from model output rejection.

Repair the provider allowlist without removing validation or cloud consent. The
live inspector now renders only that run's validated result and offers explicit
configuration for no-scan re-analysis. Missing cloud consent opens configuration
instead of transmitting evidence. Replay reuses an exact-target memory capture
regardless of cooldown age, or verifies the latest dated exact-target saved case
against hashes and current scope. A changed resolved IP, corrupt evidence or
ambiguous chronology still refuses analysis. The existing CVE-refresh loader
continues to require CVEs; zero-finding AI replay does not refresh publishers or
recompute scores. Historical timestamps and retained/not-rerun labels remain
visible. No automatic cloud selection, unsafe-output retry or scope expansion.

Alternatives rejected: raising the Ollama deadline without evidence of throughput;
claiming a standalone successful replay fixed the workflow; launching another scan
when evidence was retained; weakening citation/score checks. Seven new offline
replay tests and expanded JavaScript regression checks cover provider routing,
consent, live-result rendering, expired/restarted caches, exact endpoint/address
binding, zero-finding captures and refusal before scanner/model calls on errors.
Focused checks: 245 tests/72 subtests; after the inspector changes, 177 tests/72
subtests; the final UI/adversarial subset passed 140 tests/72 subtests. These are
overlapping subsets, not additive totals. Ruff and offline Pyright passed.

Real browser checks on the restarted local app: retained scanme evidence reached
Google and passed citation validation (8 evidence items); the live analyst node
displayed its result with 8 executed, 3 retained, 9 not applicable, 0 failed and
0 waiting. Separately, the stored-target Analyze target button reached Google and
completed all seven displayed analyst steps, with Scores changed: false. Neither
test launched a new target scan. Model confidence is advisory, not measured
accuracy. Ollama throughput remains unresolved. Full gate result recorded below
when complete; this entry does not claim it has finished or changes are published.

Final verification: scripts/check.py PASSED all four stages. Full offline suite:
4,291 passed, 530 subtests passed, zero failures/skips reported, 99.34% Python
statement coverage (12,004 statements, 79 missed), in 1,014.62 seconds. Relative
to the prior gate: seven additional tests, sixteen additional source statements,
coverage unchanged at 99.34%. Final JavaScript changes were also checked by the
92-test UI subset (72 subtests). The mirrored clean review checkout passed 99
focused tests/72 subtests, Ruff lint/format and offline Pyright. No source or
dependency download, validator relaxation, score change, live rescan or GitHub
push was used to obtain these results. Local full-gate log:
data/verification/workflow-ai-replay-gate-20261020.log.

### 2026-10-20 — Activity-first assessment workspace

The dependency graph obscured the assessment outcome and context. Make the
workflow tab the default and lead with the real current activity, its purpose,
observed services, supported finding priorities, context provenance, validated
AI recommendations and coverage gaps. Keep the full dependency map, execution
trace, overview, self-defence workspace and inspector available below or alongside
the evidence. No scanner, authorization, scoring or model-validation behavior is
changed and no dependency is added.

The presentation consumes the existing evidence brief. Pending counts remain
unknown, previews cannot masquerade as collection, skipped checks are counted
separately, retained captures are not called fresh scans, native-severity fallback
scores are explicitly not CVSS, and batch-local AI citations retain their batch.
Unknown controls remain unknown rather than being reported absent. All target
strings are inserted as bounded text, never HTML. Live finding titles come from
that target's decision frame rather than an unrelated stored assessment.

Browser inspection exposed a live-context drill-down incorrectly showing the
selected stored host. Context and scanner inspectors now bind to the active
target evidence; the context renderer is shared with the activity board. No
assessment is imported or silently persisted by these presentation changes.

Verification: six new offline JavaScript presentation scenarios cover stored,
running, rejected, preview, partial and scored cases, including literal hostile
HTML, pending counts, score immutability, native fallback, target binding and
batch-local citations. The final focused source and clean-review UI runs each
passed 99 tests / 72 subtests; these are overlapping runs, not additive counts.
Ruff lint/format passed in the clean review checkout. Browser QA on authorized
retained web evidence displayed four services, five supported header findings,
three validated Google batches, explicit skipped-CVE reasons and the correct
target in both context and collection inspectors. This QA did not rescan the
target or retrieve fresh vulnerability intelligence. Capture age remained
explicitly unknown where the retained summary did not supply it. Full regression
gate outcome is recorded separately when complete; model validation does not
establish model accuracy. No GitHub push is part of this UI increment.

Final gate: scripts/check.py PASSED Ruff lint, Ruff format, offline Pyright and
the full offline suite: 4,297 tests / 530 subtests, zero failures, in 895.79 seconds.
Python statement coverage remains 99.34% (12,004 statements; 79 missed): six new
presentation tests, no Python package statement changes. The final UI/insights
subset, including the inspector-routing regression, separately passed 99 tests /
72 subtests after the last presentation edits. Browser light/dark theme checks
passed at 1,127px viewport width without document-wide horizontal overflow;
narrow-device visual QA was not performed. Full-gate log:
data/verification/workflow-activity-gate-20261020.log.

## 2026-10-23 - HARBOR-IMPACT-01: bounded, observable application impact

PROJECT.md components: Lab and demo / Risk ranking; stages 3 (safe evidence
collection) and 7 (report). Reproducible impact and paired authorization controls
support evidence-backed prioritisation without treating lab results as expert
ranking validation.

Choose three real, bounded application behaviors: anonymous bulk export of
fictional business records (HD-17), protected-role mass assignment followed by a
separate administrator authorization request (HD-18), and cross-account order
total modification confirmed by a separate read (HD-19). Mutable records live
only in process memory, with independent vulnerable and secure workspaces.
SQL-injection fixtures remain disposable and read-only. The verifier restores
the original vulnerable role and total in finally blocks and raises an explicit
error if restoration fails. The site exposes manual training controls; opening
the page does not automatically perform these operations.

Alternatives rejected: host command execution, arbitrary filesystem reads,
external callbacks and real payment integration add containment risks irrelevant
to the ranking question. A response merely echoing an attacker-supplied role or
total would not demonstrate an authorization decision or retained mutation.
Changing only titles or severity labels would not provide additional evidence.

Conflict / resolution / why: the request asks for 100/100 weaknesses; preserve
the configured deterministic native-severity policy instead of assigning fake
CVSS/EPSS/KEV values or changing the frozen ranking configuration. Each new
observed case uses the existing HarborDesk High severity mapping (60/100).
Custom lab weaknesses are not assigned CVEs. Trusted metadata and
fixture-specific remediation guidance are wired into the existing canonical
adapter, receipt provenance and generic workflow display. No fixed model,
storage, command or configuration schema changes are made.

No dependencies are added or removed. Use the existing Python standard-library
web server without optional network mode. MISSING: `pyftpdlib` prevents the
optional FTP/TLS lab and its test module from loading. MISSING: `make`, Python
modules `ruff`, `pyright`, `pytest_cov` and `coverage` prevent the complete
required gate; no installation or download is authorized to bypass that gap.
Do not call a web-only check a complete scanner, feed, model or quality gate.

TESTED WITH MOCKS baseline: `python -m pytest tests\test_harbordesk_lab.py
tests\test_harbordesk_extended.py tests\test_harbordesk_probe.py
tests\test_harbordesk_model_budget.py -q` produced `59 passed in 6.05s`.
The socket guard remained enabled. New synthetic regression tests exercise
authorization, actual state read-back, bounds, independent comparison state,
negative verifier observations, restoration on interruption, explicit restoration
errors, canonical provenance, fix guidance and unchanged deterministic ranking.
Post-change execution evidence is recorded separately after validation; no
unexecuted result is asserted by this decision.

## 2026-10-23 - HARBOR-NET-02: preserve executable cases and add bounded network observations

PROJECT.md components: Lab and demo / Risk ranking; stages 3 (safe collection)
and 7 (report). The user clarified that every existing weakness, including the
new application cases, must remain executable and trackable rather than becoming
display-only. The temporary source-only read-only change was restored before
restarting the running lab; no existing case or network implementation is removed.

Conflict / resolution / why: "not too risky" means retain the loopback,
fictional-data, no-host-execution boundary, not replace observations with labels.
Preserve the original application and FTP/TLS implementations and HD-17/18/19.
Add actual cleartext HTTP transport (HD-20), unauthenticated declared-service
inventory (HD-21), and observed HTTP version-banner disclosure (HD-22). Record
actual response evidence and trusted native severity, without fake CVEs, forced
100/100 scores, traffic interception, new external listeners or host enumeration.
The original FTP/TLS source stays unchanged.

Alternatives rejected: an illustrative catalog without observable conditions
would not meet tracking/testing; host command execution, stronger exploit chains
and weakening TLS configurations would create unnecessary containment risk.
The new HTTP checks work with the already-running standard-library web lab and
do not justify installing optional packages. The inventory and minimized-banner
comparisons are additional controls, not removal of vulnerable routes. A /secure/
path on HTTP is explicitly not represented as transport encryption.

The catalog lists all network cases but never creates a finding by itself.
The identity/scope-gated verifier produces evidence, canonical provenance and
existing configured priorities. HTTP observations are distinguished from the
optional FTP/TLS coverage status. No dependency, scope, fixed schema or ranking
configuration is changed. Previous active-case tests are retained and expanded
with original-case preservation, negative network observations and native-priority
checks. Execution results follow validation; this entry does not assert a gate pass.

## 2026-10-23 - HARBOR-NET-03: High-impact network proof without host exploitation

PROJECT.md components: Lab and demo / Risk ranking; stages 3 and 7. The user
requests meaningful High-impact capabilities, not merely low-priority header
findings. Keep every existing case and add a real dedicated management service
on loopback 8791, with an authorization comparison on 8792. Both use only the
already available standard library and the existing fictional workspace records.
The existing web command shape and original FTP/TLS implementation are unchanged.

Choose unauthenticated full fictional backup retrieval (HD-23) and unauthenticated
configuration writes with an independently observed 200-to-503 dispatch change
(HD-24). All changes affect a disposable process-memory queue, never real host
services, files, commands, traffic volume or outside destinations. Verify both
service identities before writes, cap requests, reject foreign Host/Origin
values, restore the original state even after a lost response, and make
verification errors explicit. Existing protected comparisons are retained;
the two new checks also test denied and allowed fixture-administrator access.

Alternatives rejected: inflating the severity of a version header does not show
capability; real command execution, remote-code exploits, legacy TLS weakening
and host-level denial of service would add unnecessary risk. Replacing missing
pyftpdlib with a new FTP implementation would risk changing the original network
cases. No dependency is added, removed, installed or downloaded.

Conflict / resolution / why: preserve the requested real, trackable behavior
within the standing lab boundary. High is a native classification supported by
the fictional full-backup and management-control observations, not a fabricated
CVSS/CVE/EPSS claim or forced 100/100 rank. The unchanged configuration yields
60/100 for these High findings. Record observed protocol services only after
actual identified HTTP responses, and keep optional FTP/TLS coverage separate.
Tests cover identity refusal before writes, functional state changes,
authorization, request bounds, loopback fences, error restoration and canonical
ranking. Full-gate execution remains dependent on human-provided missing tools.

## 2026-10-23 - HARBOR-VERIFY-04: observed functional proof; full gate blocked

TESTED WITH MOCKS: with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`,
`python -m pytest tests\test_harbordesk_lab.py tests\test_harbordesk_extended.py
tests\test_harbordesk_probe.py tests\test_harbordesk_model_budget.py
tests\synthetic\test_synthetic_harbordesk_impact.py
tests\synthetic\test_synthetic_harbordesk_management.py -q` produced
`120 passed in 4.69s`: 120 passed, zero failed, zero skipped (no skip reasons).
The socket-denial fixture stayed enabled. This is not scanner or model evidence.

VERIFIED: `node --check labs\harbordesk\site.js`, Python AST/JSON parsing,
`git diff --check`, and
`git diff --quiet HEAD -- labs\harbordesk\network.py` returned exit 0.
The last command establishes that the original FTP/TLS source was not changed.

VERIFIED: `python -u -m labs.harbordesk` started the portal and the two
management listeners. Startup included
`Training management: http://127.0.0.1:8791/; protected comparison: 127.0.0.1:8792`.
Listener inspection reported `127.0.0.1:8787`, `127.0.0.1:8791` and
`127.0.0.1:8792`, all owned by Python PID 27836. The service was left running.

VERIFIED: `python -m labs.harbordesk.verify --extended` exited 0 and returned
`"passed": 19`, `"total": 19`, `"management_status": "enabled"`, and 17/17
passed secure controls. HD-23 returned a backup with 3 customers, 2 orders,
2 tickets and 2 documents. HD-24 returned
`"baseline_dispatch_status": 200`, `"modified_dispatch_status": 503`,
`"unauthenticated_write_status": 200`. Follow-up requests returned
`paused=false`, dispatch HTTP 200, role `customer`, and order total 280.

VERIFIED: `python -B -` calling `harbordesk_probe.run`, `context.build_profile`
and `scoring.score_available` produced `"canonical_findings": 19`,
`"unscored": 0`; both HD-23/HD-24 had `"native_severity": "High"`,
`"risk": 60.0`, `"band": "High"`, `"cves": []`. Observed HTTP services were
8791 and 8792, not fabricated fingerprints. Actual receipts, canonical findings
and priority summary were retained in ignored
`data/harbordesk-final-20261022T200233822751Z/`.

VERIFIED: browser DOM form submissions on the management console returned
`"afterPause":{"paused":true,"status":503}` and
`"afterResume":{"paused":false,"status":200}`. Original state was restored.
The refreshed network page showed nine network cases with HD-23 and HD-24
first, retaining the original FTP/TLS cases. DOM submissions were used because
physical Playwright clicks were blocked while the shared browser view was hidden;
initial same-document navigation also required a reload to replace stale assets.
These tool limitations are not presented as successful physical-click checks.

MISSING: `make` and Python modules `ruff`, `pyright`, `pytest_cov`, `coverage`.
The required full quality gate, lint, formatter, type gate and source coverage
are not certified. The available offline Pyright wrapper previously exited 127:
`MISSING offline Pyright prerequisite: installed pyright package with dist/index.js`.
No validator was weakened and no package was installed to bypass this blocker.

MISSING: optional `pyftpdlib`; the original FTP/TLS integration test module
cannot import and those listeners were not started. Human-captured HarborDesk
scanner artifacts remain absent at `tests/fixtures/nmap/harbordesk.xml`,
`tests/fixtures/nikto/harbordesk.json` and `tests/fixtures/zap/harbordesk.json`;
existing captures for other lab applications do not supply those inputs.

NOT RUN: Nmap, Nikto, ZAP, feed retrieval, models and the optional FTP/TLS lab.
The observed management checks are actual local application/network evidence,
not scanner output, production compromise, model accuracy or research validation.

TESTED WITH MOCKS: the final repeat of the same six-file pytest command produced
`120 passed in 6.50s`, zero failures and zero skips. VERIFIED: the final
`node --check labs\harbordesk\site.js`, `git diff --check`, and
`git diff --quiet HEAD -- labs\harbordesk\network.py` each exited 0.
Final bounded GETs returned
`GET http://127.0.0.1:8791/config status=200 paused=False` and
`GET http://127.0.0.1:8791/dispatch status=200`.
The three loopback listeners remained owned by PID 27836. The inspected temporary
browser-output file was removed; ignored real verification receipts were retained.
Concurrent worktree changes outside this HarborDesk task were left untouched.
The full quality gate remains blocked, not passed.

## 2026-10-23 - INTEL-DELIVERY-01: Recorded intelligence delivery; online expansion pending

Serves PROJECT.md stage 6 (CVE intelligence), stages 5/7 (bounded interpretation
and reporting), and the cross-cutting reproducible-ranking component. Delivering
the evidence already available helps investigate the research question without
changing its scoring hypothesis or manufacturing missing publisher information.

Conflict / resolution / why: the request proposes automatic public NVD/CPE,
FIRST EPSS, CISA KEV and MITRE CWE retrieval, while the standing boundary requires
offline processing and human-approved fixed-interface changes. The approval
request returned no available human decision. Autopilot is not an ADR approval.
Comprehensive online coverage, new CWE/CPE retrieval and any new cache/interface
schemas remain **PROPOSED, not approved or implemented by this increment**.
The existence of the earlier targeted public transport is not approval to expand
it. No provider, feed, model, credential or scanner operation was exercised.

Choose the compatible delivery increment:

- Supply at most two recorded HTTP(S) advisory references per included CVE to
  the analyst, each at most 200 characters. Keep them in citable bounded evidence,
  explicitly count withheld/duplicate/over-budget references, and reject malformed
  reference containers. Links containing credentials, whitespace/control tokens
  or unsupported schemes are not included. A retained reference is not a verified
  fix, proof of publisher identity or proof of target applicability.
- Retain existing prompt/evidence budgets and rejection rules. Do not add a
  description field to the compact intelligence object or change the model's
  output schema. Original payloads and numerical priorities are not rewritten.
- Show existing CPE-derived CVE associations in the read-only finding projection
  with their recorded match method/confidence. Preserve scanner-named identifiers
  separately; do not claim that a product association confirms exploitability.
- Expose CWE identifiers and explicitly distinguish an absent CVE association
  from negative exploitation evidence. The analyst and saved report disclose that
  CWE definitions were not retrieved. Recorded reports use "not applicable (no
  CVE)" rather than a misleading negative KEV result for no-CVE priorities.

Reuse existing analyst, score-fact, findings and report components. No fixed
model, function contract, table, CLI, configuration, score formula, scope or
dependency is changed. Alternatives rejected: a second intelligence engine would
duplicate authority; invented CWE explanations or replacement feed evidence
would misrepresent source availability; silently enabling online lookup would
bypass review; dropping CPE candidates would conceal evidence already retained.

TESTED WITH MOCKS: new pure synthetic delivery tests reproduce missing advisory
delivery, malformed-reference acceptance, hidden CPE associations and no-CVE
reporting defects without contacting a publisher or model. The initial focused
run reported 11 failures and one pass. The corrected implementation passes the
new cases, including URL withholding, four-service prompt-budget preservation,
cross-finding isolation and unchanged input/score records.

VERIFIED: the combined focused local execution used:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; $env:PYTHONDONTWRITEBYTECODE='1'; python -m pytest -q -p no:cacheprovider -- tests\synthetic\synthetic_intelligence_delivery_test.py tests\test_all.py::TestCvss31 tests\test_all.py::TestScoring tests\test_all.py::TestContext tests\test_all.py::TestEvaluate tests\test_evaluate_research.py tests\test_control_applicability.py tests\synthetic\test_synthetic_scoring_edges.py tests\synthetic\test_synthetic_scoring_input_boundary.py; exit $LASTEXITCODE
```

The execution runner reported exit code 0 and:

```text
243 passed
40 subtests passed
0 failed
0 skipped
Skip reasons: none
Runtime: 8.49s
```

MISSING: `make`, Python modules `ruff`, `pyright`, and `pytest_cov` prevent the
required complete gate and whole-package coverage measurement. An incorrectly
broadened test invocation also encountered the unrelated missing `pyftpdlib`
package during collection; that invocation is not a pass and is not evidence
that the selected delivery tests failed. It was corrected to explicit selectors.
Nothing was installed to bypass these prerequisites.

NOT RUN: Ruff lint/format, Pyright, complete pytest/coverage, real publisher
integration, MITRE taxonomy retrieval, CPE API applicability validation, scanner
execution and independent expert evaluation. Source inspection and synthetic
delivery tests do not certify those integrations or establish ranking improvement.
The next online increment requires the actual human-approved ADR and reviewed
source contracts/artifacts; the remaining quality gate requires approved tooling.

Clarification: URL credential withholding covers authority userinfo, and the
control-token check covers recognised syntax. Neither is a general secret
detector, publisher-identity verifier or assertion that a reference is safe.

VERIFIED: `git --no-pager diff --check -- README.md vulnassess\analyst.py
vulnassess\report.py vulnassess\score_facts.py
vulnassess\ui\assessment_report.py vulnassess\ui\vulnerability_findings.py`
returned exit code 0 with no output. This is whitespace validation, not Ruff.

MISSING: real fixture directories `tests\fixtures\nessus`, `tests\fixtures\cwe`
and `tests\fixtures\cpe` are absent. `tests\fixtures\nikto` contains only
`.gitkeep`, `README.md` and `EXAMPLE-synthetic-dvwa.json`, not a real capture.
These omissions prevent real-integration claims; the increment tests pure
delivery of already-recorded information rather than parser/provider correctness.

## 2026-10-23 - HARBOR-EXPLAIN-05: readable, clickable case explanations

PROJECT.md stage 7 (Report) and cross-cutting Lab/demo. Make each implemented
weakness understandable through the same reviewed guidance used by the workflow.
This supports traceability from an observation to its consequence, expected proof,
remediation and verification; it does not establish ranking accuracy.

Choose native keyboard-accessible case buttons and a responsive dialog with
plain-English meaning, impact, mechanism, entry point, expected verifier proof,
fix checklist and confirmation steps. Keep prerequisites/evidence limits in
progressive disclosure. Restore focus on close and leave all active testing
controls separate and unchanged. Opening a guide performs only a catalog read,
never an active check, state mutation, score change or model call.

Reuse vulnassess.harbordesk_guidance rather than duplicate per-case descriptions
in JavaScript. Add reviewed explanation content to the existing author-catalog
response without changing its original case fields or the canonical finding,
score, storage, command or configuration contracts. Missing guidance produces an
explicit error, not a sample or success-shaped fallback. Treat every rendered
value as text and distinguish expected proof from a current retained observation.

Alternatives rejected: raw JSON does not meet the readability request; tooltips
cannot comfortably present fixes and evidence; a new UI library or live LLM
adds unnecessary provisioning, disclosure and consistency costs. Replacing
existing testing buttons with explanations would hide the capabilities the user
explicitly asked to preserve. No dependencies are added or installed. Planned
validation covers all 23 case guides, safe text rendering, errors, focus,
close-during-load and out-of-order responses, plus the preserved active lab.

HARBOR-EXPLAIN-05 keyboard adjustment: VERIFIED browser probing with
`page.keyboard.press('Escape')` returned
`{"escapeKeyReachedDialog":true,"nativeCancelEvent":false,"dialogStillOpen":true}`
in the embedded browser. Add an explicit dialog-scoped Escape handler that closes
and restores focus, rather than relying solely on the missing native cancel
event. Keep native Tab containment and ordinary-key behavior. Extend the offline
DOM regression to cover this observed host behavior; no active lab route changes.

HARBOR-EXPLAIN-05 readability adjustment: VERIFIED browser viewport checks at
320x740, 390x844 and 1280x900 returned `horizontalOverflow:false` for the
explanation body/header. The grids used one column on narrow layouts and two on
desktop. They also exposed retained internal scroll offsets (for example
`scrollTop:692.7999877929688` at 320px), so reset the body to the beginning when
rendering each explanation. Add a regression for opening after a scrolled case;
do not change or remove any active training operation.

HARBOR-EXPLAIN-05 wording: replace the shared guide's jargon-heavy meaning
sentences with plain-English descriptions (for example, signing in, another
account's record, a database instruction and an expired certificate). Keep the
technical mechanism, expected proof, limits, fixes and confirmation steps
alongside them. This is a wording change only; finding identities, scores,
evidence, case implementations and the guidance field structure are unchanged.

## 2026-10-23 - HARBOR-EXPLAIN-06: explanation verification and remaining gates

TESTED WITH MOCKS: with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`,
`python -m pytest tests\test_harbordesk_lab.py tests\test_harbordesk_extended.py
tests\test_harbordesk_probe.py tests\test_harbordesk_model_budget.py
tests\synthetic\test_synthetic_harbordesk_impact.py
tests\synthetic\test_synthetic_harbordesk_management.py
tests\synthetic\test_synthetic_harbordesk_explanations.py -q` returned
`125 passed in 3.53s`, with zero failures/skips. The new pytest assertion confirms
`9 explanation interaction checks passed` in the network-denied Node VM.
These cover card semantics, safe text rendering, focus, close/Escape, scroll
reset, explicit content errors and delayed/out-of-order responses. They are
synthetic logic tests, not scanner, model or real-browser evidence.

VERIFIED: actual browser checks opened all 23 cases and found all six explanation
sections, restored focus for every card, activated a card with Enter, kept Tab
inside the dialog, and closed/restored focus with Escape. Five direct shortcuts
also opened their expected guides. The final browser result included
`"allCasesExplained":23,"readOnlyOpening":true,"everyCaseStartsAtTop":true,
"escapeAndFocusReturnForAll":true`; no non-GET requests were made while opening
the guides. The active HD-24 explanation was left open for the user.

VERIFIED: `page.setViewportSize` checks at 320, 390 and 1280 pixels returned
`"inViewport":true,"noHorizontalOverflow":true` for every size. Narrow grids
used one column; desktop used two. A screenshot review confirmed the summary,
impact/mechanism, proof and checklist hierarchy; each new guide starts at its
beginning rather than a previous guide's scroll offset.

VERIFIED: `node --check labs\harbordesk\site.js` exited 0.
`git diff --quiet HEAD -- labs\harbordesk\network.py` exited 0, preserving the
original FTP/TLS source. A task-scoped `git diff --check -- ...` covering the
explanation paths exited 0. The global `git diff --check` instead reported
`vulnassess/intel_online.py:256: new blank line at EOF.` This concurrent,
unrelated change was left untouched; no clean whole-worktree check is claimed.

VERIFIED: `python -m labs.harbordesk.verify --extended` still returned 19/19
intentional conditions and 17/17 passed secure controls after the explanation
changes. The catalog is not used to manufacture detections or adjust scores.

VERIFIED: the final `python -B -` bounded catalog/state check returned
`{"cases":23,"complete_explanations":23,"explanation_field":"cases[].explanation",
"state":{"role":"customer","order_total":280,"paused":false}}`.
The explanations are per-case fields, not a separate top-level `guides` array.
Listener inspection reported 127.0.0.1 ports 8787, 8791 and 8792 owned by PID
43112. The requested services remain running in detached session
`harbordesk-explanations-final-20261023`; owned temporary browser outputs were
removed and unrelated worktree edits preserved.

MISSING: Make, Ruff lint/format, Pyright, pytest-cov/coverage and optional
pyftpdlib. The full required gate and source coverage remain blocked, not passed.
No dependency was added, installed or downloaded.

MISSING: human HarborDesk scanner captures at
`tests/fixtures/nmap/harbordesk.xml`, `tests/fixtures/nikto/harbordesk.json`
and `tests/fixtures/zap/harbordesk.json`, as recorded in HARBOR-VERIFY-04.

NOT RUN: scanners, models, feeds and optional FTP/TLS integration. This increment
serves stage 7/Lab-demo comprehension and traceability, not parser certification,
research-success measurement or a verified new scan from opening a dialog.

## 2026-10-23 - HELPY-CHECK-01: verified cancellation and evidence-grounding fixes

PROJECT.md stage 7 (Report) and cross-cutting Lab/demo. The user's Helpy check
serves faithful evidence explanation, not new scores, scans or expanded model
authorization. Trace the existing saved-report panel, same-origin API, source
selector and consent boundary directly.

TESTED WITH MOCKS baseline: `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest
tests\test_helpy.py -q` returned `19 passed in 7.65s`. New synthetic regressions
then returned `5 failed, 18 passed in 2.45s`. They reproduced a late answer
repopulating Clear conversation, a 19-finding capture described as 12, an omitted
thirteenth CVE described as zero CVEs, retained HarborDesk verifier coverage
omitted, and Nikto collection asserted when only Nmap coverage was recorded.

Choose versioned pending-request ownership, explicit transport abort and stale
reply suppression on Clear/Close/provider-change/page-hide. Validate the response
before adding a model-labeled reply, so malformed excerpts cannot render partial
success. Preserve same-capture validation, plain-text rendering, cloud/voice
consent, extractive answers and existing model schema. Client cancellation does
not establish that server-side model work stopped; document this limitation.

Evaluate capture-wide counts and CVE facts over all retained findings while
retaining the existing bounded excerpt budget and disclosing omitted details.
Reuse reviewed HarborDesk guidance for known lab checks, preserve actual native
severity/tool provenance in excerpts and never infer unrecorded scanner coverage.
Source catalog changes are not scoring changes; canonical schema, fixed command
shape, storage and configuration interfaces are unchanged.

Alternatives rejected: hiding the late transcript without abort/version checks
would leave races and speech active; weakening response validation would conceal
provider failures; changing native scores or inventing model/scanner output to
make Helpy appear operational would violate the evidence boundary. No dependency
is added, removed, installed or downloaded.

MISSING at preflight: workbench listener 127.0.0.1:8765 and local model listener
127.0.0.1:11434. The existing data/live/raw directory has no saved capture.
Do not manufacture an assessment or start a model to conceal these prerequisites.
The actual model-backed answer path remains unexercised.

### HELPY-CHECK-01 verification - 2026-10-23

TESTED WITH MOCKS: `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest
tests\test_helpy.py tests\synthetic\test_synthetic_helpy_regressions.py
tests\test_assessment_report.py tests\test_report_composer.py
tests\test_capture_history.py -q` returned `94 passed in 15.87s`:
94 passed, zero failed, zero skipped (no skip reasons). The repository socket
guard stayed enabled; all selector/model clients and browser transports were
fakes. These related report/capture tests preserve the source and integrity
boundaries, not real-model reliability.

TESTED WITH MOCKS: browser checks loaded the actual helpy.js file into an
isolated, explicitly SYNTHETIC about:blank DOM with a non-forwarding fetch fake.
The initial result returned
`{"mockRequests":1,"sourceHighlighted":true,"sourceExpanded":true,
"literalText":true,"injectedImages":0}`. Additional checks returned
`{"cloudConsentBlocks":true,"clearCancelsLateReply":true,
"closeCancelsLateReply":true,"oldReplyCannotUnlockNewRequest":true,
"invalidResponseWithheld":true,"escapeClosesAndRestoresFocus":true,
"actualModelCalled":false}`. No microphone, speech provider, cloud model,
scanner, real saved assessment or external endpoint was used. The synthetic
browser harness was cleared afterward.

VERIFIED: `node --check vulnassess\ui\static\helpy.js` and the task-scoped
`git diff --check -- vulnassess\helpy.py vulnassess\ui\static\helpy.js
tests\synthetic\helpy_check.mjs tests\synthetic\test_synthetic_helpy_regressions.py
docs\ui.md docs\decisions.md` each exited 0. No global clean-worktree or full
quality-gate result is claimed; concurrent edits were left alone.

MISSING: Make and Python modules ruff, pyright, pytest_cov and coverage, confirmed
by local tool/import discovery. Ruff lint, Ruff format, Pyright, source coverage
and the required full `make check` gate cannot be certified; no tool is downloaded
or installed to bypass this blocker.

NOT RUN: a real Helpy provider round trip, dictation/speech integration, scanners,
feeds and live assessments. The workbench listener and approved local provider
were unavailable at preflight, and there was no saved capture under
data/live/raw. A human must provide a real retained assessment and an available
approved provider to verify that integration. Do not turn this missing runtime
into a fabricated successful chat. Existing HarborDesk services were not changed
or restarted by the Helpy check.

## Network-service native triage v1 — 2026-10-26

Decision: replace the identical fallback only for evidence-bound `service-network`
owner-policy violations with the optional `service-network-triage-v1` hypothesis
in `weights.yaml`. Base categories distinguish login, bounded file read, confirmed
MQTT nonce exchange, SNMP management read, optional signing and certificate expiry.
Explicit, sufficiently confident exposure/environment/owner-criticality inputs
contribute separate bounded terms. Retain the category, terms, policy version,
endpoint-policy hash and evidence hash; replay them in reports and snapshot audits.

Rejected: assigning invented CVSS vectors, importing CVE threat data without a CVE,
using an LLM to set scores, or treating host role/other endpoint controls as proven
mitigation. Existing CVE and other scanner paths, including HarborDesk, keep their
numerical behavior. Historical receipts are not rewritten. The weights are local
operational assumptions, not calibrated risk estimates or expert-validated ranks;
independent held-out judgments remain necessary to assess ranking quality.
