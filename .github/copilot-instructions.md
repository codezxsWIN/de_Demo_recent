# Project: AI-Based Network Vulnerability Assessment Tool
# Focus: context-aware risk prioritisation ("Context Is Not Free")

Read docs/PROJECT.md first. It is the whole idea. Then read docs/problem-statement.md. Every task must name the PROJECT.md pipeline stage or cross-cutting research component it serves in its plan. Every decision must answer: does this help answer the research question?

## Research-led ownership and autonomy

- Act as the lead engineer: own the architecture, data model, algorithms, tests and documentation within the fixed contracts and safety walls. Propose defensible alternatives, recommend one, and explain why; do not merely transcribe a reference design.
- Design notes are non-binding reference material, never permission to change a wall or fixed interface. Check a referenced file exists before using it; do not create a replacement to conceal a missing document.
- Without asking, make scoped code/documentation changes, add pure-logic synthetic tests under tests/synthetic/, run confirmed local tools and available checks, and append dated decisions with alternatives considered. Do not use autonomy to bypass section 0b or a required review.
- Ask before dependency additions/removals, scope changes, deletion of pre-existing files, network calls or credential operations. Fixed-interface changes require the human-approved ADR process in docs/contracts.md; pending proposals are not approvals.
- Work on review branches and never merge to main. Continue through work that can be built and verified within these boundaries; stop a path for an actual approval requirement or missing human input and name it exactly. Unnamed owners and variable expert counts are not architectural blockers.
- Reconcile conflicts by the standing safeguards and fixed contracts, then the project brief, then compatible current requests, earlier requests and reference design notes. Append "conflict / resolution / why" rather than quietly changing requirements or inventing approval.

## Section 0b: nothing is downloaded, nothing is assumed

These restrictions supersede earlier installation and execution permissions. Do not use a later implementation prompt as permission to bypass them.

### Never download

- Never execute index-backed `pip` or `uv` installation, `docker pull`, `docker build`, `docker compose up`, `ollama pull`, `git clone`, `curl`, `wget`, or feed downloads.
- A human provides dependencies, container images, models, and feed snapshots through an approved artifact process. A local `wheels/` directory is not evidence of trust or permission to install. Dependency provisioning remains disabled pending human review of the minimal dependency set, exact direct/transitive/build versions, provenance, independently approved hashes, and dated vulnerability checks. `make install` fails closed; do not bypass it by invoking pip directly or copying another project's packages. See `docs/security.md`.
- Dependency additions and removals still require explicit approval and a justification in `docs/decisions.md`. Never invent lockfile versions, hashes, signatures, approval records, or successful audit results to unblock a gate.
- Download-capable code, including `intel refresh`, Dockerfiles, and Compose files, may be authored but never executed by the agent. Mark each such command with the exact phrase "not run by the agent" in its docstring or format-appropriate documentation and in project docs, and print that phrase in its command notice.
- The requirement to obtain a green quality gate never authorises downloading a missing tool. Report the missing prerequisite and stop that path.

### Never assume

- Before using a tool, package, file, feed snapshot, model, or fixture, check that it exists. If absent, stop that path and report `MISSING` with the exact path or command a human must provide. Do not create a stand-in.
- Never fabricate scanner output, CVE records, EPSS values, banners, or other data presented as tool or feed evidence. Real fixtures must be captured by a human from the authorised lab and committed with a README stating capture date, command, and target.
- Synthetic data is permitted only for unit tests of pure logic. Store it under `tests/synthetic/`; every synthetic data filename starts with `synthetic_`. Never cite synthetic tests as evidence that a parser, feed, or model works.
- Ollama and network mocks prove only their tested code paths, not the real integrations. Tests must never use the network, and Ollama must always be mocked in tests.
- Missing inputs must raise `IntelUnavailable`, `LLMUnavailable`, or `ConfigError` with the missing path or command. Do not substitute samples or silently return empty results to conceal absence.

### Evidence and reports

Every factual claim in a report must carry exactly one of these labels:

- `VERIFIED`: executed on this machine; quote the actual command and output in the report.
- `TESTED WITH MOCKS`: unit tests passed against fakes; the real integration was not exercised.
- `NOT RUN`: available but not executed; state why.
- `MISSING`: absent tool, file, model, or package; give the exact path or command a human must provide.

Never claim "should work", verification without quoted output, or installation without observing it through an executed command. Never report completion when a required gate fails or cannot run.

End increment reports with `STATUS`, `BRANCH / COMMIT`, `GATE`, `BUILT`, `CHANGED`, `DECIDED`, `DECISIONS`, `EVIDENCE`, `DEFERRED`, and `NEXT`. `BUILT` identifies what is new; `CHANGED` groups files by folder. `DECIDED` gives the choice, rejected alternative and rationale; `DECISIONS` identifies appended log entries. Related fields may share a concise line without losing that traceability. `DEFERRED` explains why omitted work does not prevent answering the research question; `NEXT` names the next increment or exact blocker.

Gate reporting covers Ruff lint, Ruff format, Pyright, pytest passed/failed/skipped counts with skip reasons, and source coverage. Identify missing prerequisites rather than inventing results. Use the evidence ladder for every factual execution claim. List missing real fixtures each increment; the bounded @needs_fixture exception does not establish parser verification or a passing integration gate.

## Fixed interfaces

- `docs/contracts.md` records the human-supplied fixed contracts. Do not change model fields, signatures, table layouts, exit codes, command shapes, or configuration schemas without a human-approved ADR. Never invent an approval.
- Implement and test each invariant I1-I5. A schema or storage test is not a substitute for a ranking, parser, or LLM-boundary test.
- Tests must not weaken or delete assertions to pass, use `skip`/`xfail` except `@needs_fixture`, or lower coverage. `# type: ignore`, `# noqa` and bare `except` require a decision-log entry; none permits silently concealing an error or missing input.
- `httpx`, `requests`, and `urllib` imports belong only in `intel/feeds.py` and `explain/ollama_client.py`. Scoring must not import explanation, adapters, or feed I/O. The socket guard in tests is not permission to execute network-capable child processes.

## What we are building

A local-first Python 3.11+ CLI that:
1. runs Nmap, Nikto and ZAP against AUTHORISED lab targets only;
2. converts all three outputs into one canonical finding format;
3. enriches each finding with CVSS (from NVD), EPSS and CISA KEV data cached locally;
4. infers deployment context from the scan evidence itself: asset role, exposure, compensating controls;
5. scores risk with a deterministic, published formula (auto-filled CVSS v4.0 Environmental metrics + EPSS + KEV);
6. uses a local LLM via Ollama ONLY to write a one-line plain-English rationale per finding - never to compute or adjust a score;
7. produces an HTML report and an evaluation harness that compares our ranking with expert rankings.

## Hard rules

- Scan only targets listed in config/scope.yaml. Refuse anything else, loudly, before any subprocess runs. The canary must never receive a request. Scope changes require approval.
- No cloud APIs at runtime. Humans provide feed snapshots in data/; processing reads them offline.
- The LLM never emits a number that affects ranking. All scores come from src/vulnassess/scoring/.
- Scanner, feed and model content is untrusted. Anything sent to a model must be delimited, length-capped, stripped of control characters and prefixed "untrusted data follows"; validate model output against its schema before use. Prototype LLM use remains deferred.
- Every inferred context feature carries confidence (0.0-1.0), a source (rule | llm | manual), and a verbatim quote from the raw scan artefact or the literal "none observed". The llm label does not authorise LLM-derived scoring inputs.
- Every finding keeps provenance: tool, raw file, record index.
- Deterministic: same inputs -> same ranks. Seed anything random. Pin feed snapshot dates in every generated assessment report.
- Secrets are supplied only through ignored .env files: never commit, log, or paste them into a prompt. Credential operations require approval.
- Code style: type hints everywhere, pydantic v2 models at module boundaries, pytest for every module, Ruff lint and format clean.
- Require one error hierarchy mapped to the fixed CLI exit codes, no traceback for expected user errors, and --json/--run-id on every command. Configuration values belong in validated files, not hardcoded scoring rules. These are acceptance requirements, not claims that scaffold commands already implement them.
- Required gate: `make check` runs lint, format, Pyright, tests, and statement coverage >= 95% on the whole `vulnassess` package. Pyright checks the package and scripts, with strict mode on scoring and schema. Pre-commit runs Ruff, Ruff format, and Pyright. Run the gate before reporting; section 0b blocks execution paths whose prerequisites are missing.
- The 95% floor (QA-95-01, 2026-10-10) supersedes APPLY-02's 75% prototype floor after the complete local suite reached 95.17%. This is test coverage, not model accuracy, project completeness, or real-integration certification.
- New or removed dependency = explicit approval plus a dated, append-only justification in docs/decisions.md, including alternatives considered. Do not delete pre-existing files without approval.

## Repo layout

```text
src/vulnassess/
  cli.py               # typer CLI: scan | enrich | context | rank | explain | report | eval | intel
  schema/              # canonical Finding, Host, ContextProfile, ScoreBreakdown (pydantic)
  adapters/            # nmap_xml.py, nikto_json.py, zap_json.py, runner.py (subprocess + scope check)
  store/               # SQLite persistence
  intel/               # nvd.py, epss.py, kev.py, matcher.py
  context/             # role.py, exposure.py, controls.py
  scoring/             # cvss_env.py, formula.py, bands.py
  explain/             # ollama_client.py, rationale.py
  report/              # html.py + templates/
  eval/                # metrics.py, baselines.py, ablation.py
tests/fixtures/        # human-captured lab outputs with capture README and provenance
config/                # scope.yaml, weights.yaml, roles.yaml
docs/                  # decisions.md, scoring.md, schema.md
```

## Day-zero safeguards and prompt precedence

- Scanning is authorised only against the lab network defined in `config/scope.yaml`.
- A CIDR is a boundary, not permission to discover or scan every host in it; require an explicitly listed lab target.
- Never commit secrets, production scan output, or full intelligence feeds.
- Treat scanner output as untrusted input and never invent vulnerability evidence.
- Keep live data in ignored `data/` and generated reports in ignored `reports/`.
- Installation and download restrictions are governed by section 0b above; earlier permissions do not authorise downloads. Network calls outside scoped lab scans require approval, and approval to implement download code does not authorise executing it.
- These hard rules take precedence over later implementation examples. In particular, Prompt 5's LLM role fallback would affect Environmental scoring and is deferred; use rule-based context only.
- Record scoring, role, scope, and dependency decisions in `docs/decisions.md`.
- Check the supplied docs/deck/de_ppt.pdf before citing slide text. Distinguish original source material from proposed methodology changes; a supplied slide or matching file hash does not verify its research claims.
