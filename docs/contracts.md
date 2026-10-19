# Fixed contracts

Human-supplied specification, adopted 2026-09-06. These are requirements, not a completion report. The agent must not change a fixed interface without a human-approved ADR. Adoption does not approve dependencies, downloads, scope changes, or fabricated evidence; section 0b and `docs/security.md` still govern execution.

## 1. Layout and naming

Package: `vulnassess`, using the `src` layout. Modules: `cli.py`, `errors.py`, `logging.py`, `settings.py`, `registry.py`, `schema/`, `store/`, `adapters/`, `intel/`, `context/`, `scoring/`, `explain/`, `report/`, `eval/`.

Tests mirror modules as `tests/test_<module>.py`. Real fixtures belong in `tests/fixtures/<tool>/`, supplied by a human with a capture README recording date, command, and target. Synthetic data is restricted to pure-logic tests and `tests/synthetic/synthetic_*.{json,csv,yaml}`. Golden snapshots belong in `tests/golden/`.

## 2. Errors and exits

| Result | Exit code |
| --- | --- |
| Success | 0 |
| Unexpected error | 1 |
| `ConfigError` | 2 |
| `ScopeError` | 3 |
| `AdapterError` | 4 |
| `IntelUnavailable` | 5 |
| `LLMUnavailable` | 6 |

Every error must name the missing path, command, or configuration key. The CLI must not show a traceback for codes 2-6.

## 3. Models

Use Pydantic v2. `Finding`, `Enrichment`, and `ScoreBreakdown` must use `ConfigDict(frozen=True)`. Nullable fields remain required unless the specification gives a default. The sole field default specified below is `Service.tls=False`.

```python
Tool = Literal["nmap", "nikto", "zap", "nessus"]
Role = Literal[
    "database",
    "web_frontend",
    "app_server",
    "domain_controller",
    "mail",
    "file_share",
    "iot_embedded",
    "workstation",
    "network_device",
    "unknown",
]
Band = Literal["Critical", "High", "Medium", "Low"]
```

The field declarations are fixed:

```text
Provenance:
  tool: Tool; raw_path: str; record_index: int; run_id: str
Service:
  port: int; protocol: Literal["tcp", "udp"]; name: str | None; product: str | None
  version: str | None; cpe: str | None; banner: str | None; tls: bool = False
Host:
  ip: str; hostname: str | None; os_guess: str | None; services: list[Service]
Finding:
  id: str; host_ip: str; port: int | None; protocol: str | None; url: str | None
  tool: Tool; tool_native_id: str; title: str; description: str; evidence: str
  cve_ids: list[str]; cwe_ids: list[str]; reference_urls: list[str]
  native_severity: str | None; native_confidence: str | None
  first_seen: datetime; last_seen: datetime; provenance: Provenance
Feature:
  value: Any; confidence: float; source: Literal["rule", "llm", "manual"]; evidence: str
ContextProfile:
  host_ip: str; role: Feature; exposure: Feature; segment: str | None
  controls: dict[Literal["waf", "auth_required", "tls", "rate_limiting"], Feature]
  manual: dict[str, Feature]
Enrichment:
  finding_id: str; cve_id: str; match_method: Literal["explicit", "cpe_range"]
  match_confidence: float; cvss31_vector: str | None; cvss31_base: float | None
  cvss40_vector: str | None; cvss40_base: float | None; epss: float | None
  epss_percentile: float | None; kev: bool; kev_date_added: date | None
  feed_dates: dict[str, str]
ScoreBreakdown:
  finding_id: str; cve_id: str | None; cvss_version_used: Literal["4.0", "3.1"] | None
  base_vector: str | None; base_score: float | None
  env_vector: str | None; env_score: float | None; env_modifications: dict[str, str]
  epss_percentile: float | None; threat_multiplier: float | None; kev: bool
  native_fallback: str | None; risk: float; band: Band
  inputs: dict[str, Any]; weights_hash: str
Rationale:
  finding_id: str; text: str; source: Literal["llm", "template"]
  model: str | None; validation: dict[str, Any]
```

`Finding.id` is `str(uuid5(NAMESPACE_URL, fingerprint))`. Preserve the fingerprint algorithm exactly, including its handling of a falsey port:

```python
@staticmethod
def fingerprint(host_ip, port, protocol, tool, tool_native_id, url) -> str:
    return sha256(
        "|".join(
            [host_ip, str(port or ""), protocol or "", tool, tool_native_id, url or ""]
        ).encode()
    ).hexdigest()
```

`Finding.evidence` is a verbatim raw-record excerpt of at most 2048 characters, never a paraphrase. Nmap and Nikto must have `native_severity=None`. `Feature.confidence` is in [0, 1]; its evidence is never empty. `ContextProfile.exposure.value` is `internal` or `internet_facing`. Manual keys are `criticality` (integer 1-5) and `environment` (`prod` or `test`). Enrichment feed dates identify NVD, EPSS, and KEV snapshots using ISO dates. A provenance label of `llm` is not permission to influence scoring.

## 4. Store

Use standard-library `sqlite3`, WAL mode, and parameterized queries. Table names and columns are fixed:

```text
runs(run_id PK, started_at, config_hash, feeds_json)
hosts(run_id, ip, json)
findings(id PK, run_id, json, first_seen, last_seen)
enrichments(finding_id, cve_id, json)
context_profiles(run_id, host_ip, json)
scores(run_id, finding_id, json, risk, band)
rationales(run_id, finding_id, json)
cve(id PK, json, cvss31_base, cvss40_base)
epss(cve PK, epss, percentile, score_date)
kev(cve PK, json)
feeds_meta(feed PK, path, sha256, file_date, rows, loaded_at)
```

Index every FK-like column and `scores.risk`. Upsert findings by `id`; on repeat, only `last_seen` changes. In particular, do not replace the original evidence, first-seen timestamp, or run ownership. Do not add a cross-run association table or migration without the required human-approved ADR.

## 5. CLI

Every command must support `--json` and `--run-id`, with the exit codes above:

```text
vulnassess doctor
vulnassess scan <target> [--tools nmap,nikto]
vulnassess intel refresh [--nvd --epss --kev]
vulnassess intel load --from-dir data/feeds
vulnassess intel status
vulnassess enrich
vulnassess context
vulnassess rank [--weights PATH]
vulnassess explain
vulnassess report --format html --out PATH
vulnassess eval run --truth PATH
vulnassess schema export
```

`intel refresh` is HUMAN-ONLY: **not run by the agent**. Its implementation must print that phrase and include it in its docstring; authoring the command is not permission to execute it.

## 6. Function signatures

These signatures are normative, including parameter names. No implementation is implied by this reference block:

```python
def parse_nmap_xml(path: Path, run_id: str) -> tuple[list[Host], list[Finding]]: ...
def parse_nikto_json(path: Path, run_id: str) -> list[Finding]: ...
def parse_nessus_xml(path: Path, run_id: str, host_ip: str | None = None) -> list[Finding]: ...
def parse_zap_json(path: Path, run_id: str) -> list[Finding]: ...
def run_tool(tool: Tool, target: str, scope: Scope, out_dir: Path) -> Path: ...
def load_feeds(feed_dir: Path, store: Store) -> dict[str, FeedMeta]: ...
def match_finding(f: Finding, store: Store) -> list[Enrichment]: ...
def infer_role(host: Host, rules: RoleRules, llm: LLMClient | None) -> Feature: ...
def infer_exposure(host: Host, scope: Scope) -> tuple[Feature, str | None]: ...
def detect_controls(
    host: Host, findings: list[Finding], sigs: ControlSignatures
) -> dict[str, Feature]: ...
def environmental_vector(
    base_vector: str, profile: ContextProfile, w: Weights
) -> tuple[str, dict[str, str]]: ...
def cvss_score(vector: str) -> float: ...
def risk(
    env_score: float | None,
    epss_percentile: float | None,
    kev: bool,
    native: str | None,
    w: Weights,
) -> tuple[float, float, str | None]: ...
def band(risk_value: float, w: Weights) -> Band: ...
def score(f: Finding, e: Enrichment | None, p: ContextProfile, w: Weights) -> ScoreBreakdown: ...
def rationale(
    f: Finding, p: ContextProfile, s: ScoreBreakdown, client: LLMClient | None, cfg: ExplainConfig
) -> Rationale: ...
```

`run_tool` must raise `ScopeError` before any subprocess for an out-of-scope target. `load_feeds` must name every missing file in `IntelUnavailable`. Exposure inference returns `(exposure, segment)`. `cvss_score` uses the `cvss` package; do not replace it with invented arithmetic. Scoring is pure: no I/O, randomness, LLM, or clock. Only `explain/ollama_client.py` talks to Ollama. The `llm` argument to `infer_role` must not be used to bypass the rationale-only LLM boundary.

## 7. Configuration

`settings.py` must validate configuration at startup. Unknown keys are `ConfigError`. The required settings implementation uses `pydantic-settings`; an unavailable package is a blocker, not permission to silently substitute defaults or another loader.

`scope.yaml` has `allowed_cidrs[]`, `allowed_hosts[]`, `vantage: internal|external`, and `lab_targets[{name, ip, tags{environment?, criticality?, vantage?}}]`. Scope edits need human approval.

`weights.yaml` has this fixed shape and initial values:

```yaml
version: 1
environmental:
  internal_when_av_network: {MAV: A}
  waf_present: {MAC: H}
  auth_required_when_pr_none: {MPR: L}
  role_requirements:
    database: {CR: H, IR: H, AR: H}
    domain_controller: {CR: H, IR: H, AR: H}
    web_frontend: {CR: M, IR: H, AR: H}
    app_server: {CR: M, IR: H, AR: M}
    mail: {CR: H, IR: M, AR: M}
    file_share: {CR: H, IR: M, AR: L}
    iot_embedded: {CR: L, IR: M, AR: M}
    workstation: {CR: M, IR: M, AR: L}
    network_device: {CR: M, IR: H, AR: H}
    unknown: {CR: M, IR: M, AR: M}
  environment_test: {CR: L, IR: L, AR: L}
  criticality_step_above: 3
threat: {base_multiplier: 0.5, epss_weight: 0.5, missing_epss: unscored, kev_floor: 90}
native_fallback: {nessus: {Critical: 80, High: 60, Medium: 40, Low: 20}, zap: {High: 60, Medium: 40, Low: 20, Informational: 5}, nikto: 30, nmap: 25}
bands: {Critical: 80, High: 60, Medium: 35}
```

Every `Role` must appear in `role_requirements`. Each criticality point above `criticality_step_above` raises CR/IR/AR one step (L to M to H). Apply the existing test-environment precedence after role requirements.

`roles.yaml` has `roles.<Role>: [{match: port|service|banner|os, any_of|regex, weight}]` and `ambiguity: {llm_if_top2_within: 0.15, llm_if_max_below: 0.4}`. Those compatibility keys do not permit LLM role inference.

`controls.yaml` has `waf.signatures: [{where: header|cookie|body, regex, vendor}]`, plus `auth_required` and `rate_limiting` patterns. Do not invent scanner signatures as if they had been observed in real captures.

## 8. Invariants

Each invariant must have a test before full acceptance:

- **I1:** Same store and configuration produce byte-identical `rank --json`. Sort findings by id before scoring. Deterministic storage alone is not a ranking test.
- **I2:** Scanner content sent to the LLM is delimited, length-capped, stripped of control characters, and prefixed `untrusted data follows`. Validate the LLM response schema before use.
- **I3:** Every `Feature.evidence` is a verbatim substring of a raw record or exactly `none observed`. Nonblank model validation alone cannot prove this relation to a real capture.
- **I4:** No network in tests; use a socket guard. `httpx`, `requests`, and `urllib` imports are restricted to `intel/feeds.py` and `explain/ollama_client.py`.
- **I5:** `scoring/` imports nothing from `explain/`, `adapters/`, or `intel/feeds`.

## 9. Forbidden shortcuts

None of these may be used to declare completion:

- Weakening or deleting a test to pass; `pytest.skip` or `xfail` except `@needs_fixture`; lowering the coverage threshold.
- `# type: ignore` or `# noqa` without a decision-log entry; catching an exception and continuing silently.
- Inventing tool/feed evidence; claiming verification without quoted command output.

The required gate is Ruff lint, Ruff format, Pyright (package/scripts, strict on scoring and schema), pytest, and at least 95% statement coverage of the whole `vulnassess` package per decision QA-95-01 (2026-10-10), superseding APPLY-02's prototype floor. Missing prerequisites must be reported and never downloaded to force a green result. Coverage is not model accuracy or proof of live integration.
