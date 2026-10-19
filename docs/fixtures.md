# Human fixture capture guide

Status: capture procedure, not captured evidence. These commands are **not run by the agent**.
They support PROJECT stages 3 (safe scanning), 4 (unified results) and 6 (intelligence).
The capture owner can be assigned later; no command, path or test depends on their name.
Dependencies, scanner images, lab startup and egress controls must already be human-approved.
Nothing here authorises downloads, image builds, new scan targets or production access.

## Scope and prerequisites

The explicit targets in [config/scope.yaml](../config/scope.yaml) are:

| Name | Authorised IP | Planned baseline HTTP endpoint |
| --- | --- | --- |
| metasploitable2 | 172.28.0.10 | `http://172.28.0.10/` |
| dvwa | 172.28.0.11 | `http://172.28.0.11/` |
| juice-shop | 172.28.0.12 | `http://172.28.0.12:3000/` |

The endpoint ports are capture-profile assumptions, not observed service claims. Confirm them from
the actual lab configuration and Nmap capture before the corresponding ZAP run. If a service is
absent or different, stop that path and record the discrepancy; do not create sample output.
Do not scan the whole subnet. 172.28.0.250 is a canary, not an authorised target.

Before any scan, a human must independently verify that the scanning host/container can contact
only the intended target and that internet/canary traffic is denied and logged. An existing Docker
network is not an egress policy. Spiders can encounter redirects or links outside scope; the network
fence must refuse them. Do not treat the absence of a log as proof of zero traffic.
These are bounded lab baselines, not a guarantee of zero impact or full attack-surface coverage.

Run the following from the repository root in PowerShell. The image ID and network name are
non-secret values from the approved local lab record, supplied by the human; there are no defaults.

```powershell
Write-Output 'Human-only prerequisite checks: not run by the agent'
foreach ($name in @('nmap', 'docker')) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "MISSING: approved local command $name"
    }
}
if ($env:VULNASSESS_ZAP_IMAGE_ID -notmatch '^sha256:[a-fA-F0-9]{64}$') {
    throw 'MISSING: VULNASSESS_ZAP_IMAGE_ID from the reviewed local image record'
}
if ([string]::IsNullOrWhiteSpace($env:VULNASSESS_LAB_NETWORK)) {
    throw 'MISSING: VULNASSESS_LAB_NETWORK from the approved lab configuration'
}
docker image inspect $env:VULNASSESS_ZAP_IMAGE_ID --format '{{.Id}}'
if ($LASTEXITCODE -ne 0) { throw 'MISSING: reviewed local ZAP image' }
docker network inspect $env:VULNASSESS_LAB_NETWORK --format '{{.Name}}'
if ($LASTEXITCODE -ne 0) { throw 'MISSING: approved existing lab network' }
New-Item -ItemType Directory -Force tests/fixtures/nmap, tests/fixtures/zap | Out-Null
$ZapOutput = (Resolve-Path tests/fixtures/zap).Path
nmap --version
docker run --rm --pull=never --network none $env:VULNASSESS_ZAP_IMAGE_ID zap.sh -version
```

Record the actual Nmap/ZAP versions, image ID, command receipts and network restrictions. If the
approved image does not supply `zap-baseline.py` or `zap.sh`, stop with that missing command; do not
substitute a registry tag or let a tool install add-ons. A hash comparison is not security approval.
Existing captures must not be overwritten without the owner's review; preserve the previous raw
artifact in ignored storage and record replacements and redactions explicitly.

## Nmap: exact commands

These TCP connect/version probes use no NSE scripts, OS fingerprinting, UDP scanning, DNS lookups
or subnet discovery. The port set is deliberately limited and includes the planned Juice Shop port.
`--host-timeout` can leave an incomplete capture; inspect the run status before treating it as usable.
Do not interpret a missing service in this limited scan as proof of absence.

```powershell
Write-Output 'Human-only Nmap captures: not run by the agent'
nmap -n -Pn -sT -sV --version-light -T2 --max-retries 1 --host-timeout 180s -p 21,22,23,25,53,80,88,110,135,139,143,389,443,445,465,587,636,993,995,1433,2049,3000,3306,5432,6379,8080,8443,27017 -oX tests/fixtures/nmap/metasploitable2.xml 172.28.0.10
# Record exit code and run completion before proceeding.
nmap -n -Pn -sT -sV --version-light -T2 --max-retries 1 --host-timeout 180s -p 21,22,23,25,53,80,88,110,135,139,143,389,443,445,465,587,636,993,995,1433,2049,3000,3306,5432,6379,8080,8443,27017 -oX tests/fixtures/nmap/dvwa.xml 172.28.0.11
# Record exit code and run completion before proceeding.
nmap -n -Pn -sT -sV --version-light -T2 --max-retries 1 --host-timeout 180s -p 21,22,23,25,53,80,88,110,135,139,143,389,443,445,465,587,636,993,995,1433,2049,3000,3306,5432,6379,8080,8443,27017 -oX tests/fixtures/nmap/juice-shop.xml 172.28.0.12
```

## ZAP: exact commands

Use the confirmed HTTP endpoints and the approved, already-present image. `--pull=never` prevents
implicit image fetching; it does not constrain HTTP destinations. Baseline mode spiders and applies
passive rules, not a full active scan. It is unauthenticated; do not infer authenticated coverage.
The time budgets below are scanner options, not proof that the surrounding process cannot hang.
Do not add Ajax spiders or credential handling to these commands without a separate review.

```powershell
Write-Output 'Human-only ZAP baseline captures: not run by the agent'
docker run --rm --pull=never --network $env:VULNASSESS_LAB_NETWORK --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=$ZapOutput,target=/zap/wrk" $env:VULNASSESS_ZAP_IMAGE_ID zap-baseline.py -t http://172.28.0.10/ -m 1 -T 3 -J metasploitable2.json
# Record the result, scanner output and exit code before proceeding.
docker run --rm --pull=never --network $env:VULNASSESS_LAB_NETWORK --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=$ZapOutput,target=/zap/wrk" $env:VULNASSESS_ZAP_IMAGE_ID zap-baseline.py -t http://172.28.0.11/ -m 1 -T 3 -J dvwa.json
# Record the result, scanner output and exit code before proceeding.
docker run --rm --pull=never --network $env:VULNASSESS_LAB_NETWORK --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=$ZapOutput,target=/zap/wrk" $env:VULNASSESS_ZAP_IMAGE_ID zap-baseline.py -t http://172.28.0.12:3000/ -m 1 -T 3 -J juice-shop.json
```

The mounted outputs go to `tests/fixtures/zap/`. Baseline findings may yield a nonzero status;
record and interpret the actual script's result (including timeout/configuration failures) rather
than treating every nonzero code as a successful capture or suppressing errors. An absent or empty
JSON file is not an empty scan. Preserve stdout/stderr privately if they contain sensitive material.

## README template

Create `tests/fixtures/nmap/README.md` and `tests/fixtures/zap/README.md`, with one completed entry
per artifact. This is an unfilled template, not a capture or approval record:

```markdown
## <actual artifact filename>

- Capture date/time (UTC): <actual ISO-8601 timestamp>
- Captured by: <actual person or approved pseudonym>
- Target: <exact IP, port/URL and lab target name>
- Tool and version: <actual version output; ZAP image ID if applicable>
- Command: <exact command that ran, with non-secret variables resolved>
- Exit code and completion state: <observed result, timeout/error if any>
- Vantage: <actual scanning host/container and independently verified vantage>
- Scope/configuration reference: <reviewed scope revision or content hash>
- Raw artifact SHA-256: <hash computed from the actual file>
- Network fence and canary evidence: <location of the actual reviewed records>
- Coverage limits: <ports, authentication, passive-only, time limits>
- Redactions/transformations: <what changed and why, or none>
- Original artifact location: <private ignored location if the committed file was redacted>
```

Do not put credentials, production identifiers, session cookies or full feeds in a fixture commit.
Preserve genuine evidence and its provenance through any reviewed redaction; never replace it with
an imagined banner or an invented CVE/EPSS value. Golden parser snapshots may be generated only
after reviewing these captures; their expected values must trace back to actual records.

## Fixture-dependent tests

Mark tests with `@needs_fixture` (an alias for `pytest.mark.needs_fixture`) and repository-relative
paths to both the capture and its README. Missing files skip only those tests with the exact reason
`fixture not provided: <path>`. Existing-but-malformed files must fail parser validation, not skip.
The marker never permits skipping ordinary logic, gate or missing-package failures.

```python
needs_fixture = pytest.mark.needs_fixture


@needs_fixture(
    "tests/fixtures/nmap/metasploitable2.xml",
    "tests/fixtures/nmap/README.md",
)
def test_real_nmap_capture():
    # Import and exercise the implemented parser here; assert against reviewed golden data.
    ...
```

This snippet is a test-authoring template, not a passing parser test. No placeholder capture is
created by the marker. Every increment must inventory and list still-missing paths:

- `tests/fixtures/nmap/metasploitable2.xml`
- `tests/fixtures/nmap/dvwa.xml`
- `tests/fixtures/nmap/juice-shop.xml`
- `tests/fixtures/nmap/README.md`
- `tests/fixtures/zap/metasploitable2.json`
- `tests/fixtures/zap/dvwa.json`
- `tests/fixtures/zap/juice-shop.json`
- `tests/fixtures/zap/README.md`

Human-provided dated intelligence subsets and their README belong under `tests/fixtures/intel/`;
full working snapshots stay in ignored `data/feeds/`. Exact feed filenames/schema are a separate
reviewed ingestion contract, not guessed here. Human expert judgments stay in ignored study data;
committed truth examples must be explicitly synthetic pure-logic tests, never evidence of evaluation.

## Reader acceptance and snapshots

The Nmap reader requires a completed `nmaprun` capture with scan timestamps and a successful
`runstats/finished` record. Open ports are observations, not proof of a vulnerability; script
findings carry only explicitly reported identifiers. XML entity declarations and external DTDs
are refused. The ZAP reader targets traditional `-J` JSON with `@generated`, `site` and `alerts`;
sites must contain numeric IPs, not hostnames requiring DNS. Missing or malformed metadata is an
error. A ZAP timestamp without a timezone remains without a timezone; it is not relabelled UTC.

Neither reader runs a scanner, enriches findings, scores them, or persists them. A scope-validated
import workflow is still required before persistence. The 16 MiB file ceiling, XML depth of 128
and 200,000-element ceiling are defensive parser limits, not evidence of host-level isolation.
Network-share paths are rejected; a mapped drive or malicious local filesystem still requires
the independently enforced isolation described above. Raw excerpts retain at most 2048 characters.

After reviewing a real capture, create its expected snapshot under `tests/golden/nmap/<name>.json`
or `tests/golden/zap/<name>.json`. Do not generate expected data without a source capture or blindly
approve parser-produced values. Nmap snapshots contain `hosts` and `findings`; ZAP snapshots are
finding arrays. Use `capture-test` as the test run ID and repository-relative provenance paths such
as `tests/fixtures/nmap/dvwa.xml`. The tests normalize only the machine-dependent raw file path;
all remaining fields must match the reviewed output. Missing real captures skip via @needs_fixture;
a supplied capture without its reviewed snapshot fails rather than inventing expected values.

## Usable schema command

With the already-reviewed Python environment, export the nine model definitions without any
capture, intelligence feed or model. From this repository root, no installation is required:

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
python3.12 -m vulnassess schema export --json --run-id manual-check
```

This exports JSON Schema only; it is not a vulnerability report or an assessment run. Without
`--run-id`, the export does not invent a run or timestamp. The original stage commands remain
scaffold commands until their input validation and stage integration are implemented.
