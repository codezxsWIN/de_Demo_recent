# VulnAssess — Session Chronicle & Handoff

**Scope of this document:** everything that happened across the working sessions
covered by commits `c88e822 → 03de4fd` on branch `audit-no-assumptions`
(2026-09-17 → 2026-09-18), written so that a person or agent with knowledge of
the *pre-session* repository can understand what changed, why, what was
learned the hard way, and what to do next. The operational continuation plan
lives in [`HANDOFF.md`](HANDOFF.md); this document is the full narrative and
the evidence ledger behind it.

---

## 0. TL;DR

The session took the repository from **"a real engine wrapped in paperwork,
never run against anything real"** to **"a real engine, proven against real
public data and real scanner output, gate-enforced in CI, presented through a
separate demo and a hardened UI."** Specifically:

- ~50% narrative bloat deleted (`legacy/`, `project-starter-kit/`, two false
  "provisioning complete" manifests).
- Real offline intel provisioned: **NVD 376,424 / EPSS 375,610 / KEV 1,713
  records**, with fetchers, provenance, and a committed test subset.
- The advertised-but-never-run quality gate made real: 57 pyright errors
  fixed, ruff pinned, formatter applied, **CI added** — gate green at 233
  tests / 87.6% coverage.
- **Real Nmap scans executed** through the tool's own `scan --execute` against
  a live lab (loopback-bound), which immediately exposed and fixed a real
  reader bug (real Nmap XML was unparseable). Two real captures committed as
  fixtures.
- One genuine security incident on the operator machine (a deliberately
  vulnerable app briefly bound to all interfaces) — closed, root-caused, and
  turned into standing rules.
- A **separate demo repository** created (Streamlit + self-contained HTML
  exports) for presenting progress.
- The UI's Risk stage upgraded twice (UI-18, UI-19): threat hero strip, EPSS ×
  CVSS quadrant map, risk-formation waterfall, and a **formation engine**
  (animated gauge + beam-flow diagram) — all rendering stored values only,
  all motion reduced-motion-safe, all exports CSP-rehashed.

Everything is committed on `audit-no-assumptions` and pushed to
`https://github.com/codezxsWIN/privwork` (this branch is the remote's default).

---

## 1. Starting point: the honest assessment

The session began with a request for a brutally honest verdict on the
repository. The assessment, since it drove every later decision:

**What was real.** A ~9,700-line stdlib-only package (`vulnassess/`) with
essentially zero stubs: a from-scratch CVSS v3.1 engine tested against the
official calculator, deterministic scoring (`risk = environmental × 10 ×
threat`) driven by a hashed `config/weights.yaml`, readers for Nmap/Nikto/ZAP,
offline intel matching with accept/reject traces, evidence-first context
inference (every inferred fact carries a confidence, a source, and a verbatim
scan quote), a shadow-only role model, and ~237 tests with unusual honesty
(`test_kev_never_lowers_risk`, network access forbidden via socket
monkeypatch, evidence labels `VERIFIED / TESTED WITH MOCKS / NOT RUN /
MISSING`).

**What was hollow.**

1. **It had never seen real data.** `DOWNLOADS_REQUIRED.txt` marked everything
   `[MISSING]`: no scanner captures, no feeds, no expert rankings, no Ollama.
   The role model was trained on synthetic data the project generated about
   itself. Every research claim (RQ1–RQ4) was ineligible.
2. **The quality gate had never actually run.** `.github/` held only a
   Copilot-instructions file; Ruff/Pyright were listed as MISSING in the
   checklist.
3. **The provisioning docs were the biggest red flag.**
   `PROJECT_PROVISIONING_COMPLETE.md` declared the project "FULLY PROVISIONED
   & READY" and claimed pip-installed feeds that the project's own charter
   (`copilot-instructions.md` §0b) forbade an agent from installing — and the
   artifacts existed nowhere in the repo.
4. **~50% of the repo by volume was narrative**: `legacy/` (a complete
   superseded pydantic/typer duplicate), `project-starter-kit/` (a duplicate
   mini-repo containing a paste-into-Copilot `PROMPT.md`), fixture guides at
   the root, and the two ✅-laden provisioning manifests.

**The verdict given:** a first-time cybersecurity viewer would not like it —
not because the engine was weak, but because the repo talked about the project
more than it *showed* it. The user's own words — "its become slop and over
engineered" — were confirmed, with the precision that the *engine* was good
and the *packaging and evidence* were not.

**The mandate that followed:** the user could not supply real data themselves
and asked for everything that *could* be fixed to be fixed, with the agent
using its full capabilities — and later, to run the tools locally, build a
separate showcase, and upgrade the UI.

---

## 2. Commit timeline

| Commit | What it delivered |
| --- | --- |
| `c88e822` | Repository simplification (CLEANUP-01), real feed provisioning (FEED-01), CI (CI-01), 57 pyright fixes, explicit ruff config, formatted tree, self-provisioning UI tests (TEST-01), rewritten README, updated `DOWNLOADS_REQUIRED.txt` |
| `6f4e323` | First real Nmap captures (SCAN-02) + the reader DOCTYPE fix (SCAN-01) |
| `aa93ee6` | `docs/HANDOFF.md` — old→new state map, machine state, phased continuation plan |
| `6ff60a3` | UI-18: risk-stage analytics (threat strip, quadrant map, waterfall, motion layer) + 6 new UI tests |
| `03de4fd` | UI-19: formation engine (risk dial + beam flow), hero band meter, upgraded quadrant |
| *(this commit)* | `docs/PROJECT_JOURNEY_AND_HANDOFF.md` (this file) |

In the separate demo repository `C:\Users\aksha\Downloads\vulnassess-demo`:
`2c0ad7a` (Streamlit showcase), `002adcc` (self-contained HTML exports),
`c46b039` (exports regenerated with UI-19).

---

## 3. Phase chronicle

### Phase A — De-slop (CLEANUP-01)

Deleted: `legacy/` (superseded pydantic/typer prototype), `project-starter-kit/`
(including the paste-into-Copilot `PROMPT.md`), `PROJECT_PROVISIONING_COMPLETE.md`,
`PROVISIONING_SUMMARY.md`. Moved `SCAN_FORMAT_REFERENCE.md`,
`FIXTURE_CREATION_GUIDE.md`, `FIXTURE_INTEGRATION_GUIDE.md` into `docs/`.
Retained `project-starter-kit/docs/DESIGN.md` as `docs/DESIGN.md` because three
documents cite it. All dangling links repaired; every deletion recorded in
`docs/decisions.md` (CLEANUP-01) with rationale and supersession of BUILD-01's
"moved, not deleted" rule — git history itself is the archive.

### Phase B — Real feeds (FEED-01, FEED-02)

The loader (`vulnassess/intel.py`) expects three offline snapshots. All three
were fetched **from the official publishers** on 2026-09-17 at the owner's
explicit instruction, by rate-limited resumable scripts now living in
`scripts/` (`fetch_feeds.py`, `fetch_nvd.py` — note: not under `data/`, which
is gitignored):

- **CISA KEV** — 1,713 exploited CVEs (`dateReleased` 2026-09-16).
- **EPSS** — 375,610 scored CVEs (score date 2026-09-17), from
  `epss.cyentia.com`.
- **NVD** — a full API 2.0 mirror: 194 pages × 2,000 records, one request per
  ~7 s (inside the public no-key quota), retries with backoff, resumable →
  **376,424 CVE records** loaded.

Provenance (URL, fetch date, SHA-256, row counts) recorded in
`docs/FEED_PROVENANCE.md` and `data/feeds/PROVENANCE.md`. A curated committed
subset (Log4Shell, Shellshock, EternalBlue — full NVD records incl. CPE
configurations, the matching EPSS rows, the matching KEV entries) lives in
`tests/fixtures/intel/` with `PROVENANCE.md`, and `tests/test_real_intel.py`
proves the loader, matcher, and scoring accept the official formats inside CI
without downloading gigabytes. The honesty boundary was kept explicit: real
*feed* data is not real *scan* evidence, and RQ1–RQ4 remained NOT RUN.

### Phase C — Making the gate real (CI-01)

The gate (`make check` / `scripts/check.py`: ruff lint, ruff format, pyright,
pytest with ≥75% coverage) had never been run. Consequences found and fixed:

- **Ruff**: ruff ≥0.16 broadened its implicit defaults — 83 style findings
  appeared on code that never had a lint config. Resolution: an explicit,
  version-stable ruleset in `pyproject.toml` (`select = ["E4","E7","E9","F","I"]`,
  line-length 100) rather than chasing style noise; the 16 real findings
  (unused/unsorted imports, empty f-string) auto-fixed; the whole tree
  formatted once.
- **Pyright: 57 errors**, including a genuine latent crash: `rescan.py`'s
  `_newer_version()` would raise `AttributeError` when a service was missing
  from a capture. Fixes: `evaluate()` widened to `Mapping` (covariant), a
  `Weights = dict[str, Any]` alias in `scoring.py` with `cast()` naming the
  handled YAML shapes, covariant `AbstractSet[str]` for the settings validator,
  Optional-guards in `ui/` and `report.py`, and `dataclasses.replace` replacing
  an untyped dict-repack. Charter mapping applied: standard mode on the
  package, **strict mode on `scoring.py` and `schema.py`** (the charter's
  "strict on scoring/ and schema/"), tests out of scope per the charter's own
  gate definition.
- **CI added**: `.github/workflows/ci.yml` — the same four gate stages on
  Python 3.11 and 3.12, dependencies pinned to the versions that pass locally
  (pyyaml 6.0.3, packaging 24.2, pytest 9.1.1, pytest-cov 7.1.0, ruff 0.16.6,
  pyright 1.1.411).

### Phase D — UI tests made reproducible (TEST-01)

18 `tests/test_ui.py` failures on a fresh clone: the UI contracts required a
gitignored `data/vulnassess.db` containing a run literally named `verify`,
which nothing in the repository could build (author workspace state, now lost).
`setUpModule` now self-provisions: it runs `run_demo.py`'s pipeline when the
database is absent and inserts a `verify` runs-table row (mirroring how the
contract test itself creates `synthetic_ui_other`). `DEMO_RUN` changed from
`verify` to `demo`. Findings are content-addressed across runs, so a runs-row
copy is sufficient for the contracts.

**First full gate result: 233 passed + 342 subtests, 87.61% coverage, pyright
0 errors (0 warnings), ruff clean — GATE PASSED.**

### Phase E — Real feeds end-to-end (DEMO-01)

`run_real_demo.py` + `examples/real_lab_nmap.xml` (hand-built lab capture,
clearly labelled: invented hosts, real CVE evidence) run the pipeline over the
real feeds in one command. The README's hypothesis table became real:
**CVE-2021-44228 (Log4Shell) on the internet-facing host ranks 100.0
Critical; CVE-2014-6271 (Shellshock) on the internal test host ranks 79.0
High** — the "actively exploited flaw on an isolated test box lands in High,
not Critical" rule, demonstrated with real enrichment.

### Phase F — Real scans on this machine (SCAN-01, SCAN-02)

Environment inventory first: no Nmap, Nikto, ZAP, Java, Docker, Ollama, or WSL
on the operator machine (the old checklist described a different machine).
winget available; Hyper-V present. The no-VM plan:

1. **Nmap 7.80** installed via winget (owner-approved UAC), `vulners.nse`
   (official vulnersCom script) copied into Nmap's scripts dir (UAC).
2. **Loopback lab**: 172.28.0.10/.11/.12 bound to "Loopback Pseudo-Interface 1"
   via elevated `netsh` (UAC) — matching `config/scope.yaml` exactly, canary
   .250 unbound. Loopback traffic never leaves the machine.
3. **Targets**: OWASP Juice Shop 20.2.0 portable zip (md5-verified) with
   portable Node v22.21.1 on 172.28.0.12:3000; Python's own `http.server`
   (banner `SimpleHTTP/0.6 Python/3.12.10`) on 172.28.0.10:8000 (moved from
   7080 — not in Nmap's default top-1000 port list, an honest lesson).
4. **Scans**: `vulnassess scan --run-id … --tool nmap --canary-log
   data/lab/canary.log --out-dir data/captures --execute` — canary log supplied
   and empty before/after; both captures succeeded (exit 0).

**The reader bug (SCAN-01).** The first real execution failed at parse:
`DTD and entity declarations are forbidden`. Real Nmap always writes a bare
`<!DOCTYPE nmaprun>` header; the synthetic fixtures never did, so the reader —
which blanket-rejected any DOCTYPE — had never accepted genuine Nmap output.
Fix: reject `<!ENTITY` declarations and any DOCTYPE carrying an internal
subset; accept a bare (or SYSTEM-id) DOCTYPE, which `xml.etree.ElementTree`
neither fetches nor expands. Security tests cover all three cases (entity
rejection, internal-subset rejection, bare-header acceptance). This is the
session's clearest demonstration of "real data finds real bugs".

**The honest zero.** Keyless vulners named nothing vulnerable (patched Windows
host; Juice Shop strips its banner; SimpleHTTP carries no CPE), so both
captures contain **zero explicit CVE evidence** — recorded as such. The
pipeline still imported the hosts/services, inferred context from real
evidence (`172.28.0.10 | role: file_share 0.8 | evidence: "445/tcp
microsoft-ds"`), and produced an honest empty ranked queue. Both captures are
committed under `tests/fixtures/nmap/` with provenance rows and parsing tests
(`tests/test_real_captures.py`).

### Phase G — The security incident (post-mortem)

**What happened.** During lab bring-up, Juice Shop was started expecting a
bind to 172.28.0.12:3000. Its code calls `server.listen(port)` with **no host
argument** — `--host` is silently ignored — so the deliberately vulnerable app
listened on `0.0.0.0:3000` and `[::]:3000` (all interfaces, including the LAN)
for approximately 25 minutes. The user flagged the risk; the process was
killed immediately.

**Root cause & fix.** The bind was patched in the lab copy
(`build/server.js`: `server.listen(port, "172.28.0.12", …)`) making external
reachability structurally impossible; verified via `netstat -ano` showing the
only listener as `172.28.0.12:3000`. Windows Firewall's default inbound-deny
likely blocked outside access during the exposure window, but the fix does not
depend on it.

**Standing rules derived.** (1) After starting any listener, `netstat -ano |
grep LISTEN` and confirm the bind address before proceeding. (2) Never trust
an app's `--host` flag; verify or patch the bind. (3) Lab copies get their
flaky outbound startup probes short-circuited
(`build/lib/startup/validatePreconditions.js` returns false immediately) so
startup is deterministic. (4) All servers (UI on 8765, Streamlit on 8601,
temp file servers) bind loopback only.

Also learned: Juice Shop's first-run SQLite can stall after a killed run —
delete `data/juiceshop.sqlite*` and restart; port 7080 isn't in Nmap's default
top-1000 — pick ports from that list.

### Phase H — The separate showcase (user request: "a proper smaller
simulation")

Built as a genuinely separate repository `vulnassess-demo` (own git) so the
main project stays clean:

- **`prepare_data.py`** rebuilds `data/demo.db` by calling the production CLI
  (`intel load → import → enrich → context → rank`) over three labelled
  sources: the two real captures (`scan-juiceshop`, `scan-windows`) and the
  acceptance capture (`acceptance-lab`, real feeds + invented hosts).
- **`app.py`** (Streamlit, six tabs): implementation status board; real feed
  metrics; real captures with services/banners; context inference with
  verbatim quotes; the ranked queue; and a **live risk sandbox** that calls
  the production `scoring.environmental_vector()`/`scoring.risk()` with real
  CVE lookup from the local snapshots.
- Server discipline: first launch bound all interfaces — killed and relaunched
  with `--server.address 127.0.0.1` (the Juice Shop lesson applied instantly).
- **Self-hosted pivot**: the user wanted self-hosted; the project's own
  four-stage workbench already exported as a single self-contained HTML file
  (CSP hash-pinned, zero external assets, offline). Both runs were exported to
  `standalone/*.html` and verified in-browser (four stages render, sandbox
  arithmetic embedded with Python-parity fixture, guarded fetches never fire).

### Phase I — The UI upgrades (UI-18, UI-19)

The user opened the main UI, found it "a bit lame", and asked for
professional, animated additions **without taking anything away**.

**Research.** Professional threat-prioritization surfaces converge on: the
EPSS × CVSS quadrant framing (Brinqa, Cloudsmith), exploit-intelligence
overlays and KEV trend exploration (CISA/Phoenix Security), decision-first SOC
dashboard design (Activu), and remediation-funnel/waterfall storytelling.
Synthesis: add a quadrant map, a risk-formation waterfall, a threat
intelligence strip, and workflow-aligned motion — all fed from stored values.

**UI-18 (take 1).** Server-rendered additions to the Risk stage: threat strip
(animated count-ups), quadrant map (stored CVSS base vs stored EPSS percentile
with an honest "no EPSS row" lane), risk waterfall (the stored arithmetic
formation), and a reveal/motion layer. Six new UI tests; gate green; in-page
sandbox self-check: **211/211 CVSS vectors and 144/144 sandbox cases match
Python**.

**UI-19 (take 2).** The user judged take 1 too timid ("looks garbage… try
again"). The rebuild: the strip became a **hero** with a band-composition
meter; the quadrant doubled in size with **danger/watch zone gradients,
crosshair guides, drop-in point animation, and pulsing KEV rings**; and the
new **formation engine** — a 240° risk **gauge** (stroke-dashoffset driven by
a CSS variable set on reveal; verified animating 0→100 in-browser) beside a
four-station **beam diagram** (BASE → CONTEXT → THREAT → RISK with flowing
dashed connectors), plus the ledger waterfall with a bold result row. Every
value remains store-read; the sandbox remains the only arithmetic surface;
`prefers-reduced-motion` disables all of it; exports re-hash their CSP.

**Verification across both takes:** full gate green (lint/format/pyright incl.
strict modules/coverage ≥75%), 55 UI tests, live in-browser checks
(screenshots, dial animation state, sandbox self-check).

---

## 4. Evidence ledger (what is real, what is not — current state)

| Claim | Evidence | Status |
| --- | --- | --- |
| Feed data is real | `docs/FEED_PROVENANCE.md`, loader hashes, CISA/Cyentia/NIST sources | VERIFIED |
| Reader accepts real Nmap XML | Two real captures committed + `tests/test_real_captures.py` | VERIFIED |
| Scans were executed via the tool | `scan --execute` summaries, canary log empty, provenance rows | VERIFIED (loopback lab, owner-authorized) |
| Zero explicit CVE findings in captures | Keyless vulners output; honest empty queue | STATED HONESTLY |
| Gate green | `scripts/check.py` GATE PASSED; CI workflow present | VERIFIED locally; CI to be observed on push |
| Browser arithmetic matches Python | In-page self-check 211/211 + 144/144 | VERIFIED |
| RQ1–RQ4 research outcomes | No expert rankings/labels/context truth yet | NOT RUN (unchanged) |
| Role model | Synthetic labels, shadow-only | Unchanged by design |

## 5. Machine state (not in any repo)

- Windows 11, Python 3.12.10; gate tools: ruff 0.16.6, pyright 1.1.411,
  pytest 9.1.1, pytest-cov 7.1.0 (CI pins these); streamlit 1.61.0.
- Broken local `hypothesis` pytest plugin (Windows App Control blocks its
  native DLL) — NOT a project dependency; run tests locally with
  `-p no:hypothesispytest`. CI unaffected.
- Nmap 7.80 + `vulners.nse` (keyless). Free API key at `~/.nmap/vulners.key`
  unlocks CVE-level findings.
- Loopback aliases 172.28.0.10/.11/.12 (removal commands in HANDOFF.md §3).
- Lab under gitignored `data/lab/`: patched Juice Shop 20.2.0, portable Node
  22, empty canary log. UI server may still be running on 127.0.0.1:8765;
  Streamlit on 127.0.0.1:8601.

## 6. What was intentionally NOT done

- No push to `main` (the remote's default branch is `audit-no-assumptions`;
  pushes are fast-forwards to it).
- No pip installs into the project runtime (two runtime deps unchanged:
  `pyyaml`, `packaging`); dev tools pinned only in CI.
- No CVSS v4.0, no PDF export, no pre-commit (deferred by prior decisions).
- No research claims: expert rankings, role-model labels, and independent
  context truth remain human-only prerequisites.
- No weakening of the reader's security checks or the scope fence; the DOCTYPE
  allowlist was widened narrowly and testably (SCAN-01).

## 7. Handoff

The operational plan lives in [`HANDOFF.md`](HANDOFF.md) (phases 0–5 with
acceptance criteria). Immediate next actions, in order:

1. **Observe CI** on GitHub for the pushed commits; align pins if the runners
   drift from the local-passing set.
2. **Phase 1 unlock**: a free Vulners API key in `~/.nmap/vulners.key`, then a
   rescan — the first real CVE-level findings flow through enrich → rank →
   report, and the formation engine/quadrant immediately get live data.
3. **Phase 2**: ZAP (Temurin JRE via winget) for real web-scanner evidence;
   commit under `tests/fixtures/zap/` with provenance.
4. **Phase 3**: Ollama + one model for rationale rewording (scores provably
   unchanged).
5. **Phase 4**: the human research inputs (expert rankings, role labels,
   context truth) — the only path that turns RQ1–RQ4 from NOT RUN into
   decisions.
6. **Demo upkeep**: after any pipeline change, `python prepare_data.py` and
   re-export `standalone/*.html` (commands in the demo repo README).

**Standing don'ts** (repeat offenders in this repo's history): no
"provisioning complete" style manifests — status lives in
`DOWNLOADS_REQUIRED.txt` and the evidence ladder; never loosen a security
check to make a file parse — extend the allowlist narrowly with a test; never
let anything bind non-loopback without an explicit reason and a netstat
check; never let presentation arithmetic leak into the store.

---

*End of chronicle. The engine is the same engine — but it has now been
proven against the real world, enforced by CI, and shown in a UI that
demonstrates rather than claims.*
