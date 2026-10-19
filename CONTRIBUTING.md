# Contributing to VulnAssess

VulnAssess is a local-first vulnerability-prioritisation prototype. It reads reviewed
Nmap, Nikto and ZAP output, enriches findings from offline NVD, EPSS and CISA KEV
snapshots, infers deployment context, and produces an evidence-backed queue.

## Setup

Use Python 3.11 or newer and install the pinned project dependencies:

```text
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

Run the complete local quality gate before opening a change:

```text
python scripts/check.py
```

Run the synthetic demonstration and open the local workbench:

```text
python run_demo.py
python -m vulnassess ui --run demo --port 8765
```

## Boundaries

- Work only with targets listed in `config/scope.yaml`.
- Scanner execution requires an explicit human `--execute` decision.
- Keep raw scanner exports and feed snapshots out of Git; use the documented fixture
  process for reviewed examples.
- Do not change canonical scores from UI or local-model output. The deterministic score,
  evidence quote, configuration hash and feed provenance must remain inspectable.
- Treat scanner content and model content as untrusted input.
- Mark synthetic demonstrations as synthetic and never use them as expert validation.

## Useful references

- [Problem statement](docs/problem-statement.md)
- [Methodology](docs/methodology.md)
- [Architecture and design](docs/DESIGN.md)
- [Contracts](docs/contracts.md)
- [Security boundary](docs/security.md)
- [Scanner fixture guide](docs/fixtures.md)
- [Scan format reference](docs/SCAN_FORMAT_REFERENCE.md)
- [UI contract](docs/ui-contract.md)
