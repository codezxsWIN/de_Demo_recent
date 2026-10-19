# How to Run VulnAssess

This guide starts from a fresh clone of `privwork` and runs the synthetic local
demonstration. The synthetic inputs are labelled clearly in the UI; they are for
demonstrating the workflow and are not evidence of production accuracy.

## Requirements

- Python 3.11 or newer
- Git
- A modern web browser
- Windows PowerShell, macOS Terminal, or Linux shell

The basic UI does not require Nmap, Nikto, OWASP ZAP, Ollama, or downloaded
vulnerability feeds. Those are only needed for the optional workflows described
below.

## Install

Clone the repository and enter its directory:

```text
git clone https://github.com/codezxsWIN/privwork.git
cd privwork
```

Create and activate a virtual environment.

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the runtime dependencies and the local package:

```text
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

The editable install makes the `vulnassess` command available. The commands in
this guide use `python -m vulnassess`, which also works directly from the
repository root.

## Run The Synthetic Demo

Generate the local SQLite assessment and HTML report:

```text
python run_demo.py
```

Start the read-only local workbench:

```text
python -m vulnassess ui --run demo --port 8765
```

Open this address in your browser:

```text
http://127.0.0.1:8765/
```

Keep the terminal running while using the UI. Press `Ctrl+C` to stop it.

The workbench presents four connected stages:

1. Evidence: imported scanner observations and provenance.
2. Context: host role, exposure, environment, and supporting evidence.
3. Risk: deterministic environmental and threat scoring.
4. Priorities: the remediation queue and comparison against CVSS-only order.

## Export An Offline UI

To generate a self-contained HTML version of the synthetic workbench:

```text
python run_visual_simulation.py
```

The output is written to:

```text
reports/visual-simulation.html
```

This export does not need a running server and can be opened directly in a
browser.

## Run The Test Suite

Run the full automated suite:

```text
python -m pytest -q
```

Run the repository quality gate when making code changes:

```text
python scripts/check.py
```

## Optional Real-Feed Demonstration

The real-feed lab demonstration requires locally fetched public feeds. Fetch
them first:

```text
python scripts/fetch_feeds.py
```

Then run the demonstration against the committed, hand-built lab capture:

```text
python run_real_demo.py
```

This workflow uses local feed snapshots after they are fetched. It does not
scan a target by itself.

## Optional Local Model

Ollama can provide local analyst wording for an explicitly requested target.
It is not required for deterministic scoring or for viewing the workbench.

Install Ollama separately, pull the approved model, and then start the UI with:

```text
ollama pull llama3.2:3b
python -m vulnassess ui --run demo --model llama3.2:3b --port 8765
```

The local model is constrained to explanation. It does not replace the
deterministic score, invent evidence, or rewrite canonical findings.

## Optional Scanner Workflows

Real scanning is restricted to authorised targets listed in
`config/scope.yaml`. Scanner execution requires an explicit human decision and
the project safety checks.

The optional tools are:

- Nmap for network discovery
- Nikto for web-server checks
- OWASP ZAP for web application checks

Do not scan systems without written authorisation. Review
`docs/security.md`, `docs/fixtures.md`, and `DOWNLOADS_REQUIRED.txt` before
using scanner commands.

## Troubleshooting

### `MISSING: SQLite database`

The database is generated locally and intentionally is not committed. Run:

```text
python run_demo.py
```

Then start the UI again.

### `No module named yaml` or `No module named packaging`

Activate the virtual environment and reinstall the runtime dependencies:

```text
python -m pip install -r requirements.txt
```

### Port 8765 is already in use

Choose another local port:

```text
python -m vulnassess ui --run demo --port 8766
```

Then open `http://127.0.0.1:8766/`.

### The browser cannot connect

Confirm that the UI process is still running and that the address begins with
`http://127.0.0.1`. The server is deliberately loopback-only.

