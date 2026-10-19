# Starter kit — how to use these files

## Current repository review

This folder is being reviewed in place, not copied over the existing application's contracts or
scope. Start with [the five-day DESIGN](docs/DESIGN.md), [design resolutions](docs/decisions.md), and
the parent [capture guide](../docs/fixtures.md). The original deck is at
[docs/deck/de_ppt.pdf](../docs/deck/de_ppt.pdf); stage/commit state must be checked, not assumed.

The parent no-install guard and 85% coverage gate remain binding here. The kit's older 75% line,
wheel-directory shortcut and broad interface autonomy do not override them. The .env.example
variables do not by themselves impose an OS egress policy or automatically configure a shell.
Prototype model use is deferred; its template model name is not an approved or available artifact.
The kit's additional canary configuration is not applied to the parent scope schema.

Capture owner and reviewer names are pending logistics. Support N>=1 experts, report W only for
N>=2, and state the N=1 limitation. Work only on review branches; do not merge to main. Proposed
interface/dependency changes stay unapplied until the reviewer process approves them.

## 1. Put the files in place

Copy everything in this folder into the ROOT of your empty repository, keeping the folder structure:

```
your-repo/
  .github/copilot-instructions.md   <- Copilot reads this automatically on every request
  .gitignore
  .env.example
  LICENSE
  PROMPT.md                         <- the kickoff prompt (paste its contents into Copilot Chat)
  README-KIT.md                     <- this file (delete after reading)
  config/scope.yaml                 <- the safety fence: lab network only
  docs/PROJECT.md                   <- the whole idea
  docs/problem-statement.md         <- the research question
  docs/design-notes.md              <- reference design, non-binding
  docs/decisions.md                 <- append-only log, seeded
```

Commit: `git add -A && git commit -m "docs: project brief, problem statement, walls and scope"`

## 2. Before pasting the prompt (human steps, once)

- Create the venv and install the declared dependencies while online, OR build a wheels/ folder on a
  connected machine (`pip download -d wheels ...`). The agent will not install from the internet.
- Copy .env.example to .env and fill in what applies.
- Bring up the lab (three intentionally vulnerable containers on 172.28.0.0/24 at .10 / .11 / .12,
  plus a canary web server at .250 that must never be hit). The agent will write the compose file if
  you ask; a human runs it.
- Run Nmap and ZAP once per target and commit the outputs to tests/fixtures/nmap/ and
  tests/fixtures/zap/ with a README (date, exact command, target).
- Download the EPSS CSV, the KEV JSON and an NVD subset covering the CVEs in your fixtures into
  data/feeds/ (git-ignored). Commit a small real subset (10-50 records) to tests/fixtures/intel/.
- Start asking 2-3 practitioners to rank the lab findings. This is the slowest step in the project.

## 3. Paste PROMPT.md into Copilot Chat (Agent mode)

It will produce a one-page DESIGN and stop. Read it. Push back on the formula, the exposure logic and
anything deferred that touches the research question. Then say "build".

## 4. After each increment

Read the report. Check that every claim carries an evidence label. Open the terminal history and
search for `pip install`, `docker`, `ollama pull`, `curl`, `wget` — ten seconds, every time.
