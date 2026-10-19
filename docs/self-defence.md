# Self-defence: check the VulnAssess device

## Purpose

The dedicated **Self-defence** navigation section now presents nine configuration
observations, up to 64 listening TCP entries with application names and binding
classification, registered antivirus products, and the latest recorded hotfix date.
Added checks cover Remote Desktop, SMB1, Secure Boot, system-drive encryption
protection, and a Windows Update restart flag. Permission failures remain unknown.
Antivirus registration is not proof of active protection, and the hotfix date is
not a complete Windows Update audit. No external vulnerability lookup is inferred
from these observations. AI receives cited observations plus a bounded four-listener
sample, with an explicit omitted count.

## Action queue and recheck comparison

The device page now begins with a deterministic precaution queue. A disabled firewall
is promoted as an active-network configuration gap only when its profile is confirmed
active. Remote Desktop plus a non-loopback TCP 3389 listener prompts verification;
it does not prove the listener's identity or internet access. Unknown checks remain
separate verification tasks. This queue does not alter canonical vulnerability scores.

Each new device check compares matching protection settings against the most recent
hash-verified loopback device capture among the latest 100 candidate captures.
Missing baseline means first check. An enabled-to-unknown change is explicitly shown,
not interpreted as a fix. Current comparison covers configuration states, not complete
application-inventory changes. A selectable action queue sits beside a persistent
evidence and manual-precaution inspector; all protection checks remain available in
an expandable section below it. Narrow screens stack the two panels.

Each supporting check has a read-only recheck button. `/api/device-recheck` accepts
one allowlisted check ID through an explicit same-origin POST and applies the loopback
scope gate. It runs only the associated fixed PowerShell check, without Nmap, elevation,
or remediation. Results are retained locally under `data/device-rechecks`; the inspector
shows original and current observations plus up to ten matching recent records from
the latest 100 files. New records retain a checksum; malformed, wrong-target, legacy
unhashed and checksum-mismatched records are excluded from comparisons, not deleted.
Checksums detect accidental edits, not an attacker able to replace both data and hash.
The timeline remains visible when switching between actions; after a page reload,
the next explicit recheck retrieves retained history. Existing AI advice is explicitly identified
as belonging to the original assessment, not silently regenerated or revalidated.

A small personal-use mode inside the existing AI-based vulnerability assessment
workflow. Choose **Run → Self-defence · check this device + AI → Check this device**.
It checks the machine running the server, which may differ from the browser's machine.

## Collected evidence

- Existing light Nmap discovery against exactly `127.0.0.1`: top 100 TCP ports,
  connect scanning and light service identification, under the configured scope fence.
- Windows firewall Domain, Private and Public profile enabled status.
- Microsoft Defender real-time protection enabled status.
- Timestamped observations, retained in `device-check.json` with the existing evidence
  manifest. No personal files, browser history, credentials, process command lines or
  process environment variables. Listener application names are collected as described above.

PowerShell uses one fixed read-only script, no elevation, a 20-second timeout and
strict boolean interpretation. Unsupported systems, failures and missing values
produce **unknown**, never a clean bill of health. A disabled Defender check does
not exclude another antivirus provider; firewall profiles may not be active.
Each completed query emits a JSON checkpoint. If a later query times out, the last
complete checkpoint is retained; an incomplete final line is ignored. This fixes
the all-unknown result caused by discarding successful earlier queries. A real local
collection retained seven known settings, two unknown settings, 28 listeners and
the active Public profile after this change.

## AI contribution

Protection observations receive server-issued evidence IDs in the existing grounded
case. The model is instructed to explain observations and manual precautions in
everyday language. Existing JSON schema, citation and score validators still apply.
The UI distinguishes validated AI interpretation from fixed precaution guidance.
Local Ollama remains available; cloud providers require the existing evidence-sharing
consent. AI failure preserves the evidence-only summary and protection checks.

Self-defence actions can cite device-protection, inventory or listener evidence instead
of being incorrectly required to cite an unrelated scanned network service. Network
assessment actions retain their service-evidence requirement. An active disabled
firewall profile now shows up to five network-bound applications in its evidence
inspector, excluding loopback-only bindings; external reachability is still unknown.

For self-defence cases with no findings, a compact request asks for one action and
one uncertainty rather than a long network assessment. Citation, schema, score and
unsupported-assurance validation are unchanged. Local testing showed the previous
request timing out after 180 seconds on llama3.2:3b; the compact request completed
generation, but both tested responses were rejected for an unsupported safety assurance.
The rejected text was confirmed as "No vulnerabilities found." The revised request
focuses on observed settings and explicitly maps device versus role/exposure citations.
A later retained-evidence replay passed the existing validator in 107.9 seconds using
local llama3.2:3b. Its wording remained generic; structural validation is not an expert
semantic-quality evaluation. No rejected advice is shown.

CPU generation was measured at roughly 4–5 tokens/second during a slow replay.
Locally created Ollama clients for self-defence therefore have a bounded 300-second
deadline. Injected clients, cloud providers and normal network-assessment deadlines
are unchanged. Token limits and validators remain unchanged.

## Boundaries

The reserved target `self` maps server-side to loopback. Planned execution, saved-case
replay and recent-evidence replay are rejected for a fresh self-check. The normal
10-minute target cooldown and scope allowlist still apply. No firewall or antivirus
settings are changed. This mode does not detect malware, prove internet exposure,
audit every installed software patch, or establish whole-device safety. Protection
status observations are not invented CVEs and do not create canonical risk scores.

## Verification

Tests cover strict status parsing, discarded unexpected fields, malformed output,
unsupported platforms, remote target rejection and replay/plan rejection. The existing
live-assessment and UI regression suites are also run. Live model success is reported
separately from scanner and protection-check success.

The targeted recheck was also exercised against the running local endpoint: Defender
returned enabled without a new Nmap scan. Tests cover explicit-action requirements,
allowlisted parameters, scope rejection, local retention, and UI success/error states.
The redesigned dashboard has automated rendering checks; live visual verification
was blocked by the browser tool's navigation policy in this session.

Latest automated verification after the collector checkpoint fix: 673 tests plus 495
subtests passed; targeted Python type checking and lint also passed. The real local recheck endpoint returned
two retained Defender observations with an unchanged enabled state. No operating-system
settings were changed and no cloud provider received device evidence during these checks.
The fresh live run also produced an audit-recorded validated Ollama response (before
the checkpoint collector fix); this does not claim a second full scan after that fix.
