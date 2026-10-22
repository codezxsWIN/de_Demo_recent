# HarborDesk: deliberately vulnerable local training site

**Never publish, tunnel or port-forward this application.** It binds only to
`127.0.0.1` and checks the Host header and write origin. Accounts, records and
tokens are fictional; do not enter real credentials.

This supports the [project brief](../../docs/PROJECT.md)'s cross-cutting
**Lab and demo / Risk ranking** components, stage 3 (safe evidence collection)
and stage 7 (reporting). Repeatable positive and secure-control cases let the
workflow distinguish observed impact from unsupported severity claims. They do
not establish ranking accuracy or expert agreement.

## Run without installing anything

From the repository root, using an already available Python 3.11+:

```powershell
python -m labs.harbordesk
```

Open <http://127.0.0.1:8787/>. The web lab and new management listeners use
Python's standard library only. The same process starts management on
`127.0.0.1:8791` and its protected comparison on `127.0.0.1:8792`.
Stop it with Ctrl+C. All profile/order/queue changes disappear on restart.

The optional `--network` mode additionally requires human-provided `pyftpdlib`
and `cryptography`. Do not install packages to enable it automatically. Without
these prerequisites, run the web lab without `--network`; no FTP/TLS coverage
is established.

## High-impact application cases

| Case | Vulnerable behavior | Secure comparison |
| --- | --- | --- |
| HD-17 | `GET /api/admin/export` returns every fictional customer, order, ticket and document without login. | `/secure/api/admin/export` denies guests/customers and permits the fixture administrator. |
| HD-18 | A demo customer posts `role=admin` to `/api/profile`; the role persists and a separate `/api/admin/summary` request changes from 403 to 200. | `/secure/api/profile` accepts display names but rejects protected role fields; customer administration stays forbidden. |
| HD-19 | A client posts a new `total` to another account's `/api/orders/2002`; a separate GET reads the changed value. | `/secure/api/orders/2002` refuses anonymous/cross-account writes. The owner can still update its own order. |

Use **High-impact lab** in the site navigation. Sign in with the displayed
fictional demo account before the role-assignment case. Restore its role to
`customer` and order 2002's total to `280` after manual experiments, or restart
the server. The vulnerable and secure workspaces have independent in-memory
state. The SQL-injection database remains read-only and disposable. No service
executes host commands, reads arbitrary files or contacts external hosts.

The original SQL injection, authentication bypass, IDOR, reflected HTML,
configuration exposure and cookie/header cases remain available. The
[answer key](ground-truth.json) describes intended conditions, not detections.

## Additional trackable network weaknesses

All existing FTP/TLS cases (HD-13 through HD-16) and application cases
(including HD-17 through HD-19) are preserved and remain implemented. The
following additions are genuine, low-risk observable conditions, not display-only
placeholders:

| Case | Actual observation | Native severity |
| --- | --- | --- |
| HD-20 | The identified portal responds over cleartext HTTP without TLS. | Medium |
| HD-21 | An unauthenticated request reads the declared fictional service inventory. | Low |
| HD-22 | The actual HTTP `Server` header includes Python/BaseHTTP versions. | Low |

The **Network services** page preserves these and all original network cases. The verifier
collects real HTTP responses for the new cases. It does not open extra listeners,
intercept traffic, query real host configuration, invent banners or assign CVEs.
The inventory comparison requires fixture administrator authorization and the
secure-response comparison minimizes version details. `/secure/` paths remain
HTTP and are **not** claimed to fix cleartext transport.

### High-impact network service cases

- **HD-23, native High:** an unauthenticated connection to port 8791 retrieves
  the entire fictional business backup. The verifier records actual counts.
- **HD-24, native High:** an unauthenticated `/config` write pauses a fictional
  in-memory queue. A separate `/dispatch` request changes from HTTP 200 to 503.
  The verifier restores the original value even after an interrupted response.

Open <http://127.0.0.1:8791/> for the actual management console. Its buttons
pause/resume only the disposable queue. Read the backup or configuration and
check dispatch separately to observe the change. The comparison listener on
8792 rejects unauthorized backup/configuration requests; the verifier also
checks that authorized fixture access still works. Neither listener executes
commands, changes host configuration, reads arbitrary files or controls real
services. Both refuse non-loopback binding and unexpected write origins.

With optional FTP/TLS disabled, the running lab's `--extended` check covers
19 actual conditions and 17 secure controls. `network_status` refers to optional FTP/TLS;
HTTP network observations have separate coverage text. The unchanged original
FTP/TLS services still require their human-provided optional dependencies.

## Verify and connect to the workflow

### Click a vulnerability to understand it

Select any card on **Network services** or **Lab comparison** to open its
explanation. The high-impact application and management sections also have
direct **Understand** buttons, separate from their existing testing controls.

The responsive dialog groups the information into plain-English meaning,
impact, how the weakness happens, its affected entry point, expected verifier
proof, a fix checklist and confirmation steps. Extra prerequisites and evidence
limits are expandable. Use **Close** or **Esc** to return to the same card.

All 23 implemented cases reuse the workflow's reviewed fixture-specific
guidance. Opening the explanation reads the catalog only: it does not run
verification, change state, change scores or manufacture a detection.
The active vulnerable routes and their secure comparisons are unchanged.

With the web server running:

```powershell
python -m labs.harbordesk.verify --extended
```

This bounded local verification command checks the lab identity before active
requests. It records before/after observations for the three new cases and
restores the original vulnerable role and order total, including on intermediate
request failures. A failed restoration raises an explicit error. Its receipt is
distinct from Nmap, Nikto or ZAP output.

The workflow's existing
[HarborDesk adapter](../../vulnassess/harbordesk_probe.py) runs the extended
verifier for the exact authorized `http://127.0.0.1:8787/` endpoint, retains
`harbordesk-checks.json`, and creates canonical findings only for observed cases.
It supplies trusted CWE/severity metadata and
[fixture-specific fix guidance](../../vulnassess/harbordesk_guidance.py). The
answer key alone never creates a finding. Scanner/model prerequisites and their
coverage remain separate; this increment does not run scanners or models.

**Scores are not forced to 100/100.** The unchanged
[weight configuration](../../config/weights.yaml) maps HarborDesk `High` to
`60/100`. These custom flaws have no assigned CVEs, CVSS vectors, EPSS values or
KEV membership. High native severity describes the bounded observed fixture
impact, not production compromise. A maximum score would require supported
inputs and the existing deterministic policy, not a more alarming title.

## Offline regression checks

```powershell
python -m pytest tests\test_harbordesk_lab.py tests\test_harbordesk_extended.py tests\test_harbordesk_probe.py tests\test_harbordesk_model_budget.py tests\synthetic\test_synthetic_harbordesk_impact.py tests\synthetic\test_synthetic_harbordesk_management.py tests\synthetic\test_synthetic_harbordesk_explanations.py -q
```

The new synthetic tests exercise handler/state logic with fake transports and
the repository socket-denial fixture. They are not proof of real scanner,
feed or model integration. Explanation interaction checks use a tiny synthetic
DOM in Node.js with networking denied; no Node packages are required. Browser
checks separately verify real dialog focus, Escape, responsive layouts and the
23 rendered guides. Run the full `make check` gate only when its
human-provided prerequisites are available; missing tools are a blocker, not a
passing gate. Real scanner captures with human-recorded provenance are still
required for parser/integration certification.
