# Doors JSON contract

The original Phase 1 JSON contracts remain in place. Research ownership is PROJECT.md
Stage 7 (Report), with cross-cutting ranking and evaluation auditability. This is
a viewer contract, not a change to pipeline models, configuration or tables.

## Running locally

```text
python -m vulnassess ui --run verify --port 8765
python -m vulnassess ui --run-id verify --port 8765 --json
python -m vulnassess ui --db data/vulnassess.db --config config
python -m vulnassess ui --run verify --export reports/ui-verify.html
```

The bind address is always the literal `127.0.0.1`. There is no host option.
`--run` and `--run-id` are aliases; omitting both leaves `selected_run` null.
The command prints its URL and stops on Ctrl-C. `--json` prints a JSON startup
record with `url`, `run_id` and `read_only: true`. Port zero requests an ephemeral
port. An occupied or invalid port is `ConfigError` (exit 2). Global `--db` and
`--config` also work before the subcommand; all existing commands are unchanged.

The current four-stage entry page server-renders stored evidence, context,
comparison and priorities. Both `/` and `/static/index.html` return escaped
markup plus an inert `assessment-data` JSON script. Live behavior loads from a
local external module, with no inline handlers or executable inline scripts.
`/?run=<id>` selects an existing run without changing the server's default;
unknown query keys, empty IDs and duplicate run parameters fail explicitly.

`--export PATH` requires a selected run and writes one local `.html` file without
starting a server. It embeds the same assessment, current configuration and the
synthetic arithmetic-check fixture. Its CSP authorizes the exact stylesheet and
module text by SHA-256 and sets `connect-src 'none'`. Offline refresh is disabled.
The only client scoring is inside the explicitly labelled sandbox; it never
changes any stored field. See [ui.md](ui.md) for the checkpoint and limitations.

## Transport and safety

- Only GET is served. Every other parsed HTTP method returns 405 with `Allow: GET`.
- The temporary `/api/model` and `/api/model/run` routes are withdrawn by UI-12.
  GET returns 404 and POST returns 405. The later AI-01 analyst route is separate:
  only its explicit target-analysis request invokes local Ollama. Ordinary record
  routes, the workflow page and exports do not run a model.
- `/` and `/static/index.html` serve the same entry file. `/static/` has no listing.
- Static paths must remain inside `vulnassess/ui/static/`. Dot paths, hidden paths,
  encoded traversal, backslashes, control characters and Windows alternate streams
  are rejected. Arbitrary repository and raw files are not routes in this phase.
- Requests must carry exactly one Host matching `127.0.0.1:<port>`. Cross-origin
  requests and `Sec-Fetch-Site: cross-site` are refused; no CORS access is granted.
- All responses carry CSP beginning `default-src 'self'`, `nosniff`, `no-store`,
  `Referrer-Policy: no-referrer`, and same-origin resource policy. CSP prohibits
  inline scripts/styles, embedding, objects, base overrides and form actions.
- Each database request opens a new `sqlite3` connection with `uri=True`, `mode=ro`,
  `PRAGMA query_only = ON`, and one read transaction. It never constructs `Store`,
  changes journal mode, runs DDL, commits, scores, scans or downloads. The existing
  analyst route reads those records before its separately explicit model call.
- Unknown routes return 404. Missing runs, missing database/schema records and
  invalid stored records return 409 with a named error; they never become empty
  successful assessments. A present run with genuinely no rows may have empty arrays.

JSON is UTF-8 with sorted object keys. Arrays use the order documented below.
Numbers and nulls in assessment payloads are decoded directly from stored JSON,
not calculated or coerced. Risk, band and finding identity must also equal the
indexed score columns; conflicting values cause `ConfigError`.

## Routes

| GET path | Status | Top-level fields |
| --- | --- | --- |
| `/api/runs` | 200 | `runs`, `selected_run` |
| `/api/run/<id>` | 200 | `run`, `hosts`, `findings`, `context`, `scores`, `enrichments`, `rationales`, `feeds_meta`, `feeds_meta_scope`, `refusals`, `config_hashes` |
| `/api/scope` | 200 | `path`, `sha256`, `values`, `yaml` |
| `/api/weights` | 200 | `path`, `sha256`, `values`, `yaml` |
| `/api/cvss-fixture` | 200 when present | `source`, `seed`, `pinned`, `vectors`, `sandbox_weights`, `sandbox_cases` |
| `/api/eval/<id>` | 409 while absent | `run_id`, `status`, `records`, `reason` |
| `/api/diff/<a>/<b>` | 409 while absent | `run_ids`, `status`, `records`, `reason` |
| `/api/analyst/<run>/<host>` | 200 on a validated local response | `run_id`, `host_ip`, `model`, `source`, `canonical_scores_changed`, `analysis`, `evidence` |

## Workflow view

`GET /workflow` serves the independent visualization HTML. Its local modules read
the unchanged `/api/runs`, `/api/run/<id>`, `/api/scope` and `/api/weights` shapes.
`?run=<id>` selects the existing assessment. Hash keys `node`, `host` and `finding`
restore selection only; they do not execute stages or change configuration.
No new JSON assessment fields or score computations are introduced.

The analyst action uses the already-existing route documented above. It is never
requested on load, node selection, filtering or refresh. Its transient response
is held in page memory under the requested run and target and discarded on a full
reload. Errors remain explicit; no default answer substitutes for failed inference.
Model prose is rendered with text nodes and never feeds back into stored scores.
The new visualization does not change the backend analyst implementation.

Nodes expose whether source records exist, not a manufactured execution timeline.
Report/evaluation/re-scan outputs remain unattached when the run API has no such
artifact. Counts and scores shown by the inspector are values from existing
records; diagram layout coordinates are presentation metadata, not measurements.

## Missing results

IDs are URL-encoded path segments and parameterized SQL values, never filenames
or SQL fragments. Both run IDs must exist for a diff request. The current pipeline
does not persist these evaluation/diff results in the store. Those endpoints
explicitly report unavailability; they do not invoke `evaluate.py` or `diff.py`,
infer a metric, or treat an unrecorded result as zero. Supporting a supplied stored
result requires a documented artifact binding in its later phase, not a new UI
calculation. Refusal storage is deferred to G40.

The CVSS fixture route is a local arithmetic test resource, not assessment or feed
evidence. Each `vectors` record has `vector`, `base` and `environmental`. Each
`sandbox_cases` record has a base `vector`, a synthetic `profile`, explicit
`changes` and `expected` arithmetic output. `sandbox_weights` binds those cases
to their test configuration. Missing fixture files return a named error; no
network fetch, score computation or generated substitute occurs on this route.

The entry-page bootstrap has `assessment`, `configuration`, `runs`, and, when a
run is selected, `tour_finding`. `assessment` equals the run-route payload;
`configuration` contains the scope/weights endpoint objects. A CLI export adds
`offline: true` and `cvss_fixture`. This wrapper is a presentation adapter, not
new canonical fields. No evaluation metrics or inferred stage totals are added.

## Run and configuration fields

`runs` is an array ordered by `started_at` descending, then `run_id` ascending.
`selected_run` is the requested stored run ID, or null, and does not change that list.
`run` and each item in `runs` have exactly these fields:

| Field | Type | Source and meaning |
| --- | --- | --- |
| `run_id` | string | `runs.run_id`; assessment identifier |
| `started_at` | string | `runs.started_at`; preserved recorded timestamp |
| `config_hash` | string | `runs.config_hash`; preserved pipeline configuration digest |
| `summary` | object | Decoded `runs.summary_json`; stored stage metadata, without added counts |

`config_hashes.run_config` repeats the stored run digest.
`config_hashes.score_weights` is the sorted distinct set of stored
`scores.json.weights_hash` strings. An empty set means there are no scored rows,
not that the current weights have been substituted.

Each configuration endpoint returns these fields:

| Field | Type | Source and meaning |
| --- | --- | --- |
| `path` | string | Absolute local path to the selected YAML file |
| `sha256` | string | Full SHA-256 of those file bytes at server startup |
| `values` | object | Parsed values, validated by the existing `Settings` implementation |
| `yaml` | string | UTF-8 source document, preserved for evidence display |

These are explicitly current configuration files, not reconstructed historical
configuration. They are cached at server startup; restart after changing files.
The full file SHA-256 is not interchangeable with the pipeline's configuration or
weights digests, which use different existing algorithms. No hash comparison is
invented. `values` preserves every validated key of the corresponding existing
scope/weights schema; the viewer adds no default configuration fields.

## Hosts and services

`hosts` is ordered by stored `ip`. Each host has exactly:

| Field | Type | Meaning |
| --- | --- | --- |
| `ip` | string | Stored host address |
| `hostname` | string or null | Stored hostname, without resolution |
| `os_guess` | string or null | Stored scanner OS guess |
| `services` | array | Stored services, in their original order |

Each service has `port` (number), `protocol` (string), `name` (string or null),
`product` (string or null), `version` (string or null), `cpe` (string or null),
`banner` (string or null), and `tls` (boolean). All are stored observations; the UI
does not detect a new service, infer TLS or resolve a name.

## Findings and provenance

`findings` uses `finding_runs` membership, including findings whose original
ownership belongs to an earlier run. Rows are ordered by finding ID. Stored bodies,
original provenance and original timestamps are preserved rather than rewritten
for the selected run. Each finding has exactly:

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Stored canonical fingerprint-derived identity |
| `host_ip` | string | Stored affected host |
| `port` | number or null | Stored affected port |
| `protocol` | string or null | Stored transport |
| `url` | string or null | Stored affected URL, not fetched |
| `tool` | string | Source scanner |
| `tool_native_id` | string | Source scanner's identifier |
| `title` | string | Stored finding title |
| `description` | string | Stored finding description |
| `evidence` | string | Stored verbatim excerpt, without UI rewriting |
| `cve_ids` | string array | Recorded CVE identifiers |
| `cwe_ids` | string array | Recorded CWE identifiers |
| `reference_urls` | string array | Recorded references, not fetched |
| `native_severity` | string or null | Recorded scanner severity |
| `native_confidence` | string or null | Recorded scanner confidence |
| `first_seen` | string | Stored original first-seen timestamp |
| `last_seen` | string | Timestamp in the stored finding JSON, not synthesized from membership |
| `provenance` | object | Fields described immediately below |

Provenance has exactly `tool` (scanner string), `raw_path` (original local artifact
path string), `record_index` (stored number), and `run_id` (original import run
string). This is not a route granting arbitrary filesystem access.

## Context and enrichments

`context` is ordered by `host_ip`. Each profile has `host_ip` (string), `role`
(feature), `exposure` (feature), `segment` (string or null), `controls` (map of
control names to features) and `manual` (map of recorded override names to features).
A feature has `value` (stored JSON value), `confidence` (stored number), `source`
(recorded `rule`, `manual` or `llm` label), and `evidence` (stored quote). A source
label neither authorizes model calls nor establishes that an inference is correct.

`enrichments` is selected by finding membership and ordered by `finding_id`,
then `cve_id`. Each item preserves:

| Field | Type | Meaning |
| --- | --- | --- |
| `finding_id` | string | Related finding identity |
| `cve_id` | string | Matched CVE identifier |
| `match_method` | string | Stored match method |
| `match_confidence` | number | Stored match confidence |
| `cvss31_vector` | string or null | Recorded CVSS 3.1 vector |
| `cvss31_base` | number or null | Recorded CVSS 3.1 base score |
| `cvss40_vector` | string or null | Recorded CVSS 4.0 vector |
| `cvss40_base` | number or null | Recorded CVSS 4.0 base score |
| `epss` | number or null | Recorded exploitation probability |
| `epss_percentile` | number or null | Recorded percentile, distinct from probability |
| `kev` | boolean | Recorded KEV membership |
| `kev_date_added` | string or null | Recorded date added |
| `patch_references` | string array | Recorded advisory references, without fetching |
| `description` | string | Recorded intelligence description |
| `version_end` | string or null | Recorded matched version boundary, not proof of a fix |
| `feed_dates` | object | Feed-name to recorded date-string map |

Enrichments are global mutable store rows, not historical per-run snapshots. Their
presence does not prove they remain identical to the records used when scoring.
The viewer keeps score inputs separate and never rescores with these current rows.

## Scores and rationales

`scores` is ordered by indexed risk descending, then finding ID. It preserves:

| Field | Type | Meaning |
| --- | --- | --- |
| `finding_id` | string | Stored related identity |
| `host_ip` | string | Stored affected host |
| `cve_id` | string or null | CVE used for this stored score |
| `cvss_version_used` | string or null | Recorded scoring version |
| `base_vector` | string or null | Recorded starting vector |
| `base_score` | number or null | Recorded base result |
| `env_vector` | string or null | Recorded Environmental vector |
| `env_score` | number or null | Recorded Environmental result |
| `env_modifications` | object | Stored metric-to-rule strings |
| `epss_percentile` | number or null | Percentile used in this score |
| `threat_multiplier` | number or null | Stored factor; null remains unscored, never zero |
| `kev` | boolean | Membership used in this score |
| `native_fallback` | string or null | Recorded native-severity fallback path |
| `risk` | number | Stored risk, checked against its indexed column |
| `band` | string | Stored band, checked against its indexed column |
| `inputs` | object | Stored formula inputs, not new UI inferences |
| `weights_hash` | string | Stored weights digest |
| `reason` | string | Stored deterministic explanation |
| `fix` | string | Stored fix text; not proof of a sourced remedy |

`rationales` is ordered by `finding_id`. Each has `finding_id` (string), `text`
(stored sentence string), `source` (recorded `template` or `llm`), `model` (string
or null), and `validation` (stored JSON object containing status/rejection details).
The viewer never creates a new explanation or sends these records to a model.

## Feeds and unavailable records

`feeds_meta` is ordered by `feed`. Each record has `feed` (name string), `path`
(source path string), `sha256` (stored digest string), `file_date` (date string or
null), `rows` (stored count), and `loaded_at` (stored timestamp string).
`feeds_meta_scope` is the literal `current_store_not_frozen_per_run`: these global
rows are not evidence of historical run-pinned feed metadata. No feed age or row
count is computed by this phase. Files are not fetched or loaded through the UI.

`refusals` currently has `status: MISSING`, `records: null`, and `reason` naming
the run and database. It is not an empty claim that no imports were refused.
Unavailable evaluation and diff responses use the same three fields, adding
`run_id` or `run_ids` as shown in the route table. `records: null` never means zero.

Errors have exactly `error: {type, message, exit_code}`. `type` is `ConfigError`,
`message` names the failed path, run or boundary, and `exit_code` is the fixed 2.
HTTP transport status is distinct from the process exit code. Error messages are
JSON data, not HTML; request logging is disabled to avoid echoing untrusted paths.

## Verification commands

```text
python scripts/check_ui_inputs.py
python -m unittest -v tests.test_ui
python scripts/check_ui_server.py
python -m unittest -v
python scripts/check.py
```

The UI tests require the existing local `data/vulnassess.db` and its `verify` and
`x` runs. Their absence is a named missing-input failure, not a generated demo or
a new skip. The local demo's metadata points at synthetic feeds; tests over it
validate record fidelity and code paths, not real scanner/Intelligence integration.
Unittests forbid socket creation; the separately approved smoke script checks a
real ephemeral loopback server, API/SQLite equality and unchanged database bytes.
The smoke script does not leave a server running. Missing gate tools are never
installed by any command above.
