# Canonical schema

The normative definitions are in [contracts.md](contracts.md), sections 2-4.
Changes to those interfaces require a human-approved ADR. This reference is not
a full pipeline acceptance or security report.

## Model boundary

- Use the nine canonical Pydantic models from `vulnassess.schema`.
- Nullable fields are still required unless an explicit default is specified.
- Derive `Finding.id` using the exact SHA-256 fingerprint and UUID5 algorithm; supply the identifier rather than inventing a different scheme.
- Preserve evidence exactly. Oversized finding excerpts and blank feature evidence are errors, not permission to silently truncate or paraphrase.
- Nmap and Nikto must retain `native_severity=None`.
- Preserve `Feature.value: Any` and its three provenance labels. Representing an `llm` source does not authorise LLM-derived scoring inputs.
- The requested frozen Pydantic configuration prohibits attribute reassignment; do not describe mutable nested lists or dictionaries as deeply immutable.
- A model alone cannot establish that evidence came from a genuine scanner record. Capture provenance and invariant I3 require separate validation.

## Store boundary

Use `Store(path)` for an existing database. Creation must be explicit via
`Store(path, create=True)`, with an existing parent directory. Do not silently
create a missing input store, migrate an incompatible database, or hide corrupt
stored JSON behind an empty result.

Run metadata is supplied through `vulnassess.store.Run`. Timestamps and hashes
come from the caller, not a store clock or generated approval record. A reused
run ID must not replace different metadata. Store objects are context managers
and must be closed when no longer needed.

On a finding conflict, retain the original run, first-seen timestamp, evidence,
and remaining fields; only replace `last_seen`, in both the JSON and column.
This is global deduplication by finding ID, not a per-run association history.
Changing that representation requires the contract's human-approved ADR.

Serialize model JSON with stable key ordering. Retrieve findings by ascending
ID, and stored scores by descending risk with finding-ID tie-breaking. These
storage properties are prerequisites for, not evidence of, `rank --json`
determinism.

## Verification boundary

The schema and store tests use `tests/synthetic/synthetic_schema.json` only for
model round-trips, validation, deduplication, and persistence behavior. They are
not scanner, feed, CVSS calculation, or model-inference integration tests.

Socket refusal tests use a mocked network boundary. The guard applies to the
Python test process; it is not host-level egress enforcement or a sandbox for
arbitrary child processes. Static import checks likewise do not establish
behavior inside third-party dependencies.
