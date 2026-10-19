"""Typed follow-up evidence collection. Network transports are not run by the agent.

Approval is one-use, target/parameters are hash-bound, and observations never enter scoring.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import socket
import ssl
import time
import uuid
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from threading import RLock
from typing import Any, Callable

from vulnassess.ai_boundary import (
    CONTROL_TOKENS,
    INJECTION_SENTINEL,
    SYSTEM_BOUNDARY_PROMPT,
    append_audit,
    digest,
    envelope,
    verify_claims,
)
from vulnassess.analyst import AnalystProvider
from vulnassess.errors import LLMUnavailable, NeedsReview
from vulnassess.scan_plans import CLAIM_FIELDS, cited_claim_schema
from vulnassess.website_metadata import minimise

VERSION = "evidence_request.v1"
KINDS = ("http_head", "tls_inspect", "tcp_connect")
FIELDS = {
    "schema_version",
    "target_ip",
    "kind",
    "port",
    "timeout_seconds",
    "reason",
    "expected_information_gain",
    "claims",
}
MAX_BYTES = 8192


def validate(value: Any, context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise NeedsReview("Needs review: unknown evidence request schema")
    try:
        literal = str(ip_address(value["target_ip"]))
    except (ValueError, TypeError) as error:
        raise NeedsReview("Needs review: evidence requests require a literal pinned IP") from error
    if value["schema_version"] != VERSION or literal != context["target_ip"]:
        raise NeedsReview("Needs review: evidence request target differs from the pinned IP")
    if (
        value["kind"] not in KINDS
        or type(value["port"]) is not int
        or not 1 <= value["port"] <= 65535
        or type(value["timeout_seconds"]) is not int
        or not 1 <= value["timeout_seconds"] <= 10
    ):
        raise NeedsReview("Needs review: unsupported probe or parameter bounds")
    options = [
        item
        for item in context["probe_options"]
        if item["kind"] == value["kind"] and item["port"] == value["port"]
    ]
    if not options:
        raise NeedsReview("Needs review: probe must reference an observed service")
    texts = {field: value[field] for field in ("reason", "expected_information_gain")}
    supplied = json.dumps(context)
    identifiers = re.compile(
        r"CVE-\d{4}-\d{4,}|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b\d+/(?:tcp|udp)\b|\bE[1-9]\d*\b", re.I
    )
    allowed_identifiers = {item.casefold() for item in identifiers.findall(supplied)}
    for text in texts.values():
        if not isinstance(text, str) or not text.strip() or len(text) > 500:
            raise NeedsReview("Needs review: probe justification is invalid")
        for identifier in identifiers.findall(text):
            if identifier.casefold() not in allowed_identifiers:
                raise NeedsReview("Needs review: probe justification invents an identifier")
    try:
        claims = verify_claims(value["claims"], context["evidence"], set(), {}, set(texts), texts)
    except (LLMUnavailable, TypeError, ValueError, KeyError) as error:
        raise NeedsReview(str(error)) from error
    for claim in claims:
        if (
            not any(item["evidence_id"] in claim["evidence_ids"] for item in options)
            or len(claim["evidence_ids"]) > 4
            or len(claim["quotes"]) > 4
            or any(len(quote["text"]) > 1000 for quote in claim["quotes"])
            or len(claim["verification_action"] or "") > 1000
        ):
            raise NeedsReview("Needs review: probe needs bounded citations to its observed service")
    return copy.deepcopy(value)


def propose(context: dict[str, Any], client: AnalystProvider, audit_path: Path) -> dict[str, Any]:
    """One proposal per call; no tool invocation occurs in this function."""
    service_ids = {item["evidence_id"] for item in context["probe_options"]}
    claim = cited_claim_schema(sorted(service_ids))
    claim["properties"]["path"] = {
        "type": "string",
        "enum": ["reason", "expected_information_gain"],
    }
    # The model selects references; the server attaches exact quotes, as in analyst.v4.
    claim["required"].remove("quotes")
    del claim["properties"]["quotes"]
    schema = {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(FIELDS),
        "properties": {
            "schema_version": {"type": "string", "enum": [VERSION]},
            "target_ip": {"type": "string", "enum": [context["target_ip"]]},
            "kind": {
                "type": "string",
                "enum": sorted({item["kind"] for item in context["probe_options"]}),
            },
            "port": {
                "type": "integer",
                "enum": sorted({item["port"] for item in context["probe_options"]}),
            },
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 10},
            "reason": {"type": "string", "maxLength": 500},
            "expected_information_gain": {"type": "string", "maxLength": 500},
            "claims": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "items": claim,
            },
        },
    }
    # Bind each operation/port choice to its own service IDs in the decoder too.
    # Independent enums let small models combine the right port with the wrong citation.
    variants = []
    for kind, port in sorted({(item["kind"], item["port"]) for item in context["probe_options"]}):
        variant = copy.deepcopy(schema)
        variant["properties"]["kind"]["enum"] = [kind]
        variant["properties"]["port"]["enum"] = [port]
        variant["properties"]["claims"]["items"]["properties"]["evidence_ids"]["items"]["enum"] = (
            sorted(
                {
                    item["evidence_id"]
                    for item in context["probe_options"]
                    if item["kind"] == kind and item["port"] == port
                }
            )
        )
        variants.append(variant)
    schema["oneOf"] = variants
    prompt = (
        "Propose one evidence_request.v1 from the supplied probe_options. Return JSON only. "
        "Reason and expected_information_gain each require a labeled, cited claim. "
        'The claims array must contain EXACTLY two entries: path="reason" and '
        'path="expected_information_gain". Use those literal names, without prefixes or array indexes. '
        "Each claim needs evidence_ids, label, confidence, "
        "finding_ids: [], score: null, verification_action: null (or a check for a hypothesis). "
        "Do not generate quotations: the server attaches exact evidence text for your selected IDs. "
        "Both claims must cite the evidence_id of the selected probe_options entry. Baseline policy is not service evidence. "
        "No scores, findings or invented identifiers. "
        "http_head sends HEAD / to the literal IP without redirects; tls_inspect checks a "
        "certificate against the literal IP; tcp_connect only checks connectivity. "
        "These probes cannot establish general authentication, WAF presence or vulnerability. "
        "untrusted data follows\n"
        + envelope(
            "CASE",
            json.dumps({key: context[key] for key in ("target_ip", "probe_options")}),
        )
        + "\n"
        + "\n".join(envelope(item["id"], item["text"], limit=1500) for item in context["evidence"])
    )
    audit: dict[str, Any] = {
        "stage": VERSION,
        "model": client.model,
        "prompt_hash": digest({"system": SYSTEM_BOUNDARY_PROMPT, "user": prompt}),
        "input_hash": digest(context),
        "output_hash": None,
        "decision": "reject",
        "outcome": "needs_review",
        "canary_seen": False,
    }

    def capture(raw: bytes) -> None:
        audit["output_hash"] = hashlib.sha256(raw).hexdigest()
        audit["canary_seen"] = audit["canary_seen"] or INJECTION_SENTINEL.encode() in raw

    try:
        if not context["probe_options"] or len(prompt) > 16000:
            raise NeedsReview(
                "Needs review: observed services and a bounded evidence context are required"
            )
        if not client.available():
            raise NeedsReview("Needs review: evidence-request model unavailable")
        output = client.generate_structured(
            prompt, schema, num_predict=1800, num_ctx=8192, on_raw=capture
        )
        audit["output_hash"] = audit["output_hash"] or digest(output)
        if audit["canary_seen"] or INJECTION_SENTINEL in json.dumps(output):
            audit["flagged_evidence_ids"] = [
                item["id"] for item in context["evidence"] if CONTROL_TOKENS.search(item["text"])
            ]
            raise NeedsReview("Needs review: evidence-request instruction canary triggered")
        enriched = copy.deepcopy(output)
        if not isinstance(enriched, dict) or not isinstance(enriched.get("claims"), list):
            raise NeedsReview("Needs review: invalid evidence-request claim schema")
        quote_text = {
            item["id"]: item["text"][:160]
            for item in context["evidence"]
            if item["id"] in service_ids
        }
        for item in enriched["claims"]:
            if not isinstance(item, dict) or set(item) != CLAIM_FIELDS - {"quotes"}:
                raise NeedsReview("Needs review: unknown model claim fields")
            ids = item["evidence_ids"]
            if (
                not isinstance(ids, list)
                or not 1 <= len(ids) <= 4
                or not all(isinstance(identity, str) and identity in quote_text for identity in ids)
            ):
                raise NeedsReview("Needs review: claim must cite server-issued service evidence")
            item["quotes"] = [
                {"evidence_id": identity, "text": quote_text[identity]} for identity in ids
            ]
        result = validate(enriched, context)
        audit.update(decision="accept", outcome="validated")
        return result
    except Exception as error:
        audit["reason"] = type(error).__name__
        raise NeedsReview(
            str(error)
            if isinstance(error, LLMUnavailable)
            else "Needs review: invalid evidence-request response"
        ) from error
    finally:
        append_audit(audit, audit_path)


def probe(request: dict[str, Any]) -> dict[str, str]:
    """Fixed wire operations, literal IP only, one deadline, no redirects. Not run by the agent."""
    kind = request.get("kind")
    if kind not in KINDS:
        raise NeedsReview("Needs review: unsupported transport")
    address = ip_address(request["target_ip"])
    deadline = time.monotonic() + request["timeout_seconds"]
    raw = b""
    with socket.socket(
        socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM
    ) as connection:
        connection.settimeout(request["timeout_seconds"])
        connection.connect((str(address), request["port"]))
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        if kind == "tls_inspect":
            with ssl.create_default_context().wrap_socket(
                connection, server_hostname=str(address)
            ) as secured:
                raw = secured.getpeercert(binary_form=True) or b""
                if len(raw) > MAX_BYTES:
                    raise NeedsReview("Needs review: certificate exceeds evidence budget")
                observation = json.dumps(
                    {
                        "protocol": secured.version(),
                        "certificate": secured.getpeercert(),
                        "validation": "verified against literal IP; virtual-host certificates may differ",
                    },
                    sort_keys=True,
                )
        elif kind == "http_head":
            host = f"[{address}]" if address.version == 6 else str(address)
            connection.sendall(
                f"HEAD / HTTP/1.0\r\nHost: {host}:{request['port']}\r\nConnection: close\r\n\r\n".encode(
                    "ascii"
                )
            )
            while b"\r\n\r\n" not in raw:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Evidence request deadline exceeded")
                connection.settimeout(remaining)
                chunk = connection.recv(min(1024, MAX_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
                if b"\r\n\r\n" in raw:
                    raw = raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
                if len(raw) > MAX_BYTES:
                    raise NeedsReview("Needs review: HTTP headers exceed evidence budget")
            if b"\r\n\r\n" not in raw or not raw.startswith(b"HTTP/"):
                raise NeedsReview("Needs review: incomplete or invalid HTTP response")
            projected = minimise(raw)
            raw = bytes.fromhex(projected["raw_hex"])
            observation = projected["observation"]
        else:
            observation = (
                "TCP connection established; service identity and authentication not checked"
            )
    if time.monotonic() > deadline:
        raise TimeoutError("Evidence request deadline exceeded")
    return {"raw_hex": raw.hex(), "observation": observation[:4000]}


class EvidenceRequests:
    """Ephemeral approval authority, durable immutable evidence and audit artifacts."""

    def __init__(self, directory: Path, clock: Callable[[], float] = time.monotonic):
        self.directory, self.clock = directory, clock
        self.audit_path = directory / "audit.jsonl"
        self._records: dict[str, dict[str, Any]] = {}
        self._lock = RLock()

    def create(self, proposal: Any, context: dict[str, Any]) -> dict[str, Any]:
        request = validate(proposal, context)
        with self._lock:
            self._records = {
                key: row for key, row in self._records.items() if row["expires"] > self.clock()
            }
            if len(self._records) >= 64:
                raise NeedsReview("Needs review: evidence request queue is full")
            record = {
                "request_id": uuid.uuid4().hex,
                "request_hash": digest({"request": request, "context": context}),
                "request": request,
                "context": copy.deepcopy(context),
                "state": "proposed",
                "expires": self.clock() + 600,
            }
            self._audit(record, "proposed")
            self._records[record["request_id"]] = record
            return self._view(record)

    @staticmethod
    def _view(record: dict[str, Any]) -> dict[str, Any]:
        return copy.deepcopy(
            {key: value for key, value in record.items() if key not in {"context", "expires"}}
        )

    def _record(self, identity: str, binding: str) -> dict[str, Any]:
        record = self._records.get(identity)
        if (
            not record
            or record["request_hash"] != binding
            or record["state"] != "proposed"
            or record["expires"] <= self.clock()
        ):
            raise NeedsReview("Needs review: request expired, changed or already consumed")
        return record

    def _audit(self, record: dict[str, Any], action: str, **extra: Any) -> None:
        append_audit(
            {
                "stage": VERSION,
                "request_id": record["request_id"],
                "request_hash": record["request_hash"],
                "decision": action,
                **extra,
            },
            self.audit_path,
        )

    def reject(self, identity: str, binding: str, reason: str) -> dict[str, Any]:
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
            raise NeedsReview("Needs review: rejection needs a reason of 1–500 characters")
        with self._lock:
            record = self._record(identity, binding)
            self._audit(record, "rejected", reason=reason)
            record["state"] = "rejected"
            return self._view(record)

    def execute(
        self,
        identity: str,
        binding: str,
        scope_check: Callable[[str], str],
        transport: Callable[[dict[str, Any]], dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            record = self._record(identity, binding)
            if scope_check(record["request"]["target_ip"]) != record["context"]["scope_hash"]:
                self._audit(record, "scope_changed")
                record["state"] = "needs_review"
                raise NeedsReview("Needs review: scope changed; propose again")
            self._audit(record, "human_approved")
            record["state"] = "executing"
            try:
                output = (transport or probe)(copy.deepcopy(record["request"]))
                if set(output) != {"raw_hex", "observation"} or not all(
                    isinstance(value, str) for value in output.values()
                ):
                    raise NeedsReview("Needs review: unknown transport evidence schema")
                raw = bytes.fromhex(output["raw_hex"])
                if len(raw) > MAX_BYTES or len(output["observation"]) > 4000:
                    raise NeedsReview("Needs review: transport exceeded evidence bounds")
                evidence = {
                    "id": uuid.uuid4().hex,
                    "origin": "ai_request",
                    "schema_version": VERSION,
                    "target_ip": record["request"]["target_ip"],
                    "run_id": record["context"]["run_id"],
                    "request_hash": binding,
                    "kind": record["request"]["kind"],
                    "port": record["request"]["port"],
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                    "raw_sha256": hashlib.sha256(raw).hexdigest(),
                    **output,
                }
                self.directory.mkdir(parents=True, exist_ok=True)
                with (self.directory / f"{evidence['id']}.json").open(
                    "x", encoding="utf-8"
                ) as handle:
                    json.dump(
                        {"evidence": evidence, "sha256": digest(evidence)}, handle, sort_keys=True
                    )
                self._audit(
                    record, "complete", evidence_id=evidence["id"], output_hash=digest(evidence)
                )
                record.update(state="complete", evidence=evidence)
            except Exception as error:
                record["state"] = "needs_review"
                self._audit(record, "needs_review", reason=type(error).__name__)
                raise NeedsReview(
                    f"Needs review: evidence request failed ({type(error).__name__}); no finding or score was changed"
                ) from error
            return self._view(record)

    def evidence(self, run_id: str, target_ip: str) -> list[dict[str, Any]]:
        records = []
        for path in sorted(self.directory.glob("*.json")):
            try:
                stored = json.loads(path.read_text(encoding="utf-8"))
                value = stored["evidence"]
                if (
                    digest(value) != stored["sha256"]
                    or hashlib.sha256(bytes.fromhex(value["raw_hex"])).hexdigest()
                    != value["raw_sha256"]
                ):
                    raise ValueError("artifact integrity mismatch")
                if value["run_id"] == run_id and value["target_ip"] == target_ip:
                    records.append(value)
            except (ValueError, KeyError, TypeError) as error:
                raise NeedsReview(
                    "Needs review: saved supplementary evidence failed integrity verification"
                ) from error
        return sorted(records, key=lambda item: item["captured_at"])[-8:]
