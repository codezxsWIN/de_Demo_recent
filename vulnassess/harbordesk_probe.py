"""Adapt identity-guarded HarborDesk fixture checks into canonical evidence.

High confidence describes a verified fixture condition, not a general exploit claim.
All active requests belong to the lab verifier, which checks LAB_ID before probing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnassess.errors import ScopeError
from vulnassess.schema import Finding, Provenance, Service

BASE = "http://127.0.0.1:8787/"
# Trusted metadata never comes from target-controlled titles, URLs, or severities.
# title, path, CWE, severity, port, scheme
CHECKS = {
    "HD-01": ("Missing browser security headers", "/", "CWE-693", "Low", 8787, "http"),
    "HD-02": ("SQL injection in customer search", "/api/customers", "CWE-89", "High", 8787, "http"),
    "HD-03": ("SQL injection bypasses login", "/api/login", "CWE-89", "High", 8787, "http"),
    "HD-04": (
        "Order object authorization bypass",
        "/api/orders/2002",
        "CWE-639",
        "High",
        8787,
        "http",
    ),
    "HD-05": ("Unescaped HTML marker reflected", "/search", "CWE-79", "Medium", 8787, "http"),
    "HD-06": (
        "Administration accessible without authentication",
        "/admin",
        "CWE-306",
        "High",
        8787,
        "http",
    ),
    "HD-07": ("Debug configuration exposed", "/debug/config", "CWE-200", "Medium", 8787, "http"),
    "HD-08": (
        "Session cookie missing security attributes",
        "/api/login",
        "CWE-614",
        "Low",
        8787,
        "http",
    ),
    "HD-09": (
        "Ticket object authorization bypass",
        "/api/tickets/3002",
        "CWE-639",
        "High",
        8787,
        "http",
    ),
    "HD-10": (
        "Document object authorization bypass",
        "/api/documents/4002",
        "CWE-639",
        "High",
        8787,
        "http",
    ),
    "HD-11": (
        "Profile accessible without authentication",
        "/api/profile",
        "CWE-306",
        "Medium",
        8787,
        "http",
    ),
    "HD-13": ("Anonymous FTP exposes fixture files", "/", "CWE-306", "Medium", 2121, "ftp"),
    "HD-14": ("FTP uses cleartext transport", "/", "CWE-319", "Medium", 2121, "ftp"),
    "HD-15": ("Expired TLS certificate", "/", "CWE-295", "Medium", 8443, "https"),
    "HD-16": (
        "TLS management accessible without authentication",
        "/admin",
        "CWE-306",
        "High",
        8443,
        "https",
    ),
}


def eligible(target_ip: str, endpoint: dict[str, Any] | None) -> bool:
    """Never resolve aliases or trust a banner as authorization for active checks."""
    return bool(
        target_ip == "127.0.0.1"
        and endpoint
        and endpoint.get("host") == "127.0.0.1"
        and endpoint.get("scheme") == "http"
        and type(endpoint.get("port")) is int
        and endpoint["port"] == 8787
        and endpoint.get("path") == "/"
    )


def _bounded_json(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False)
    if len(text) <= 2048:
        return text
    # Keep valid JSON and label the preview; the full result remains in the receipt.
    preview = text[:1800]
    while True:
        bounded = json.dumps({"receipt_preview": preview, "truncated": True})
        if len(bounded) <= 2048:
            return bounded
        preview = preview[: len(preview) // 2]


def _rows(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    checks = receipt.get("checks")
    network = receipt.get("network_checks", [])
    if not isinstance(checks, list) or not isinstance(network, list):
        raise ValueError("HarborDesk receipt checks must be lists")
    # Some verifier versions include network checks in checks as well.
    rows = list(checks)
    for row in network:
        if row not in rows:
            rows.append(row)
    identities = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("id"), str)
            or row["id"] in identities
            or type(row.get("observed_intentional_weakness")) is not bool
            or "evidence" not in row
        ):
            raise ValueError("HarborDesk receipt contains invalid or duplicate checks")
        identities.add(row["id"])
        metadata = CHECKS.get(row["id"])
        if (
            metadata
            and "port" in row
            and (type(row["port"]) is not int or row["port"] != metadata[4])
        ):
            raise ValueError("HarborDesk check port differs from trusted metadata")
    return rows


def run(
    scope, target_ip: str, endpoint: dict[str, Any] | None, directory: Path
) -> tuple[list[Finding], dict[str, Any]]:
    """Return canonical findings and the preserved, validated verifier receipt."""
    if (
        not eligible(target_ip, endpoint)
        or not scope.contains(target_ip)
        or scope.is_canary(target_ip)
    ):
        raise ScopeError("HarborDesk verification requires authorized http://127.0.0.1:8787/")
    from labs.harbordesk import verify as verifier
    from labs.harbordesk.app import LAB_ID

    capture = Path(directory) / "harbordesk-checks.json"
    # Reserve the receipt before active checks; a repeat must not replace evidence.
    with capture.open("x", encoding="utf-8") as handle:
        receipt = verifier.verify(BASE, extended=True, include_network=True)
        json.dump(receipt, handle, ensure_ascii=True, indent=2, allow_nan=False)
    if (
        not isinstance(receipt, dict)
        or receipt.get("lab_id") != LAB_ID
        or receipt.get("target") not in (BASE, BASE.rstrip("/"))
    ):
        raise ValueError("HarborDesk receipt identity does not match the fixture")
    rows = _rows(receipt)
    findings = []
    for index, row in enumerate(rows, 1):
        metadata = CHECKS.get(row["id"])
        if metadata is None or row["observed_intentional_weakness"] is not True:
            continue
        title, path, cwe, severity, port, scheme = metadata
        findings.append(
            Finding.make(
                host_ip=target_ip,
                port=port,
                protocol="tcp",
                tool="harbordesk",
                tool_native_id=row["id"],
                title=title,
                url=f"{scheme}://127.0.0.1:{port}{path}",
                description=(
                    "Known intentional HarborDesk fixture condition verified by bounded lab checks. "
                    "High native confidence applies only to this fixture condition; no CVE or "
                    "general exploitability is asserted. HTML checks use a safe marker, not script execution."
                ),
                evidence=_bounded_json(
                    {
                        "id": row["id"],
                        "observed_intentional_weakness": True,
                        "evidence": row["evidence"],
                    }
                ),
                cwe_ids=[cwe],
                native_severity=severity,
                native_confidence="high",
                provenance=Provenance(
                    tool="harbordesk",
                    raw_path=str(capture.resolve()),
                    record_index=index,
                    run_id="live",
                ),
            )
        )
    return findings, receipt


def coverage(receipt: dict[str, Any]) -> str:
    rows = _rows(receipt)
    passed = sum(row["observed_intentional_weakness"] for row in rows)
    errors = [
        row["id"]
        for row in rows
        if isinstance(row["evidence"], dict) and "check_error" in row["evidence"]
    ]
    status = "partial" if errors else "complete"
    detail = f"{status}: {passed}/{len(rows)} verified intentional fixture weaknesses observed"
    if errors:
        detail += "; check errors=" + ",".join(errors)
    if "network_status" in receipt:
        detail += "; network_status=" + _bounded_json(receipt["network_status"])
    if not any(row["id"] in {"HD-13", "HD-14", "HD-15", "HD-16"} for row in rows):
        detail += "; network checks not configured or not returned; no network coverage claimed"
    for key in ("secure_controls", "secure_control_results", "secure_checks"):
        if key in receipt:
            controls = receipt[key]
            if isinstance(controls, list):
                passed_controls = sum(
                    isinstance(item, dict) and item.get("passed") is True for item in controls
                )
                detail += (
                    f"; {key}={passed_controls}/{len(controls)} passed; full details in raw receipt"
                )
            else:
                detail += f"; {key}=not established"
    return detail


def confirmed_services(receipt: dict[str, Any]) -> tuple[Service, ...]:
    """Describe only protocol observations from the fixed network verifier checks."""
    services = {}
    for row in _rows(receipt):
        evidence = row["evidence"]
        if not isinstance(evidence, dict) or "check_error" in evidence:
            continue
        banner = evidence.get("banner")
        if row["id"] == "HD-13" and isinstance(banner, str) and banner.startswith("220"):
            services[2121] = Service(2121, "tcp", name="ftp", banner=banner[:2048])
        if row["id"] in ("HD-15", "HD-16") and evidence.get("tls_version") in (
            "TLSv1",
            "TLSv1.1",
            "TLSv1.2",
            "TLSv1.3",
        ):
            services[8443] = Service(8443, "tcp", name="https", tls=True)
    # These fixed control identities are emitted only after their corresponding
    # FTP response / TLS handshake and HTTP response have actually completed.
    controls = receipt.get("secure_controls", [])
    if isinstance(controls, list):
        passed = {
            row.get("id")
            for row in controls
            if isinstance(row, dict)
            and row.get("passed") is True
            and isinstance(row.get("id"), str)
        }
        if "HC-11" in passed:
            services[2122] = Service(2122, "tcp", name="ftp")
        if passed & {"HC-12", "HC-13"}:
            services[8444] = Service(8444, "tcp", name="https", tls=True)
    return tuple(services[port] for port in sorted(services))
