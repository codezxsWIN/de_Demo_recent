"""Nikto JSON -> findings. Produced by: nikto -h <target> -Format json -output out.json.

Nikto has no severity concept, so `native_severity` is always None; those findings rank on the
scalar fallback in weights.yaml, never on an invented severity.
"""

import re
from dataclasses import replace
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from vulnassess.errors import AdapterError
from vulnassess.readers._input import load_json_capture
from vulnassess.schema import Finding, Provenance

CVE = re.compile(r"CVE-\d{4}-\d{4,}")


def _urls(text: str) -> list[str]:
    return [token for token in str(text or "").split() if token.startswith("http")]


def _reports(payload: object, path: Path) -> list[dict]:
    if isinstance(payload, dict):
        candidates = [payload]
    elif isinstance(payload, list):
        candidates = [item for item in payload if isinstance(item, dict)]
    else:
        candidates = []
    reports = [item for item in candidates if isinstance(item.get("vulnerabilities"), list)]
    if not reports:
        raise AdapterError(f"nikto: {path} has no 'vulnerabilities' list; not a Nikto JSON report")
    return reports


def parse_nikto_json(path: str | Path, run_id: str, host_ip: str | None = None) -> list[Finding]:
    path, payload = load_json_capture(path, "nikto")

    seen = ""
    findings: list[Finding] = []
    record_index = 0

    for report in _reports(payload, path):
        address = host_ip or report.get("ip") or report.get("host")
        if not address:
            raise AdapterError(f"nikto: {path} report has neither 'ip' nor 'host'")
        try:
            port = int(str(report.get("port", 80)))
        except (TypeError, ValueError):
            port = 80

        for item in report["vulnerabilities"]:
            if not isinstance(item, dict):
                raise AdapterError(f"nikto: {path} contains a non-object vulnerability entry")
            message = str(item.get("msg", "")).strip()
            url = str(item.get("url", "") or "")
            native_id = str(item.get("id") or item.get("OSVDB") or "unknown")
            if native_id.upper() == "FAIL":
                raise AdapterError(
                    f"nikto: {path} contains a scan failure; no findings accepted from this report"
                )
            haystack = f"{message} {item.get('references', '')}"
            record_index += 1
            findings.append(
                Finding.make(
                    host_ip=str(address),
                    port=port,
                    protocol="tcp",
                    url=url or None,
                    tool="nikto",
                    tool_native_id=native_id,
                    title=message[:120] or f"Nikto finding {native_id}",
                    description=message,
                    evidence=message or url or native_id,
                    cve_ids=sorted(set(CVE.findall(haystack))),
                    cwe_ids=[],
                    reference_urls=_urls(item.get("references", "")),
                    native_severity=None,
                    native_confidence=None,
                    first_seen=seen,
                    last_seen=seen,
                    provenance=Provenance(
                        tool="nikto",
                        raw_path=str(path),
                        record_index=record_index,
                        run_id=run_id,
                    ),
                )
            )

    # Nikto reuses check 013587 and "/" for several different missing headers.
    # Preserve its native ID, but distinguish individual observations. Neither run
    # IDs nor report order participate, so repeat imports remain stable.
    return [
        replace(
            finding,
            id=str(
                uuid5(NAMESPACE_URL, f"nikto-observation-v1|{finding.id}|{finding.description}")
            ),
        )
        for finding in findings
    ]
