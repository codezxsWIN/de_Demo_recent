"""ZAP JSON -> findings. Produced by: zap-baseline.py -t <target> -J out.json."""

import re
from datetime import UTC
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit

from vulnassess.errors import AdapterError
from vulnassess.readers._input import load_json_capture
from vulnassess.schema import Finding, Provenance

RISK = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High"}
CONFIDENCE = {"0": "False Positive", "1": "Low", "2": "Medium", "3": "High", "4": "User Confirmed"}
PARAGRAPH = re.compile(r"</?p>", re.IGNORECASE)


def _plain(text: str | None) -> str:
    return PARAGRAPH.sub(" ", text or "").strip()


def _generated(payload: dict) -> str:
    raw = payload.get("@generated")
    if raw:
        try:
            return parsedate_to_datetime(raw).astimezone(UTC).isoformat()
        except (TypeError, ValueError):
            pass
    return ""


def _host_from(site: dict) -> str | None:
    host = site.get("@host")
    if host:
        return str(host)
    name = site.get("@name")
    if name:
        return urlsplit(str(name)).hostname
    return None


def _port_of(url: str, site: dict) -> int:
    parts = urlsplit(url)
    if parts.port:
        return int(parts.port)
    if parts.scheme == "https":
        return 443
    if parts.scheme == "http":
        return 80
    try:
        return int(site.get("@port", 80))
    except (TypeError, ValueError):
        return 80


def parse_zap_json(path: str | Path, run_id: str, host_ip: str | None = None) -> list[Finding]:
    path, payload = load_json_capture(path, "zap")
    if not isinstance(payload, dict) or not isinstance(payload.get("site"), list):
        raise AdapterError(f"zap: {path} has no top-level 'site' list; not a ZAP JSON report")

    seen = _generated(payload)
    findings: list[Finding] = []
    record_index = 0

    for site in payload["site"]:
        if not isinstance(site, dict):
            raise AdapterError(f"zap: {path} contains a non-object site entry")
        address = host_ip or _host_from(site)
        if not address:
            raise AdapterError(f"zap: {path} site entry has neither '@host' nor a usable '@name'")

        for alert in site.get("alerts", []):
            cwe = str(alert.get("cweid", "")).strip()
            cwe_ids = [] if cwe in {"", "-1", "0"} else [f"CWE-{cwe}"]
            references = [
                token
                for token in _plain(alert.get("reference")).split()
                if token.startswith("http")
            ]
            severity = RISK.get(str(alert.get("riskcode", "")).strip())
            confidence = CONFIDENCE.get(str(alert.get("confidence", "")).strip())
            instances = alert.get("instances") or [{}]

            for instance in instances:
                url = instance.get("uri") or site.get("@name") or ""
                evidence = instance.get("evidence") or instance.get("param") or alert.get("name")
                record_index += 1
                findings.append(
                    Finding.make(
                        host_ip=address,
                        port=_port_of(str(url), site),
                        protocol="tcp",
                        url=str(url) or None,
                        tool="zap",
                        tool_native_id=str(alert.get("pluginid", "")),
                        title=str(alert.get("name", "")),
                        description=_plain(alert.get("desc")),
                        evidence=str(evidence),
                        cve_ids=[],
                        cwe_ids=cwe_ids,
                        reference_urls=references,
                        native_severity=severity,
                        native_confidence=confidence,
                        first_seen=seen,
                        last_seen=seen,
                        provenance=Provenance(
                            tool="zap",
                            raw_path=str(path),
                            record_index=record_index,
                            run_id=run_id,
                        ),
                    )
                )

    return findings
