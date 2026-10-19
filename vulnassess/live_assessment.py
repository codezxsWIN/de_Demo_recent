"""One explicit, bounded live target run for the loopback workbench."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from tempfile import mkdtemp
from typing import Any

from vulnassess import (
    analyst,
    capture_history,
    context,
    intel,
    intel_online,
    orchestrator,
    protocols,
    redis_probe,
    scoring,
)
from vulnassess.ai_boundary import digest
from vulnassess.errors import AdapterError, ConfigError, IntelUnavailable, NeedsReview
from vulnassess.readers import parse_nikto_json, parse_nmap_xml
from vulnassess.readers._input import read_capture, reject_xml_declarations, validate_tree
from vulnassess.scan_plans import PlanExecution
from vulnassess.settings import Settings
from vulnassess.store import Store

Progress = Callable[[str, str, str], None]


def nmap_binary() -> str | None:
    return nmap_probe()[0]


def _registered_nmap_binary() -> str | None:
    if os.name != "nt":
        return None
    try:
        import winreg

        key_name = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Nmap"
        for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, key_name, 0, winreg.KEY_READ | view
                ) as key:
                    install_dir = winreg.QueryValueEx(key, "InstallLocation")[0]
                if isinstance(install_dir, str):
                    binary = Path(install_dir) / "nmap.exe"
                    if binary.is_file():
                        return str(binary)
            except OSError:
                continue
    except ImportError:
        return None
    return None


def nmap_probe() -> tuple[str | None, str]:
    """Explain executable discovery and check launchability without scanning."""
    configured = os.environ.get("VULNASSESS_NMAP_BIN", "").strip()
    if configured:
        binary = shutil.which(configured)
        if binary:
            source = "configured by VULNASSESS_NMAP_BIN"
        else:
            return None, f"VULNASSESS_NMAP_BIN points to a missing executable: {configured}"
    else:
        binary = shutil.which("nmap")
        source = "found on the server PATH"
        if not binary:
            binary = _registered_nmap_binary()
            source = "found in the Windows install registry"
        if not binary:
            return None, (
                "Nmap is not on the server PATH and no usable Windows install was found; "
                "set VULNASSESS_NMAP_BIN to the full nmap.exe path"
            )
    try:
        version = subprocess.run(
            [binary, "-V"], capture_output=True, text=True, timeout=10, check=False
        )
    except subprocess.TimeoutExpired:
        return None, f"Nmap was found at {binary} but its version check timed out"
    except OSError as error:
        return None, f"Nmap was found at {binary} but could not start: {error}"
    if version.returncode != 0:
        return None, f"Nmap was found at {binary} but its version check exited {version.returncode}"
    missing = _nmap_data_error(binary)
    if missing:
        return None, missing
    return binary, f"Nmap {source}: {binary}"


def _nmap_data_error(binary: str) -> str | None:
    """Windows portable installations need scanner data, not just an executable."""
    if os.name != "nt":
        return None
    directory = Path(os.environ.get("NMAPDIR") or Path(binary).resolve().parent)
    missing = []
    for name in ("nmap-protocols", "nmap-services", "nmap-service-probes"):
        path = directory / name
        try:
            with path.open("rb") as handle:
                if not handle.read(1):
                    missing.append(str(path))
        except OSError:
            missing.append(str(path))
    if missing:
        return (
            "Nmap installation is incomplete: MISSING readable scanner data: "
            + "; ".join(missing)
            + ". A version check is not scan readiness. Supply a complete approved Nmap installation; "
            "NMAPDIR, if set, must point to its complete data directory. No scan started."
        )
    return None


def _nmap_failure_detail(completed: subprocess.CompletedProcess, capture: Path) -> str:
    detail = completed.stderr or completed.stdout or ""
    if not detail.strip() and capture.is_file():
        try:
            path, raw = read_capture(capture, "nmap")
            reject_xml_declarations(raw, path, "nmap")
            root = ET.fromstring(raw)
            validate_tree(root, path, "nmap")
            finished = root.find("runstats/finished")
            if finished is not None:
                detail = finished.get("errormsg", "")
        except (AdapterError, ET.ParseError, OSError):
            detail = "Scanner diagnostic XML was missing or invalid"
    detail = re.sub(r"[\x00-\x20\x7f]+", " ", detail).strip()[:500]
    return detail or (
        "No XML report produced" if not capture.is_file() else "No diagnostic supplied"
    )


def assessment_summary(
    target: str,
    target_ip: str,
    services: list[dict[str, Any]],
    payload: dict[str, Any],
    result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    scan_status = payload.get("scan_status")
    if scan_status is not None and (
        not isinstance(scan_status, str) or scan_status not in ("complete", "partial")
    ):
        raise ConfigError("Recorded collection status must be complete or partial when supplied")
    findings = payload["findings"]
    scores = payload["scores"]
    if not isinstance(findings, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"].strip()
        for item in findings
    ):
        raise ConfigError("Recorded findings require non-empty identities")
    if not isinstance(scores, list) or any(not isinstance(item, dict) for item in scores):
        raise ConfigError("Recorded scores must be a list of priority records")
    finding_ids = {item["id"] for item in findings}
    if len(finding_ids) != len(findings):
        raise ConfigError("Recorded finding identities are duplicated")
    enrichments = payload["enrichments"]
    if not isinstance(enrichments, list) or any(
        not isinstance(item, dict)
        or not isinstance(item.get("finding_id"), str)
        or item["finding_id"] not in finding_ids
        for item in enrichments
    ):
        raise ConfigError("Recorded enrichment is invalid or not bound to the collected findings")
    scored_ids: set[str] = set()
    for item in scores:
        identity, risk = item.get("finding_id"), item.get("risk")
        if (
            not isinstance(identity, str)
            or identity not in finding_ids
            or identity in scored_ids
            or ("host_ip" in item and item["host_ip"] != target_ip)
            or type(risk) not in (int, float)
            or not 0 <= risk <= 100
            or not math.isfinite(risk)
            or item.get("band") not in ("Critical", "High", "Medium", "Low")
        ):
            raise ConfigError(
                "Recorded score is invalid, duplicated, or not bound to this target's findings"
            )
        scored_ids.add(identity)
    unscored_records = payload.get("unscored_findings", [])
    if not isinstance(unscored_records, list) or any(
        not isinstance(item, dict)
        or not isinstance(item.get("finding_id"), str)
        or item["finding_id"] not in finding_ids - scored_ids
        or not isinstance(item.get("reason"), str)
        or not item["reason"].strip()
        for item in unscored_records
    ):
        raise ConfigError("Unscored findings require bound identities and a recorded reason")
    if len({item["finding_id"] for item in unscored_records}) != len(unscored_records):
        raise ConfigError("Unscored finding identities are duplicated")
    unscored_reasons = {
        item["finding_id"]: item.get("reason", "No deterministic priority was recorded")
        for item in unscored_records
    }
    unscored_findings = [
        {
            "finding_id": item["id"],
            "title": item.get("title", item["id"]),
            "reason": unscored_reasons.get(item["id"], "No deterministic priority was recorded"),
        }
        for item in findings
        if item["id"] not in scored_ids
    ]
    profile = next(
        (item for item in payload.get("context", []) if item.get("host_ip") == target_ip), {}
    )
    analysis = (result or {}).get("analysis", {})
    batches = (result or {}).get("batches", [])
    batch_coverage = (result or {}).get("batch_coverage")
    included_findings: int | None = None
    if batches:
        if not isinstance(batch_coverage, dict):
            raise NeedsReview("AI batch coverage metadata is missing or invalid")
        included_findings = batch_coverage.get("findings_included")
        if type(included_findings) is not int or not 0 <= included_findings <= len(findings):
            raise NeedsReview("AI batch coverage count is not supported by the collected findings")
    cve_ids = sorted({cve for finding in findings for cve in finding.get("cve_ids", [])})
    feed_status = payload.get("feed_status") or []
    scanner_coverage = payload.get("scanner_coverage")
    scanner_coverage = scanner_coverage if isinstance(scanner_coverage, dict) else {}
    collection_failures = payload.get("collection_failures", [])

    def recorded_coverage(tool: str) -> str | None:
        value = scanner_coverage.get(tool)
        return value.strip() if isinstance(value, str) and value.strip() else None

    nmap_coverage = recorded_coverage("nmap")
    nikto_coverage = recorded_coverage("nikto")
    nessus_coverage = recorded_coverage("nessus")
    return {
        "target": target,
        "resolved_ip": target_ip,
        "scan_status": scan_status or "unknown",
        "collection_failures": collection_failures,
        "service_count": len(services),
        **({"self_defence": payload["self_defence"]} if "self_defence" in payload else {}),
        "finding_count": len(findings),
        "scored_finding_count": len(scored_ids),
        "unscored_finding_count": len(findings) - len(scored_ids),
        "unscored_findings": unscored_findings,
        "priorities": scores,
        "cve_evidence": cve_evidence_rows(payload),
        "intelligence": {
            "mode": (
                "on_demand"
                if payload.get("intelligence_mode") == "on_demand"
                else "offline"
                if feed_status
                else "unavailable"
                if cve_ids
                else "not_applicable"
            ),
            "checked_cves": cve_ids if feed_status else [],
            "matched_findings": len({item["finding_id"] for item in enrichments}),
            "sources": feed_status,
        },
        "context": {
            "role": profile.get("role", {}).get("value", "unknown"),
            "exposure": profile.get("exposure", {}).get("value", "unknown"),
        },
        "conclusion": (
            "No vulnerability findings were recorded by the scanners that completed; this is not proof that the target is safe."
            if not findings
            else f"{len(findings)} scanner findings have deterministic priorities."
            if len(scored_ids) == len(findings)
            else f"{len(findings)} scanner findings were recorded; no deterministic priorities were recorded."
            if not scored_ids
            else f"{len(findings)} scanner findings were recorded; {len(scored_ids)} have deterministic priorities and {len(findings) - len(scored_ids)} remain unscored."
        ),
        "scanner_coverage": scanner_coverage,
        "coverage_gaps": [
            *[
                f"Unscored finding {item['finding_id']}: {item['reason']}"
                for item in unscored_findings
            ],
            *[
                f"Requested {item['stage']} failed: {item['detail']}"
                for item in collection_failures
            ],
            f"Recorded Nmap coverage: {nmap_coverage}."
            if nmap_coverage
            else "Nmap coverage was not recorded; no port/profile coverage is claimed.",
            *(
                []
                if nikto_coverage and nikto_coverage.startswith("complete")
                else [f"Nikto web checks: {nikto_coverage}."]
                if nikto_coverage
                else ["Nikto coverage was not recorded; no completed web scan is established."]
            ),
            f"Nessus coverage: {nessus_coverage}."
            if nessus_coverage
            else "Nessus coverage was not recorded; no Nessus assessment is established.",
            *(
                ["No vulnerability intelligence feed snapshots were available."]
                if findings and not payload.get("feed_status")
                else []
            ),
        ],
        "validated_ai_summary": (
            f"{included_findings} findings included in {len(batches)} validated AI batches."
            if batches
            else analysis.get("summary")
        ),
        "ai_coverage": batch_coverage,
        "next_actions": [] if batches else analysis.get("recommended_actions", []),
        "uncertainties": (
            [
                "AI claims and citations are scoped to each batch; relationships across batches were not assessed."
            ]
            if batches
            else analysis.get("uncertainties", [])
        ),
    }


def cve_evidence_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Display joins only; never create findings or modify canonical scores."""
    rows = []
    for finding in payload["findings"]:
        for cve in finding.get("cve_ids", []):
            match = next(
                (
                    item
                    for item in payload["enrichments"]
                    if item["finding_id"] == finding["id"] and item["cve_id"] == cve
                ),
                {},
            )
            score = next(
                (
                    item
                    for item in payload["scores"]
                    if item["finding_id"] == finding["id"] and item.get("cve_id") == cve
                ),
                {},
            )
            dates = dict(match.get("feed_dates", {}))
            kev_checked = bool(match) and "kev" in payload.get("feed_status", [])
            rows.append(
                {
                    "finding_id": finding["id"],
                    "cve_id": cve,
                    "title": finding.get("title", ""),
                    "tool": finding.get("tool", "unknown"),
                    "port": finding.get("port"),
                    "evidence": finding.get("evidence", ""),
                    "raw_path": finding.get("provenance", {}).get("raw_path"),
                    "cvss_base": match.get("cvss40_base")
                    if match.get("cvss40_base") is not None
                    else match.get("cvss31_base"),
                    "epss": match.get("epss"),
                    "kev_status": ("listed" if match.get("kev") else "not_listed")
                    if kev_checked
                    else "not_checked",
                    "feed_dates": dates,
                    "priority": {"risk": score["risk"], "band": score["band"]} if score else None,
                }
            )
    return rows


def _validated_endpoint(check: dict[str, Any]) -> dict[str, Any] | None:
    endpoint = check.get("endpoint")
    if endpoint is None:
        return None
    if not isinstance(endpoint, dict):
        raise ConfigError("Target endpoint metadata is invalid")
    host = endpoint.get("host")
    scheme = endpoint.get("scheme")
    port = endpoint.get("port")
    path = endpoint.get("path")
    valid_host = False
    if isinstance(host, str):
        try:
            ip_address(host)
            valid_host = True
        except ValueError:
            valid_host = bool(re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*", host, re.IGNORECASE))
    if (
        not isinstance(host, str)
        or not valid_host
        or scheme not in ("http", "https")
        or type(port) is not int
        or not 1 <= port <= 65535
        or not isinstance(path, str)
        or not path.startswith("/")
        or len(path) > 2048
        or any(ord(char) < 32 for char in path)
    ):
        raise ConfigError("Target endpoint metadata is invalid")
    return {"host": host.lower(), "scheme": scheme, "port": port, "path": path}


def _scan_requested_endpoint(
    binary: str,
    target_ip: str,
    endpoint: dict[str, Any] | None,
    settings: Settings,
    directory: Path,
    host,
    findings: list,
    emit: Progress,
    plan_execution: PlanExecution | None = None,
) -> tuple[Any, list, str, str]:
    if endpoint is None:
        emit("endpoint_scan", "skipped", "No explicit URL endpoint or port was supplied")
        emit("nikto", "skipped", "No explicit authorized web URL was supplied")
        return host, findings, "not requested", "not requested"

    port = endpoint["port"]
    emit("endpoint_scan", "running", f"Checking the requested TCP/{port} on the pinned IP")
    capture = directory / "requested-endpoint.xml"
    command = [
        binary,
        "-n",
        "-Pn",
        "-sT",
        "-p",
        str(port),
        "-sV",
        "--version-light",
        "-T3",
        "-oX",
        str(capture),
        target_ip,
    ]
    try:
        if plan_execution:
            plan_execution.recheck(
                "nmap", target_ip, digest(Settings(settings.config_dir).raw["scope.yaml"])
            )
        timeout = plan_execution.remaining("nmap", 90) if plan_execution else 90
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        if result.returncode != 0 or not capture.is_file():
            detail = (result.stderr or result.stdout or f"Nmap exited {result.returncode}").strip()
            emit("endpoint_scan", "error", f"Requested-port check failed: {detail[:400]}")
            emit(
                "nikto",
                "skipped",
                "The requested port could not be verified; Nikto was not launched",
            )
            return host, findings, "failed", "skipped"
        hosts, port_findings = parse_nmap_xml(capture, "live")
    except (OSError, subprocess.TimeoutExpired, AdapterError) as error:
        emit("endpoint_scan", "error", f"Requested-port check failed: {type(error).__name__}")
        emit("nikto", "skipped", "The requested port could not be verified; Nikto was not launched")
        return host, findings, "failed", "skipped"

    matches = [item for item in hosts if item.ip == target_ip]
    if len(matches) != 1:
        emit(
            "endpoint_scan",
            "error",
            "Nmap did not confirm the pinned target for the requested port",
        )
        emit("nikto", "skipped", "The requested port was not verified on the pinned target")
        return host, findings, "failed", "skipped"
    endpoint_host = matches[0]
    services = {(service.port, service.protocol): service for service in host.services}
    services.update(
        {(service.port, service.protocol): service for service in endpoint_host.services}
    )
    host = replace(host, services=tuple(services[key] for key in sorted(services)))
    findings.extend(port_findings)
    is_open = any(
        service.port == port and service.protocol == "tcp" for service in endpoint_host.services
    )
    emit(
        "endpoint_scan",
        "complete",
        f"Requested TCP/{port} is {'open' if is_open else 'not open'} on the pinned target",
    )
    if not is_open:
        emit("nikto", "skipped", "The requested port is not open; Nikto was not launched")
        return host, findings, "closed", "skipped"

    if plan_execution and not plan_execution.includes("nikto"):
        emit("nikto", "skipped", "Not in the approved scan plan; no web or Redis probe launched")
        return host, findings, "complete", "not in approved plan"

    tags = settings.scope.tags(target_ip)
    if tags.get("environment") != "test":
        emit(
            "nikto",
            "skipped",
            "Nikto is limited to an exact in-scope asset tagged environment:test",
        )
        return host, findings, "complete", "skipped"

    if any(
        service.port == port and service.protocol == "tcp" and service.name == "redis"
        for service in endpoint_host.services
    ):
        if plan_execution:
            emit(
                "nikto",
                "skipped",
                "Observed protocol differs from the approved web tier; Redis probe requires a separate plan",
            )
            return host, findings, "redis not inspected", "not HTTP"
        emit(
            "nikto", "skipped", "Nmap identified Redis, not an HTTP service; no Nikto scan launched"
        )
        if endpoint["scheme"] != "http":
            emit(
                "endpoint_scan",
                "complete",
                "Redis observed; plaintext inspection not enabled for a TLS URL",
            )
            return host, findings, "redis not inspected", "skipped"
        emit(
            "endpoint_scan",
            "running",
            "Redis: fixed Lua type inspection; no keys, files or OS commands accessed",
        )
        try:
            observed = redis_probe.run(settings.scope, target_ip, port, directory)
        except (OSError, TimeoutError) as error:
            emit(
                "endpoint_scan",
                "error",
                f"Redis configuration check unavailable ({type(error).__name__})",
            )
            return host, findings, "redis inspection failed", "skipped"
        if observed is not None:
            findings.append(observed)
        detail = (
            "Redis Lua sandbox exposes package.loadlib: CVE-2022-0543 configuration observed; RCE not attempted"
            if observed
            else "Redis inspection did not establish the CVE-2022-0543 configuration; not proof of safety"
        )
        emit("endpoint_scan", "complete", detail)
        return host, findings, detail, "not HTTP"

    # A URL supplies an address and requested port, not evidence of its protocol.
    # In particular, tcpwrapped does not justify web checks or a Redis probe.
    if not any(
        service.port == port and protocols.is_http(service) for service in endpoint_host.services
    ):
        emit(
            "nikto",
            "skipped",
            "HTTP was not identified on the requested port; Nikto was not launched",
        )
        return host, findings, "complete", "not HTTP"

    readiness = orchestrator.scanner_status("nikto")
    if readiness["status"] != "available":
        emit("nikto", "error", readiness["detail"][:500])
        return host, findings, "complete", "failed"

    argv = orchestrator.scanner_argv("nikto")
    if argv is None:
        emit("nikto", "error", "Nikto executable became unavailable after preflight")
        return host, findings, "complete", "failed"

    output = directory / "nikto.json"
    timeout = (
        plan_execution.before(
            "nikto", target_ip, digest(Settings(settings.config_dir).raw["scope.yaml"])
        )
        if plan_execution
        else 150
    )
    rendered_ip = f"[{target_ip}]" if ":" in target_ip else target_ip
    target_url = f"{endpoint['scheme']}://{rendered_ip}:{port}{endpoint['path']}"
    host_header = endpoint["host"] + (f":{port}" if port not in (80, 443) else "")
    nikto_command = [
        *argv,
        "-host",
        target_url,
        "-Add-header",
        f"Host: {host_header}",
        "-Format",
        "json",
        "-output",
        str(output),
        "-nointeractive",
        "-nocheck",
        "-nolookup",
        "-Tuning",
        "123b",
        "-maxtime",
        f"{min(120, timeout)}s",
    ]
    if endpoint["scheme"] == "https":
        nikto_command.append("-ssl")
    emit("nikto", "running", f"Nikto: bounded checks against pinned {target_ip}:{port}")
    try:
        result = subprocess.run(
            nikto_command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=orchestrator._nikto_cwd(argv),
        )
        if result.returncode != 0 or not output.is_file():
            detail = (result.stderr or result.stdout or f"Nikto exited {result.returncode}").strip()
            emit("nikto", "error", detail[:500])
            return host, findings, "complete", "failed"
        nikto_findings = parse_nikto_json(output, "live", host_ip=target_ip)
    except (OSError, subprocess.TimeoutExpired, AdapterError) as error:
        emit("nikto", "error", f"Nikto failed: {type(error).__name__}")
        return host, findings, "complete", "failed"
    findings.extend(nikto_findings)
    emit("nikto", "complete", f"Nikto completed; {len(nikto_findings)} findings parsed")
    return host, findings, "complete", "complete"


def run(
    target: str,
    check: dict[str, Any],
    config_dir: Path,
    *,
    provider: str,
    on_progress: Progress,
    database: str | Path | None = None,
    on_capture: Callable[[dict[str, Any]], None] | None = None,
    on_case: Callable[[dict[str, Any]], None] | None = None,
    allow_fallback: bool = False,
    plan_execution: PlanExecution | None = None,
    self_defence: bool = False,
) -> dict[str, Any]:
    """Scan one scoped, DNS-pinned IP and analyze its in-memory evidence."""
    if provider not in ("ollama", "openrouter", "groq", "groq_qwen", "google"):
        raise ConfigError("Unknown analyst provider")
    addresses = check.get("resolved_ips") or []
    if check.get("status") not in ("ready", "needs-tools", "needs-pinning") or len(addresses) != 1:
        raise ConfigError(check.get("reason") or "Target must resolve to one authorised address")
    target_ip = addresses[0]
    endpoint = _validated_endpoint(check)
    if self_defence and (target_ip != "127.0.0.1" or endpoint or plan_execution):
        raise ConfigError("Self-defence only checks the local VulnAssess machine")
    settings = Settings(config_dir)
    if settings.scope.is_canary(target_ip) or not settings.scope.contains(target_ip):
        raise ConfigError("Target is outside the authorised scope")
    binary = nmap_binary()
    if binary is None:
        raise ConfigError("Nmap is not installed or VULNASSESS_NMAP_BIN is not configured")
    stage_events: list[tuple[str, str, str]] = []

    def emit(stage: str, state: str, detail: str) -> None:
        stage_events.append((stage, state, detail))
        on_progress(stage, state, detail)

    emit("scope", "complete", f"{target} pinned to authorised {target_ip}")
    emit("model", "complete", analyst.configuration_detail(provider))
    emit("scanner", "running", "Nmap: common 100 TCP ports, light service detection")
    raw_root = Path(config_dir).resolve().parent / "data" / "live" / "raw"
    raw_root.mkdir(parents=True, exist_ok=True)
    directory = Path(mkdtemp(prefix="assessment-", dir=raw_root))
    capture = directory / "nmap.xml"
    command = [
        binary,
        "-n",
        "-Pn",
        "-sT",
        "--top-ports",
        "100",
        "-sV",
        "--version-light",
        "-T3",
        "-oX",
        str(capture),
        target_ip,
    ]
    timeout = (
        plan_execution.before("nmap", target_ip, digest(Settings(config_dir).raw["scope.yaml"]))
        if plan_execution
        else 180
    )
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as error:
        detail = f"Light Nmap scan timed out after {timeout} seconds"
        emit("scanner", "error", detail)
        raise ConfigError(detail) from error
    except OSError as error:
        detail = f"Nmap could not start ({type(error).__name__}); check the configured executable and runtime"
        emit("scanner", "error", detail)
        raise ConfigError(detail) from error
    if completed.returncode != 0 or not capture.is_file():
        detail = f"Light Nmap scan failed (exit {completed.returncode}): {_nmap_failure_detail(completed, capture)}"
        emit("scanner", "error", detail)
        raise ConfigError(detail)
    hosts, findings = parse_nmap_xml(capture, "live")
    matching = [host for host in hosts if host.ip == target_ip]
    if len(matching) != 1:
        raise ConfigError("Nmap did not return exactly the pinned target")
    host, findings, endpoint_scan_status, nikto_status = _scan_requested_endpoint(
        binary,
        target_ip,
        endpoint,
        settings,
        directory,
        matching[0],
        findings,
        emit,
        plan_execution,
    )
    emit(
        "scanner",
        "complete",
        f"{len(host.services)} open services; {len(findings)} vulnerability findings",
    )
    device_check = None
    if self_defence:
        from vulnassess.self_defence import collect, compare, previous_capture

        emit(
            "canonical",
            "running",
            "Reading local firewall and antivirus status; no settings changed",
        )
        device_check = collect()
        device_check["comparison"] = compare(previous_capture(raw_root), device_check)
    emit(
        "canonical",
        "complete",
        f"Parsed {len(host.services)} services and {len(findings)} findings; raw scanner files retained locally"
        + ("; local protection observations collected" if self_defence else ""),
    )
    captured_at = datetime.now(UTC).isoformat()
    enrichments = []
    feed_meta = {}
    cve_ids = sorted({cve for finding in findings for cve in finding.cve_ids})
    feed_failure = (
        "No scanner-named CVE IDs to look up"
        if not cve_ids
        else "No operational intelligence cache available"
    )
    # Public CVE lookups write only to the separate intelligence cache. They never
    # persist the live target, findings, context, or scores in the assessment DB.
    feed_path = (
        Path(database).with_name("intel-cache.db")
        if database and not str(database).startswith(("postgres:", "postgresql:", "env:"))
        else None
    )
    if feed_path is not None and cve_ids:
        try:
            with Store(feed_path) as store:
                feed_meta = store.feeds_meta()
                if any(intel.is_fixture_source(item["path"]) for item in feed_meta.values()):
                    feed_meta = {}
                    feed_failure = (
                        "Only test fixture feeds are loaded; no operational intelligence claimed"
                    )
                else:
                    offline_ready = (
                        all(feed in feed_meta for feed in ("nvd", "epss", "kev"))
                        and feed_meta["nvd"]["path"] != intel_online.NVD_URL
                        and all(store.cve(cve) is not None for cve in cve_ids)
                    )
                    if offline_ready:
                        for feed in ("nvd", "epss", "kev"):
                            emit(
                                feed,
                                "complete",
                                f"Offline snapshot dated {feed_meta[feed].get('file_date') or 'unknown'}; coverage limited to loaded rows",
                            )
                    else:
                        intel_online.sync_cves(cve_ids, store, on_progress=emit)
                    feed_meta = store.feeds_meta()
                if findings and feed_meta:
                    dates = {name: item.get("file_date") or "" for name, item in feed_meta.items()}
                    matching_store = (
                        intel_online.requested_cache(store, cve_ids)
                        if feed_meta.get("nvd", {}).get("path") == intel_online.NVD_URL
                        else store
                    )
                    for finding in findings:
                        matches, _ = intel.match_finding_with_trace(
                            finding, host.services, matching_store, dates
                        )
                        enrichments.extend(matches)
        except (IntelUnavailable, ConfigError, sqlite3.DatabaseError, OSError, ValueError) as error:
            feed_meta = {}
            enrichments = []
            feed_failure = f"On-demand intelligence unavailable ({type(error).__name__}); no enrichment claimed"
    for feed in ("nvd", "epss", "kev"):
        metadata = feed_meta.get(feed)
        if metadata is None:
            emit(feed, "error" if cve_ids else "skipped", feed_failure)
    emit(
        "intel",
        "complete" if findings and feed_meta else "error" if cve_ids else "skipped",
        (
            f"Matched {len(enrichments)} intelligence records to {len(findings)} findings"
            if findings and feed_meta
            else "No vulnerability findings to enrich"
            if not findings
            else feed_failure
            if cve_ids
            else "No scanner-named CVE IDs; native-severity scoring remains available"
        ),
    )
    if on_capture is not None:
        on_capture(
            {
                "target": target,
                "resolved_ip": target_ip,
                "services": [service.to_json() for service in host.services],
                "finding_count": len(findings),
            }
        )
    emit("context", "running", "Inferring context from the observed services")
    profile = context.build_profile(
        host, findings, settings.scope, settings.roles, settings.controls
    )
    emit("context", "complete", f"Role {profile.role.value}; exposure {profile.exposure.value}")
    scores, unscored_findings = scoring.score_available(
        findings, enrichments, profile, host.services, settings.weights
    )
    if unscored_findings:
        emit(
            "score",
            "error",
            f"{len(scores)} priorities calculated; {len(unscored_findings)} findings need severity review; no unsupported Low score assigned",
        )
    if scores:
        basis = (
            "with local CVE intelligence"
            if enrichments
            else "using native-severity fallback; no CVE match"
        )
        if not unscored_findings:
            emit("score", "complete", f"Calculated {len(scores)} deterministic priorities {basis}")
        emit("queue", "complete", f"Ordered {len(scores)} findings by deterministic risk")
        emit("rationale", "complete", f"Recorded {len(scores)} deterministic score reasons")
    else:
        for stage in ("score", "queue", "rationale"):
            if stage != "score" or not unscored_findings:
                emit(
                    stage,
                    "skipped",
                    "No severity basis; no score or priority is claimed"
                    if unscored_findings
                    else "No vulnerability findings; no score or priority is claimed",
                )
    nikto_detail = next(
        (detail for stage, _state, detail in reversed(stage_events) if stage == "nikto"),
        "not requested",
    )
    collection_failures = [
        {"stage": stage, "detail": detail}
        for stage, state, detail in stage_events
        if state == "error" and stage in {"scanner", "endpoint_scan", "nikto"}
    ]
    scan_status = "partial" if collection_failures else "complete"
    payload = {
        "scan_status": scan_status,
        "collection_failures": collection_failures,
        "hosts": [host.to_json()],
        "findings": [finding.to_json() for finding in findings],
        "scores": [score.to_json() for score in scores],
        "unscored_findings": unscored_findings,
        "enrichments": [item.to_json() for item in enrichments],
        "feed_status": sorted(feed_meta),
        "feeds_meta": feed_meta,
        "intelligence_mode": (
            "on_demand"
            if feed_meta.get("nvd", {}).get("path") == intel_online.NVD_URL
            else "offline"
        )
        if feed_meta
        else "unavailable",
        "context": [profile.to_json()],
        "scanner_coverage": {
            "nmap": (
                f"top 100 TCP ports; explicit TCP/{endpoint['port']} check {endpoint_scan_status}"
                if endpoint is not None
                else "top 100 TCP ports, light service detection"
            ),
            "nikto": (
                f"complete: bounded checks on {endpoint['scheme']} endpoint, {sum(item.tool == 'nikto' for item in findings)} findings"
                if nikto_status == "complete" and endpoint is not None
                else "not run; separate authorized web scan required"
                if endpoint is None
                else f"{nikto_status}: {nikto_detail}"
            ),
            "nessus": "no .nessus report imported; no Nessus scan claimed",
        },
    }
    scan_profile = payload["scanner_coverage"]["nmap"]
    if device_check is not None:
        payload["self_defence"] = device_check
        payload["scanner_coverage"]["device-check"] = device_check["limitations"]
        (directory / "device-check.json").write_text(
            json.dumps(device_check, ensure_ascii=True), encoding="utf-8"
        )
    if (directory / "redis-lua-check.json").is_file():
        payload["scanner_coverage"]["redis-check"] = endpoint_scan_status
    # Keep replayable evidence even if AI fails. Exclusive creation in a unique
    # directory prevents a later run from replacing an earlier capture.
    with (directory / "case.json").open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=True)
    with (directory / "manifest.json").open("x", encoding="utf-8") as stream:
        json.dump(
            {
                "target": target,
                "resolved_ip": target_ip,
                "captured_at": captured_at,
                "files": {
                    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in directory.iterdir()
                    if path.is_file() and path.name != "manifest.json"
                },
            },
            stream,
        )
    decision_frame = analyst.build_evidence_frame(payload, target_ip)
    evidence_summary = assessment_summary(
        target,
        target_ip,
        [service.to_json() for service in host.services],
        payload,
    )
    evidence_result = {
        "target": target,
        "resolved_ip": target_ip,
        "scan_profile": scan_profile,
        "services": [service.to_json() for service in host.services],
        "finding_count": len(findings),
        "decision_frame": decision_frame,
        "assessment_summary": evidence_summary,
        "scan_status": scan_status,
        "analyst": None,
        "ai_status": "not_attempted",
        "ai_attempts": [],
    }
    saved_assessment = {"status": "unavailable"}
    try:
        checkpoint = capture_history.save(
            directory, evidence_result, config_hash=settings.config_hash()
        )
        saved_assessment = {
            "status": "saved",
            "capture_id": directory.name,
            "snapshot_hash": checkpoint["snapshot_hash"],
        }
        evidence_summary["saved_capture_id"] = directory.name
    except (OSError, ConfigError):
        evidence_summary["persistence_warning"] = (
            "Review checkpoint could not be saved; raw scanner files remain local."
        )
    if on_capture is not None:
        on_capture(
            {
                "target": target,
                "resolved_ip": target_ip,
                "services": [service.to_json() for service in host.services],
                "finding_count": len(findings),
                "scan_profile": scan_profile,
                "scanner_coverage": payload["scanner_coverage"],
                "scan_status": scan_status,
                "decision_frame": decision_frame,
                "assessment_summary": evidence_summary,
            }
        )
    if on_case is not None:
        on_case(
            {
                "target": target,
                "resolved_ip": target_ip,
                "scan_profile": scan_profile,
                "services": [service.to_json() for service in host.services],
                "finding_count": len(findings),
                "decision_frame": decision_frame,
                "assessment_summary": evidence_summary,
                "payload": payload,
                "scan_status": scan_status,
                "stage_events": stage_events.copy(),
            }
        )
    outcome = analyst.analyze_optional(
        payload, target_ip, provider, on_progress, allow_fallback=allow_fallback
    )
    summary = assessment_summary(
        target,
        target_ip,
        [service.to_json() for service in host.services],
        payload,
        outcome["analyst"],
    )
    summary.update(ai_status=outcome["ai_status"], ai_attempts=outcome["ai_attempts"])
    emit(
        "report",
        "complete",
        (
            "Partial scan. Failed requested checks are listed in coverage."
            if collection_failures
            else "Scan complete."
        )
        + " Evidence summary attached."
        + (
            " AI analysis validated."
            if outcome["analyst"]
            else " AI analysis " + outcome["ai_status"].replace("_", " ") + "."
        ),
    )
    result = {
        "target": target,
        "resolved_ip": target_ip,
        "scan_profile": scan_profile,
        "services": [service.to_json() for service in host.services],
        "finding_count": len(findings),
        "decision_frame": decision_frame,
        "assessment_summary": summary,
        "scan_status": scan_status,
        "evidence_directory": str(directory),
        **outcome,
    }
    if saved_assessment["status"] == "saved":
        try:
            checkpoint = capture_history.save(directory, result, final=True)
            saved_assessment["snapshot_hash"] = checkpoint["snapshot_hash"]
        except (OSError, ConfigError):
            summary["persistence_warning"] = (
                "Final AI review could not be saved; the evidence checkpoint is retained."
            )
        summary["saved_capture_id"] = directory.name
    elif "persistence_warning" in evidence_summary:
        summary["persistence_warning"] = evidence_summary["persistence_warning"]
    result["saved_assessment"] = saved_assessment
    return result
