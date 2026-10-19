"""Read-only, scope-gated replay of locally retained CVE evidence."""

import copy
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from vulnassess import capture_history, intel, intel_online, scoring
from vulnassess.errors import ConfigError, IntelUnavailable
from vulnassess.schema import ContextProfile, Finding, Host
from vulnassess.store import Store


def _refresh_inputs(payload, ip) -> tuple[Host, ContextProfile, list[Finding]]:
    """Validate retained prerequisites before opening a cache or fetching publishers."""
    if not isinstance(payload, dict):
        raise ConfigError("Saved refresh requires an evidence object")
    selected = {}
    for section, identity in (("hosts", "ip"), ("context", "host_ip"), ("findings", "host_ip")):
        rows = payload.get(section)
        if not isinstance(rows, list) or any(
            not isinstance(row, dict) or not isinstance(row.get(identity), str) for row in rows
        ):
            raise ConfigError(f"Saved refresh requires a valid {section} list")
        selected[section] = [row for row in rows if row[identity] == ip]
    for section in ("hosts", "context"):
        if len(selected[section]) != 1:
            raise ConfigError(f"Saved refresh requires exactly one matching {section} record")
    if not selected["findings"]:
        raise ConfigError("Saved refresh requires matching findings")
    for row in selected["findings"]:
        cves = row.get("cve_ids", [])
        if not isinstance(cves, list) or any(
            not isinstance(cve, str) or not cve.strip() for cve in cves
        ):
            raise ConfigError("Saved refresh requires valid finding CVE identifiers")
    try:
        host = Host.from_json(selected["hosts"][0])
        profile = ContextProfile.from_json(selected["context"][0])
        findings = [Finding.from_json(row) for row in selected["findings"]]
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ConfigError(
            "Saved refresh requires valid host, context and finding records"
        ) from error
    return host, profile, findings


def refresh_saved_case(payload, ip, settings, database, on_progress):
    """Fresh public intelligence and deterministic derivatives; never edit a capture."""
    if not settings.scope.contains(ip) or settings.scope.is_canary(ip):
        raise ConfigError("Saved evidence is outside the current authorized scope")
    host, profile, findings = _refresh_inputs(payload, ip)
    refreshed = copy.deepcopy(payload)
    ids = sorted({cve for finding in findings for cve in finding.cve_ids})
    # Do not let yesterday's enrichment masquerade as today's successful lookup.
    refreshed.update(
        enrichments=[], scores=[], feed_status=[], feeds_meta={}, intelligence_mode="unavailable"
    )
    refreshed.pop("intelligence_refreshed_at", None)
    enrichments = []
    try:
        with Store(Path(database).with_name("intel-cache.db")) as store:
            intel_online.sync_cves(ids, store, on_progress=on_progress, force_refresh=True)
            requested = intel_online.requested_cache(store, ids)
            feed_meta = store.feeds_meta()
            dates = {name: item.get("file_date") or "" for name, item in feed_meta.items()}
            for finding in findings:
                matches, _ = intel.match_finding_with_trace(
                    finding, host.services, requested, dates
                )
                enrichments.extend(matches)
        refreshed.update(
            feed_status=["nvd", "epss", "kev"],
            feeds_meta=feed_meta,
            intelligence_mode="on_demand",
            intelligence_refreshed_at=datetime.now(timezone.utc).isoformat(),
        )
        on_progress(
            "intel",
            "complete",
            f"Fresh publisher data matched to {len(findings)} retained findings; {len(enrichments)} matches",
        )
    except (IntelUnavailable, sqlite3.DatabaseError, OSError) as error:
        # A later match can fail after earlier matches succeeded. Never score
        # that partial batch while reporting the refresh as unavailable.
        enrichments = []
        for stage in ("nvd", "epss", "kev", "intel"):
            on_progress(
                stage,
                "error",
                f"Fresh intelligence unavailable ({type(error).__name__}); old enrichment not reused",
            )
    scores, unscored_findings = scoring.score_available(
        findings, enrichments, profile, host.services, settings.weights
    )
    refreshed.update(
        enrichments=[item.to_json() for item in enrichments],
        scores=[item.to_json() for item in scores],
        unscored_findings=unscored_findings,
    )
    for stage in ("score", "queue", "rationale"):
        on_progress(
            stage,
            "error"
            if stage == "score" and unscored_findings
            else "complete"
            if scores
            else "skipped",
            f"{len(scores)} priorities calculated; {len(unscored_findings)} findings need severity review; no unsupported Low score assigned"
            if unscored_findings
            else f"Recalculated {len(scores)} deterministic priorities from fresh intelligence"
            if enrichments
            else f"{len(scores)} native-severity priorities; fresh intelligence unavailable, no CVE enrichment claimed",
        )
    return refreshed


def _capture_bytes(directory, name, limit):
    if not isinstance(name, str) or Path(name).name != name or ":" in name:
        raise ConfigError("Invalid saved evidence filename")
    path = directory / name
    if path.is_symlink() or path.resolve().parent != directory.resolve():
        raise ConfigError("Saved evidence must stay in its capture directory")
    with path.open("rb") as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ConfigError("Saved evidence exceeds the replay budget")
    return raw


def _verified_payload(directory, manifest, manifest_raw, record):
    if record is not None:
        verified = capture_history.load(directory.parent, directory.name)
        if (
            verified["snapshot_hash"] != record["snapshot_hash"]
            or verified["manifest_hash"] != hashlib.sha256(manifest_raw).hexdigest()
        ):
            raise ConfigError("Saved capture changed during selection; replay refused")
        return verified["payload"]
    files = manifest["files"]
    if not isinstance(files, dict) or "case.json" not in files or len(files) > 20:
        raise ConfigError("Invalid saved capture manifest")
    total = 0
    case_raw = None
    for name, expected in files.items():
        raw = _capture_bytes(directory, name, 8 * 1024 * 1024)
        total += len(raw)
        if total > 64 * 1024 * 1024:
            raise ConfigError("Saved evidence exceeds the replay budget")
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ConfigError("Saved evidence hash mismatch; replay refused")
        if name == "case.json":
            case_raw = raw
    # Parse exactly the bytes whose hash was verified; do not reopen case.json.
    if case_raw is None:
        raise ConfigError("Invalid saved capture manifest: case.json is required")
    return json.loads(case_raw)


def load_saved_cve_case(root, target, scope):
    root = Path(root).resolve()
    directories = []
    for path in root.glob("assessment-*"):
        if not path.is_symlink() and path.is_dir():
            directories.append(path)
        if len(directories) > 100:
            raise ConfigError(
                "Saved capture discovery exceeds 100 directories; use explicit saved review"
            )
    discovery_diagnostics = []
    candidates = []
    for directory in sorted(directories):
        try:
            manifest_raw = _capture_bytes(directory, "manifest.json", 65536)
            manifest = json.loads(manifest_raw)
            if not isinstance(manifest, dict):
                raise ValueError("Saved capture manifest must be an object")
        except (OSError, ValueError, ConfigError) as error:
            discovery_diagnostics.append(
                {
                    "evidence_directory": str(directory),
                    "reason": f"Saved capture manifest is unreadable or malformed ({type(error).__name__})",
                }
            )
            continue
        if manifest.get("target") != target:
            continue
        captured_at, time_source, record = capture_history.capture_time(
            directory, manifest, manifest_raw
        )
        candidates.append((captured_at, directory, manifest, manifest_raw, time_source, record))
    dated = sorted(
        [item for item in candidates if item[0] is not None],
        key=lambda item: (datetime.fromisoformat(item[0]), item[1].name),
        reverse=True,
    )
    undated = [item for item in candidates if item[0] is None]
    for captured_at, directory, manifest, manifest_raw, time_source, record in [*dated, *undated]:
        if captured_at is None and len(undated) > 1:
            raise ConfigError(
                "Multiple saved captures have unknown chronology; recorded capture time is required"
            )
        # The selected target-bound candidate must verify, not fall back on corruption.
        try:
            ip = manifest["resolved_ip"]
            if not scope.contains(ip) or scope.is_canary(ip):
                raise ConfigError("Saved evidence is outside the current authorized scope")
            payload = _verified_payload(directory, manifest, manifest_raw, record)
            if not isinstance(payload, dict):
                raise ValueError("Saved evidence must be an object")
            hosts, findings = payload["hosts"], payload["findings"]
            if (
                not isinstance(hosts, list)
                or not hosts
                or any(not isinstance(host, dict) for host in hosts)
                or not isinstance(findings, list)
            ):
                raise ValueError("Saved evidence must contain host and finding lists")
            if any(host["ip"] != ip for host in payload["hosts"]):
                raise ConfigError("Saved evidence contains a different target")
            for finding in findings:
                if not isinstance(finding, dict):
                    raise ValueError("Saved finding must be an object")
                cve_ids = finding.get("cve_ids", [])
                if not isinstance(cve_ids, list) or any(
                    not isinstance(cve, str) or not cve for cve in cve_ids
                ):
                    raise ValueError("Saved finding CVE IDs must be a list of strings")
            if not any(finding.get("cve_ids") for finding in findings):
                continue
            warnings = []
            if captured_at is None:
                warnings.append(
                    "Capture time was not recorded; filesystem dates are not scan provenance."
                )
            elif undated:
                warnings.append(
                    f"Selected the latest dated capture; {len(undated)} undated matching captures cannot be chronologically compared."
                )
            if captured_at and sum(item[0] == captured_at for item in dated) > 1:
                warnings.append(
                    "Matching captures share this timestamp; capture ID breaks the presentation tie, not collection chronology."
                )
            return {
                "target": target,
                "resolved_ip": ip,
                "payload": payload,
                "historical_capture": True,
                "evidence_directory": str(directory),
                "captured_at": captured_at,
                "capture_time_source": time_source,
                "capture_time_warning": " ".join(warnings),
                "discovery_diagnostics": discovery_diagnostics,
            }
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise ConfigError("Saved capture is unreadable or malformed; replay refused") from error
    message = "No verified saved CVE capture exists for this exact target"
    if discovery_diagnostics:
        rejected = "; ".join(
            f"{Path(item['evidence_directory']).name}: {item['reason']}"
            for item in discovery_diagnostics
        )
        message += f"; discovery rejected candidates: {rejected}"
    raise ConfigError(message)
