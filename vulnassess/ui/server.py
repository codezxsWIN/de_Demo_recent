"""Loopback workbench with explicit analyst requests and a scoped report import."""

import json
import os
import re
import time
from dataclasses import dataclass
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
from socketserver import TCPServer
from threading import Lock
from typing import Any, Callable, cast
from urllib.parse import parse_qs, unquote, urlsplit

import yaml

import vulnassess.analyst as analyst
import vulnassess.capture_history as capture_history
import vulnassess.decision_focus as decision_focus
import vulnassess.evidence_requests as evidence_requests
import vulnassess.helpy as helpy
import vulnassess.live_assessment as live_assessment
import vulnassess.orchestrator as orchestrator
import vulnassess.protocols as protocols
import vulnassess.public_website as public_website
import vulnassess.report_composer as report_composer
import vulnassess.scan_plans as scan_plans
from vulnassess.ai_boundary import digest
from vulnassess.errors import AdapterError, ConfigError, LLMUnavailable, NeedsReview, ScopeError
from vulnassess.intel_status import read_cache_status
from vulnassess.nessus_import import import_nessus_report
from vulnassess.readers._input import MAX_CAPTURE_BYTES
from vulnassess.repository import ENV_VAR, AssessmentRepository
from vulnassess.runner import plan as scope_fence
from vulnassess.saved_cve_case import (
    load_saved_cve_case,
    load_saved_target_case,
    refresh_saved_case,
)
from vulnassess.schema import ContextProfile, Finding, Host, Service
from vulnassess.settings import CONFIG_FILES, Settings
from vulnassess.target_intake import resolve_addresses
from vulnassess.ui import assessment_report, capture_review, vulnerability_findings
from vulnassess.ui.entry import render_entry
from vulnassess.ui.reader import local_path, open_read_store

STATIC_ROOT = Path(__file__).resolve().parent / "static"


def _load_decision_focus(directory, record):
    try:
        return decision_focus.load_saved(directory, record)
    except (ConfigError, OSError):
        # The optional AI selection must never hide the independent evidence ledger.
        return {"unavailable": True}


# data: images carry Cobe's embedded land-map texture; without it the globe has no continents.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'none'"
)
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".woff2": "font/woff2",
}
MAX_STATIC_BYTES = 4 * 1024 * 1024
LAB_REFERENCES = {
    "owasp.org": "OWASP project page (Juice Shop or WebGoat)",
    "www.owasp.org": "OWASP project page (Juice Shop or WebGoat)",
    "dvwa.co.uk": "DVWA project page",
    "www.dvwa.co.uk": "DVWA project page",
    "docs.rapid7.com": "Metasploitable documentation",
    "tryhackme.com": "TryHackMe platform",
    "www.tryhackme.com": "TryHackMe platform",
    "hackthebox.com": "Hack The Box platform",
    "www.hackthebox.com": "Hack The Box platform",
    "portswigger.net": "PortSwigger Web Security Academy",
    "overthewire.org": "OverTheWire wargames",
    "www.overthewire.org": "OverTheWire wargames",
    "picoctf.org": "picoCTF platform",
    "www.picoctf.org": "picoCTF platform",
    "google-gruyere.appspot.com": "Google Gruyere training platform",
}


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    content_type: str = "application/json; charset=utf-8"


def json_response(status: int, payload: Any) -> Response:
    return Response(status, json.dumps(payload, sort_keys=True, allow_nan=False).encode("utf-8"))


def error_response(status: int, message: str) -> Response:
    return json_response(
        status,
        {
            "error": {
                "type": "ConfigError",
                "message": message,
                "exit_code": ConfigError.exit_code,
            },
        },
    )


def _replay_evidence(
    source: dict[str, Any], target_ip: str, on_progress: Callable[[str, str, str], None]
) -> tuple[list[dict[str, Any]], str, list[tuple[str, str, str]]]:
    """Validate retained prerequisites and describe historical scanner coverage."""
    payload = source.get("payload")
    try:
        if not isinstance(payload, dict) or source.get("resolved_ip") != target_ip:
            raise ValueError("retained target identity is missing or changed")
        hosts = payload.get("hosts")
        if not isinstance(hosts, list) or any(not isinstance(item, dict) for item in hosts):
            raise ValueError("retained host evidence is missing")
        matching = [item for item in hosts if item.get("ip") == target_ip]
        if len(matching) != 1:
            raise ValueError("exactly one retained target host is required")
        host = Host.from_json(matching[0])
        if not isinstance(payload.get("findings"), list):
            raise ValueError("retained finding evidence is missing")
        findings = [Finding.from_json(item) for item in payload["findings"]]
        if any(finding.host_ip != target_ip for finding in findings):
            raise ValueError("retained finding belongs to a different target")
        identities = [finding.id for finding in findings]
        if any(not isinstance(identity, str) or not identity.strip() for identity in identities):
            raise ValueError("retained finding identity is invalid")
        if len(identities) != len(set(identities)):
            raise ValueError("retained finding identity is duplicated")
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        message = f"Retained host/canonical evidence is invalid: {error}"
        on_progress("canonical", "error", message)
        raise ConfigError(message) from error
    try:
        profiles = payload.get("context")
        if not isinstance(profiles, list) or any(not isinstance(item, dict) for item in profiles):
            raise ValueError("retained context is missing")
        matching_profiles = [item for item in profiles if item.get("host_ip") == target_ip]
        if len(matching_profiles) != 1:
            raise ValueError("exactly one retained context profile is required for the target")
        ContextProfile.from_json(matching_profiles[0])
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        message = f"Retained context is invalid: {error}"
        on_progress("context", "error", message)
        raise ConfigError(message) from error

    summary = source.get("assessment_summary")
    summary = summary if isinstance(summary, dict) else {}
    statuses = (source.get("scan_status"), payload.get("scan_status"), summary.get("scan_status"))
    for status in statuses:
        if status is not None and (
            type(status) is not str or status not in ("complete", "partial")
        ):
            message = "Retained scan_status must be complete or partial when supplied"
            on_progress("scanner", "error", message)
            raise ConfigError(message)

    coverage = payload.get("scanner_coverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    nmap = coverage.get("nmap", "")
    nmap = nmap if isinstance(nmap, str) else ""
    baseline = nmap.split(";", 1)[0].strip().lower()
    baseline_state = (
        "complete" if baseline.startswith(("top 100 tcp ports", "complete")) else "error"
    )
    states = {"scanner": (baseline_state, nmap or "Nmap baseline coverage was not retained")}
    endpoint = re.search(r"; explicit TCP/(\d+) check (.+)", nmap)
    parsed = urlsplit(str(source.get("target", "")))
    requested_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if endpoint is not None:
        detail = endpoint[2]
        known = detail.lower() in (
            "complete",
            "closed",
            "redis not inspected",
        ) or detail.lower().startswith(("redis lua sandbox", "redis inspection did not establish"))
        state = "complete" if known else "error"
        if parsed.scheme in ("http", "https") and int(endpoint[1]) != requested_port:
            state, detail = "error", "Requested endpoint differs from retained port coverage"
    elif parsed.scheme in ("http", "https"):
        state, detail = "error", "Requested endpoint coverage was not retained"
    else:
        state, detail = "skipped", "No explicit endpoint coverage was retained"
    states["endpoint_scan"] = (state, detail)
    nikto = coverage.get("nikto")
    if isinstance(nikto, str) and nikto.lower().startswith("complete"):
        states["nikto"] = ("complete", nikto)
    elif isinstance(nikto, str) and nikto.lower().startswith(("failed", "error")):
        states["nikto"] = ("error", nikto)
    else:
        states["nikto"] = (
            "skipped",
            nikto if isinstance(nikto, str) else "No Nikto coverage retained",
        )
    for event in source.get("stage_events", []):
        if isinstance(event, (list, tuple)) and len(event) == 3:
            stage, state, detail = event
            if stage in states and state == "error":
                states[stage] = ("error", str(detail))
    scan_status = (
        "partial"
        if "partial" in statuses or any(state == "error" for state, _ in states.values())
        else "complete"
    )
    stages = [
        ("scope", "complete", "Retained target checked against current scope; no new scan"),
        *(
            (stage, state, f"Retained coverage: {detail}; no new scan")
            for stage, (state, detail) in states.items()
        ),
        ("canonical", "complete", "Retained host and finding records verified; no new scan"),
        ("context", "complete", "Retained target context verified; no new inference or scan"),
    ]
    return [service.to_json() for service in host.services], scan_status, stages


class UiApplication:
    def __init__(
        self,
        database: str | Path,
        config_dir: str | Path,
        run_id: str | None = None,
        analyst_model: str = analyst.DEFAULT_MODEL,
        ollama_host: str = analyst.DEFAULT_HOST,
    ) -> None:
        resolved = str(database)
        if os.environ.get(ENV_VAR) and not resolved.startswith(
            ("postgres://", "postgresql://", "env:")
        ):
            resolved = f"env:{ENV_VAR}"
        self.database = (
            resolved
            if resolved.startswith(("postgres://", "postgresql://", "env:"))
            else local_path(resolved)
        )
        self.config_dir = local_path(config_dir)
        self.run_id = run_id
        self.analyst_model = analyst_model
        self.ollama_host = ollama_host
        self._live_lock = Lock()
        self._helpy_lock = Lock()
        self._last_public_check = 0.0
        self._last_live_scan: dict[str, float] = {}
        self._recent_live_cases: dict[str, tuple[float, dict[str, Any]]] = {}
        self.scan_plans = scan_plans.PlanRegistry()
        self.evidence_requests = evidence_requests.EvidenceRequests(Path("data/ai_evidence"))
        for name in CONFIG_FILES:
            path = local_path(self.config_dir / name)
            if not path.is_relative_to(self.config_dir):
                raise ConfigError(f"configuration file leaves its local directory: {path}")
        settings = Settings(self.config_dir)
        self.configurations: dict[str, dict[str, Any]] = {}
        for name in ("scope", "weights"):
            path = self.config_dir / f"{name}.yaml"
            try:
                content = path.read_bytes()
                document = content.decode("utf-8")
                values = yaml.safe_load(document)
            except (OSError, UnicodeError, yaml.YAMLError) as error:
                raise ConfigError(f"cannot read configuration file {path}") from error
            if values != settings.raw[path.name]:
                raise ConfigError(f"configuration file changed during validation: {path}")
            self.configurations[name] = {
                "path": str(path),
                "sha256": sha256(content).hexdigest(),
                "values": values,
                "yaml": document,
            }
        with open_read_store(self.database) as store:
            if run_id is None:
                store.runs()
            else:
                store.run_info(run_id)
        if not (STATIC_ROOT / "index.html").is_file():
            raise ConfigError(f"MISSING: UI entry point {STATIC_ROOT / 'index.html'}")

    def _static(self, parts: list[str]) -> Response:
        path = STATIC_ROOT.joinpath(*parts).resolve()
        if not path.is_relative_to(STATIC_ROOT) or path.suffix not in CONTENT_TYPES:
            return error_response(404, "UI static file not found")
        try:
            if not path.is_file() or path.stat().st_size > MAX_STATIC_BYTES:
                return error_response(404, "UI static file not found")
            return Response(200, path.read_bytes(), CONTENT_TYPES[path.suffix])
        except OSError:
            return error_response(404, "UI static file not found")

    def intelligence_status(self) -> dict[str, Any]:
        return read_cache_status(self.database)

    def _entry(self, requested_run: str | None = None) -> Response:
        template = self._static(["index.html"])
        if template.status != 200:
            return template
        try:
            with open_read_store(self.database) as store:
                run_id = self.run_id if requested_run is None else requested_run
                payload = None if run_id is None else store.run(run_id)
                runs = store.runs() if payload is None else []
            document = render_entry(
                template.body.decode("utf-8"), payload, runs, self.configurations
            )
        except ConfigError as error:
            return error_response(409, str(error))
        return Response(200, document.encode("utf-8"), "text/html; charset=utf-8")

    def cvss_fixture(self) -> dict[str, Any]:
        path = (
            Path(__file__).resolve().parents[2]
            / "tests"
            / "synthetic"
            / "synthetic_cvss31_vectors.json"
        )
        if not path.is_file():
            raise ConfigError(f"MISSING: CVSS arithmetic fixture {path}")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ConfigError(f"cannot read CVSS arithmetic fixture {path}") from error

    def target_check(self, target: str) -> dict[str, Any]:
        """Classify an IP, lab URL, or project link; never connect to the target."""
        submitted = target.strip()
        if not submitted or len(submitted) > 512:
            raise ConfigError("Enter one target address of at most 512 characters")
        try:
            parsed = urlsplit(submitted if "://" in submitted else f"//{submitted}")
        except ValueError as error:
            raise ConfigError("Target URL has an invalid host") from error
        if (
            (parsed.scheme and parsed.scheme not in ("http", "https"))
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ConfigError("Target URL must be HTTP(S), without credentials, query or fragment")
        try:
            hostname = parsed.hostname
            port = parsed.port
        except ValueError as error:
            raise ConfigError("Target URL has an invalid host or port") from error
        if not hostname or (port is not None and port < 1):
            raise ConfigError("Target URL needs a valid host")
        endpoint = None
        if parsed.scheme in ("http", "https"):
            endpoint = {
                "scheme": parsed.scheme,
                "host": hostname.rstrip(".").lower(),
                "port": port or (443 if parsed.scheme == "https" else 80),
                "path": parsed.path or "/",
            }
        hostname = hostname.rstrip(".").lower()
        if hostname in LAB_REFERENCES:
            return {
                "submitted": submitted,
                "status": "reference",
                "reason": f"{LAB_REFERENCES[hostname]} — not a scan target. Run or open your assigned lab instance and check its specific URL/IP.",
            }
        try:
            addresses = [str(ip_address(hostname))]
        except ValueError:
            if len(hostname) > 253 or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", hostname):
                raise ConfigError("Enter an IP or valid domain, not a CIDR or project title")
            try:
                addresses = resolve_addresses(hostname, port or 0)
            except (OSError, ValueError) as error:
                raise ConfigError("Domain could not be resolved; no scan was started") from error
            if not addresses or len(addresses) > 32:
                raise ConfigError("Domain resolution returned no usable or too many addresses")
        settings = Settings(self.config_dir)
        if any(settings.scope.is_canary(address) for address in addresses):
            return {
                "submitted": submitted,
                "status": "blocked",
                "reason": "Canary address: never scan",
            }
        if any(not settings.scope.contains(address) for address in addresses):
            return {
                "submitted": submitted,
                "status": "blocked",
                "resolved_ips": addresses,
                "reason": "At least one resolved address is outside the authorised scope; no scanner command was built",
            }
        nmap, nmap_detail = live_assessment.nmap_probe()
        missing = [] if nmap else ["nmap"]
        return {
            "target": addresses[0],
            "submitted": submitted,
            "endpoint": endpoint,
            "resolved_ips": addresses,
            "status": "needs-pinning"
            if hostname != addresses[0]
            else ("ready" if not missing else "needs-tools"),
            "scope": settings.scope.segment(addresses[0]) or addresses[0],
            "missing": missing,
            "reason": (
                f"Scope accepted. The live run will pin the URL to {addresses[0]}, check its requested port, and use only scanners allowed for this configured asset. {nmap_detail}"
                if endpoint is not None and hostname != addresses[0]
                else f"Scope accepted. The live run will check the requested port on the pinned target and use only scanners allowed for this configured asset. {nmap_detail}"
                if endpoint is not None
                else f"Scope accepted. A live run will pin this domain to its authorised IP. {nmap_detail}"
                if hostname != addresses[0]
                else (
                    f"Scope accepted for a light live Nmap scan. {nmap_detail}"
                    if not missing
                    else f"Scope accepted, but {nmap_detail}"
                )
            ),
        }

    def plan_context(self, target: str, run_id: str, hints: str = "") -> dict[str, Any]:
        check = self.target_check(target)
        addresses = check.get("resolved_ips") or []
        if (
            check.get("status") not in ("ready", "needs-tools", "needs-pinning")
            or len(addresses) != 1
        ):
            raise ConfigError(check.get("reason") or "Target must resolve to one authorised IP")
        ip = addresses[0]
        settings = Settings(self.config_dir)
        if not settings.scope.contains(ip) or settings.scope.is_canary(ip):
            raise ConfigError("Planner target is outside the authorised scope")
        evidence = [
            {
                "id": "E1",
                "text": "Approved baseline: common 100 TCP ports, light service discovery; scores remain deterministic.",
            }
        ]
        endpoints: dict[str, dict[str, Any]] = {}
        probe_options: list[dict[str, Any]] = []
        histories = []
        with self._live_lock:
            recent = self._recent_live_cases.get(ip)
            if recent and time.monotonic() - recent[0] < 600:
                histories.append(recent[1]["payload"])
        with open_read_store(self.database) as store:
            runs = store.runs()[:10]
            if run_id and not any(row["run_id"] == run_id for row in runs):
                runs.insert(0, store.run_info(run_id))
            for row in runs:
                payload = store.run(row["run_id"])
                if any(host.get("ip") == ip for host in payload["hosts"]):
                    histories.append(payload)
                    if len(histories) >= 3:
                        break
        requested = live_assessment._validated_endpoint(check)
        for payload in histories:
            host = next((item for item in payload["hosts"] if item.get("ip") == ip), None)
            if host is None:
                continue
            captured_at = payload.get("run", {}).get("started_at", "capture time unavailable")
            for service in host.get("services", [])[:12]:
                identity = f"E{len(evidence) + 1}"
                evidence.append(
                    {
                        "id": identity,
                        "text": f"Prior observation as of {captured_at}: "
                        + json.dumps(service, sort_keys=True)[:1000],
                    }
                )
                port = service.get("port")
                if service.get("protocol") == "tcp" and type(port) is int and 1 <= port <= 65535:
                    probe_options.append(
                        {"kind": "tcp_connect", "port": port, "evidence_id": identity}
                    )
                if (
                    settings.scope.tags(ip).get("environment") == "test"
                    and service.get("protocol") == "tcp"
                    and type(port) is int
                    and 1 <= port <= 65535
                    and protocols.http_service_name(service.get("name"))
                    and (requested is None or requested["port"] == port)
                ):
                    endpoints[identity] = requested or {
                        "host": ip,
                        "scheme": "https"
                        if protocols.uses_tls(Service.from_json(service))
                        else "http",
                        "port": port,
                        "path": "/",
                    }
                    probe_options.append(
                        {
                            "kind": "tls_inspect"
                            if endpoints[identity]["scheme"] == "https"
                            else "http_head",
                            "port": port,
                            "evidence_id": identity,
                        }
                    )
            for feature in host.get("features", [])[:6]:
                evidence.append(
                    {
                        "id": f"E{len(evidence) + 1}",
                        "text": "Prior recorded signal: "
                        + json.dumps(feature, sort_keys=True)[:1000],
                    }
                )
        if hints:
            evidence.append(
                {"id": f"E{len(evidence) + 1}", "text": "User hint, not an observation: " + hints}
            )
        return {
            "target_ip": ip,
            "submitted": target,
            "scope_hash": digest(settings.raw["scope.yaml"]),
            "evidence": evidence,
            "endpoints": endpoints,
            "probe_options": probe_options,
            "run_id": run_id,
            "hints": hints,
            "history_count": len(histories),
            "history_limit": 3,
            "metadata_limitations": "Only supplied scan evidence is read; no DNS/certificate probes are launched by planning.",
        }

    def scan_plan_action(self, action: str, body: Any) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise ConfigError("Invalid scan plan request")
        if action == "propose":
            if (
                set(body) != {"target", "run_id", "hints", "provider", "share_evidence"}
                or not isinstance(body["target"], str)
                or not 0 < len(body["target"]) <= 512
                or not isinstance(body["run_id"], str)
                or len(body["run_id"]) > 128
                or not isinstance(body["hints"], str)
                or len(body["hints"]) > 1000
                or body["provider"] not in analyst.PROVIDERS
                or body["share_evidence"] is not (body["provider"] != "ollama")
            ):
                raise ConfigError("Invalid scan plan proposal request")
            context = self.plan_context(body["target"], body["run_id"], body["hints"])
            client = analyst.provider_client(body["provider"], self.analyst_model, self.ollama_host)
            plan = scan_plans.propose(context, client, self.scan_plans.audit_path)
            return self.scan_plans.create(plan, context)
        fields = {"plan_id", "plan_hash"} | ({"plan"} if action == "edit" else set())
        if action not in ("edit", "approve") or set(body) != fields:
            raise ConfigError("Invalid plan edit or approval request")
        if action == "edit":
            return self.scan_plans.edit(body["plan_id"], body["plan_hash"], body["plan"])
        return self.scan_plans.approve(body["plan_id"], body["plan_hash"])

    def evidence_request_action(self, action: str, body: Any) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise ConfigError("Invalid evidence request")
        if action in {"propose", "analyze"}:
            if (
                set(body) != {"target", "run_id", "provider", "share_evidence"}
                or not isinstance(body["target"], str)
                or not 0 < len(body["target"]) <= 512
                or not isinstance(body["run_id"], str)
                or not 0 < len(body["run_id"]) <= 128
                or body["provider"] not in analyst.PROVIDERS
                or body["share_evidence"] is not (body["provider"] != "ollama")
            ):
                raise ConfigError("Invalid evidence proposal or evidence-sharing choice")
            context = self.plan_context(body["target"], body["run_id"])
            self._evidence_scope(context["target_ip"])
            if action == "analyze":
                target_ip = context["target_ip"]
                payload = None
                with self._live_lock:
                    recent = self._recent_live_cases.get(target_ip)
                    if recent and time.monotonic() - recent[0] < 600:
                        payload = dict(recent[1]["payload"])
                if payload is None:
                    with open_read_store(self.database) as store:
                        payload = store.run(body["run_id"])
                payload["supplemental_evidence"] = self.evidence_requests.evidence(
                    body["run_id"], target_ip
                )
                if not payload["supplemental_evidence"]:
                    raise ConfigError(
                        "No approved follow-up evidence exists for this target and assessment"
                    )
                return analyst.analyze_target(
                    payload,
                    target_ip,
                    model=self.analyst_model,
                    ollama_host=self.ollama_host,
                    provider=body["provider"],
                )
            client = analyst.provider_client(body["provider"], self.analyst_model, self.ollama_host)
            proposal = evidence_requests.propose(context, client, self.evidence_requests.audit_path)
            return self.evidence_requests.create(proposal, context)
        fields = {"request_id", "request_hash"} | ({"reason"} if action == "reject" else set())
        if (
            action not in {"approve", "reject"}
            or set(body) != fields
            or not all(isinstance(body[key], str) for key in fields)
        ):
            raise ConfigError("Invalid evidence approval or rejection")
        if action == "reject":
            return self.evidence_requests.reject(
                body["request_id"], body["request_hash"], body["reason"]
            )
        return self.evidence_requests.execute(
            body["request_id"], body["request_hash"], self._evidence_scope
        )

    def _evidence_scope(self, target_ip: str) -> str:
        settings = Settings(self.config_dir)
        scope_fence(settings, target_ip, [], Path("data/ai_evidence"))
        return digest(settings.raw["scope.yaml"])

    def analyst_report(
        self,
        run_id: str,
        host_ip: str,
        on_progress: Callable[[str, str, str], None] | None = None,
        provider: str = "ollama",
        allow_fallback: bool = False,
        cloud_sharing_authorized: bool = False,
    ) -> dict[str, Any]:
        if on_progress is not None:
            on_progress("records", "running", "Reading the selected stored assessment")
        with open_read_store(self.database) as store:
            payload = store.run(run_id)
        payload["supplemental_evidence"] = self.evidence_requests.evidence(run_id, host_ip)
        if on_progress is not None:
            on_progress("records", "complete", "Stored assessment loaded")
        if allow_fallback:
            outcome = analyst.analyze_optional(
                payload,
                host_ip,
                provider,
                on_progress or (lambda *_: None),
                allow_fallback=True,
                cloud_sharing_authorized=cloud_sharing_authorized,
            )
            if outcome["analyst"] is None:
                detail = (
                    outcome["ai_attempts"][-1]["detail"]
                    if outcome["ai_attempts"]
                    else "No analyst provider responded"
                )
                if outcome["ai_status"] == "needs_review":
                    raise NeedsReview(detail)
                raise LLMUnavailable(detail)
            return {"run_id": run_id, **outcome["analyst"], "ai_attempts": outcome["ai_attempts"]}
        return {
            "run_id": run_id,
            **analyst.analyze_target(
                payload,
                host_ip,
                model=self.analyst_model,
                ollama_host=self.ollama_host,
                provider=provider,
                on_progress=on_progress,
            ),
        }

    def live_report(
        self,
        target: str,
        provider: str,
        on_progress: Callable[[str, str, str], None],
        on_capture: Callable[[dict[str, Any]], None] | None = None,
        *,
        reuse_recent: bool = False,
        allow_fallback: bool = False,
        cloud_sharing_authorized: bool = False,
        replay_saved: bool = False,
        plan_id: str | None = None,
        plan_hash: str | None = None,
    ) -> dict[str, Any]:
        self_defence = target == "self"
        if self_defence:
            if reuse_recent or replay_saved or plan_id is not None or plan_hash is not None:
                raise ConfigError(
                    "Self-defence requires a fresh local check without a scanner plan"
                )
            target = "127.0.0.1"
        if (plan_id is None) != (plan_hash is None) or (
            plan_id is not None and (reuse_recent or replay_saved)
        ):
            raise ConfigError("Planned execution needs both approval fields and a new scan")
        if replay_saved:
            settings = Settings(self.config_dir)
            saved = load_saved_cve_case(
                self.config_dir.resolve().parent / "data" / "live" / "raw", target, settings.scope
            )
            ip = saved["resolved_ip"]
            services, scan_status, stages = _replay_evidence(saved, ip, on_progress)
            for stage, state, detail in stages:
                on_progress(stage, state, detail)
            payload = refresh_saved_case(saved["payload"], ip, settings, self.database, on_progress)
            payload = {**payload, "scan_status": scan_status}
            summary = live_assessment.assessment_summary(target, ip, services, payload)
            summary.update(
                scan_status=scan_status,
                historical_capture=True,
                captured_at=saved["captured_at"],
                capture_time_source=saved.get("capture_time_source", "unknown"),
                capture_time_warning=saved.get("capture_time_warning", ""),
                intelligence_refreshed_at=payload.get("intelligence_refreshed_at"),
            )
            capture = {key: value for key, value in saved.items() if key != "payload"}
            capture.update(
                scan_status=scan_status,
                services=services,
                finding_count=len(payload["findings"]),
                assessment_summary=summary,
            )
            if on_capture:
                on_capture(capture)
            analyst_options = {"allow_fallback": allow_fallback}
            if cloud_sharing_authorized:
                analyst_options["cloud_sharing_authorized"] = True
            outcome = analyst.analyze_optional(
                payload, ip, provider, on_progress, **analyst_options
            )
            summary = live_assessment.assessment_summary(
                target, ip, services, payload, outcome["analyst"]
            )
            summary.update(
                scan_status=scan_status,
                historical_capture=True,
                captured_at=saved["captured_at"],
                capture_time_source=saved.get("capture_time_source", "unknown"),
                capture_time_warning=saved.get("capture_time_warning", ""),
                intelligence_refreshed_at=payload.get("intelligence_refreshed_at"),
                ai_status=outcome["ai_status"],
                ai_attempts=outcome["ai_attempts"],
            )
            on_progress(
                "report",
                "complete",
                ("Partial scan. " if scan_status == "partial" else "")
                + "Saved-evidence summary built; fresh intelligence attempted; no scanner launched",
            )
            return {
                **capture,
                **outcome,
                "assessment_summary": summary,
                "scan_status": scan_status,
                "reused_scan": True,
            }
        on_progress("scope", "running", "Resolving and checking the entered target")
        check = self.target_check(target)
        addresses = check.get("resolved_ips") or []
        if (
            check.get("status") not in ("ready", "needs-tools", "needs-pinning")
            or len(addresses) != 1
        ):
            raise ConfigError(
                check.get("reason") or "Target must resolve to one authorised address"
            )
        if check.get("missing"):
            raise ConfigError(live_assessment.nmap_probe()[1])
        target_ip = addresses[0]
        execution = None
        planned_context = None
        if plan_id is not None and plan_hash is not None:
            saved_context = self.scan_plans.context(plan_id, plan_hash)
            if saved_context["submitted"] != target or saved_context["target_ip"] != target_ip:
                raise ConfigError("Approved plan target changed; review and approve again")
            current_context = self.plan_context(
                target, saved_context["run_id"], saved_context["hints"]
            )
            planned_context = (saved_context, current_context)
        with self._live_lock:
            now = time.monotonic()
            recent = self._recent_live_cases.get(target_ip)
            case = recent[1] if recent and reuse_recent else None
            if case is not None and reuse_recent and case.get("target") != target:
                case = None
            if case is None and reuse_recent:
                case = load_saved_target_case(
                    self.config_dir.resolve().parent / "data" / "live" / "raw",
                    target,
                    Settings(self.config_dir).scope,
                )
                if case["resolved_ip"] != target_ip:
                    raise ConfigError("Saved target address changed; no AI request was sent")
            if case is None:
                if target_ip in self._last_live_scan:
                    raise ConfigError(
                        "A live scan of this target is already running; wait for it to finish before starting another."
                    )
                if planned_context is not None and plan_id is not None and plan_hash is not None:
                    saved_context, current_context = planned_context
                    execution = self.scan_plans.claim(plan_id, plan_hash, current_context)
                    if execution.includes("nikto"):
                        endpoint_id = execution.record["plan"]["steps"][1]["endpoint_evidence_id"]
                        check = {**check, "endpoint": saved_context["endpoints"][endpoint_id]}
                self._last_live_scan[target_ip] = now
        if case is not None:
            services, scan_status, stages = _replay_evidence(case, target_ip, on_progress)
            payload = {**case["payload"], "scan_status": scan_status}
            case = {
                **case,
                "finding_count": len(payload["findings"]),
                "decision_frame": analyst.build_evidence_frame(payload, target_ip),
            }
            for stage, state, detail in stages:
                on_progress(stage, state, f"Reused previous scan: {detail}")
            replayed = set()
            for stage, state, detail in case.get("stage_events", []):
                if stage in {"nvd", "epss", "kev", "intel", "score", "queue", "rationale"}:
                    replayed.add(stage)
                    on_progress(stage, state, f"Reused previous scan: {detail}")
            for stage in ("nvd", "epss", "kev", "intel", "score", "queue", "rationale"):
                if stage not in replayed:
                    on_progress(
                        stage,
                        "skipped",
                        "AI-only replay: no publisher fetch or scoring rerun; retained inputs unchanged",
                    )
            summary = live_assessment.assessment_summary(target, target_ip, services, payload)
            summary["scan_status"] = scan_status
            history = {
                "historical_capture": True,
                "captured_at": case.get("captured_at"),
                "capture_time_source": case.get("capture_time_source", "unknown"),
                "capture_time_warning": case.get("capture_time_warning", ""),
            }
            summary.update(history)
            if on_capture is not None:
                on_capture(
                    {
                        **{
                            key: case[key]
                            for key in ("target", "resolved_ip", "finding_count", "decision_frame")
                            if key in case
                        },
                        "services": services,
                        "scan_status": scan_status,
                        "assessment_summary": summary,
                    }
                )
            analyst_options = {"allow_fallback": allow_fallback}
            if cloud_sharing_authorized:
                analyst_options["cloud_sharing_authorized"] = True
            outcome = analyst.analyze_optional(
                payload, target_ip, provider, on_progress, **analyst_options
            )
            summary = live_assessment.assessment_summary(
                target,
                target_ip,
                services,
                payload,
                outcome["analyst"],
            )
            summary.update(
                **history,
                scan_status=scan_status,
                ai_status=outcome["ai_status"],
                ai_attempts=outcome["ai_attempts"],
            )
            on_progress(
                "report",
                "complete",
                ("Partial scan. " if scan_status == "partial" else "")
                + "Summary built from recent evidence; no new scan; AI "
                + outcome["ai_status"].replace("_", " "),
            )
            return {key: value for key, value in case.items() if key != "payload"} | {
                **outcome,
                "services": services,
                "scan_status": scan_status,
                "assessment_summary": summary,
                "reused_scan": True,
            }

        def remember_case(scanned: dict[str, Any]) -> None:
            with self._live_lock:
                self._recent_live_cases[target_ip] = (time.monotonic(), scanned)

        scanner_failed = False

        def progress(stage: str, state: str, detail: str) -> None:
            nonlocal scanner_failed
            if stage in {"scanner", "endpoint_scan", "nikto"} and state == "error":
                scanner_failed = True
            on_progress(stage, state, detail)

        try:
            result = live_assessment.run(
                target,
                check,
                self.config_dir,
                provider=provider,
                on_progress=progress,
                database=self.database,
                on_capture=on_capture,
                on_case=remember_case,
                allow_fallback=allow_fallback,
                **({"cloud_sharing_authorized": True} if cloud_sharing_authorized else {}),
                **(cast(dict[str, Any], {"plan_execution": execution}) if execution else {}),
                self_defence=self_defence,
            )
        except Exception:
            if execution:
                execution.finish(failed=True)
            raise
        finally:
            with self._live_lock:
                self._last_live_scan.pop(target_ip, None)
        if execution:
            result["scan_plan"] = execution.finish(failed=scanner_failed)
        return result

    def import_nessus_report(
        self, run_id: str, target_ip: str, content: bytes, *, new_run: bool = False
    ) -> dict[str, Any]:
        return import_nessus_report(
            self.database, self.config_dir, run_id, target_ip, content, new_run=new_run
        )

    def helpy_answer(self, body):
        if (
            not isinstance(body, dict)
            or set(body) != {"capture_id", "question", "provider", "share_evidence"}
            or not isinstance(body["capture_id"], str)
            or not isinstance(body["question"], str)
            or not 1 <= len(body["question"].strip()) <= 600
            or body["provider"] not in ("ollama", "google", "groq")
            or body["share_evidence"] is not (body["provider"] != "ollama")
        ):
            raise ConfigError(
                "Select a provider and explicitly approve bounded report sharing for cloud AI"
            )
        if not self._helpy_lock.acquire(blocking=False):
            raise ConfigError("Helpy is answering another question; try again shortly")
        try:
            record = capture_history.load(
                self.config_dir.parent / "data/live/raw", body["capture_id"]
            )
            client = analyst.provider_client(body["provider"], self.analyst_model, self.ollama_host)
            if hasattr(client, "timeout"):
                cast(Any, client).timeout = min(cast(Any, client).timeout, 45.0)
            return helpy.answer(record, body["question"], client)
        finally:
            self._helpy_lock.release()

    def _repository(self) -> AssessmentRepository:
        value = self.database if isinstance(self.database, str) else str(self.database)
        return AssessmentRepository(value, read_only=True)

    def _assessment_api(self, parts: list[str], query: dict[str, list[str]]) -> Response | None:
        if tuple(parts) in (
            ("api", "assessment-runs"),
            ("api", "assets"),
            ("api", "model-evaluations"),
            ("api", "ablations"),
        ):
            with self._repository() as repo:
                if parts == ["api", "assessment-runs"]:
                    payload: Any = {"runs": repo.assessment_runs()}
                elif parts == ["api", "assets"]:
                    payload = {"assets": repo.asset_inventory(self._first(query, "run"))}
                elif parts == ["api", "model-evaluations"]:
                    payload = repo.model_evaluations()
                else:
                    payload = {"ablations": repo.ablation_summaries()}
            return json_response(200, payload)
        if parts == ["api", "findings"]:
            try:
                limit = int(self._first(query, "limit") or 200)
            except ValueError:
                limit = 200
            with self._repository() as repo:
                findings = repo.findings_queue(
                    run_id=self._first(query, "run"),
                    status=self._first(query, "status"),
                    severity=self._first(query, "severity"),
                    decision=self._first(query, "decision"),
                    limit=limit,
                )
            return json_response(200, {"findings": findings})
        if len(parts) == 3 and parts[1] == "asset":
            with self._repository() as repo:
                return json_response(200, repo.asset_details(parts[2]))
        if len(parts) == 3 and parts[1] == "finding":
            with self._repository() as repo:
                return json_response(200, repo.finding_evidence(parts[2]))
        if len(parts) == 4 and parts[1] == "finding" and parts[3] == "score-history":
            with self._repository() as repo:
                return json_response(200, repo.finding_score_history(parts[2]))
        return None

    @staticmethod
    def _first(query: dict[str, list[str]], name: str) -> str | None:
        values = query.get(name)
        return values[0] if values else None

    def get(self, target: str) -> Response:
        try:
            parsed = urlsplit(target)
            decoded = unquote(parsed.path, errors="strict")
        except (ValueError, UnicodeError):
            return error_response(404, "UI path not found")
        if (
            parsed.scheme
            or parsed.netloc
            or parsed.fragment
            or not decoded.startswith("/")
            or any(ord(character) < 32 or ord(character) == 127 for character in decoded)
            or any(character in decoded for character in ("\\", ":", "%"))
        ):
            return error_response(404, "UI path not found")
        if decoded == "/workflow":
            return self._static(["workflow.html"])
        if decoded == "/website-check" and not parsed.query:
            return self._static(["website-check.html"])
        if decoded == "/vulnerabilities" and not parsed.query:
            return self._static(["vulnerabilities.html"])
        if decoded == "/api/vulnerability-findings" and not parsed.query:
            try:
                dashboard = vulnerability_findings.latest(self.config_dir.parent / "data/live/raw")
                return json_response(200, dashboard)
            except (ConfigError, OSError, ValueError, TypeError, KeyError):
                return error_response(
                    409,
                    "The latest completed assessment could not be verified. No evidence was changed.",
                )
        if decoded == "/":
            parameters = parse_qs(parsed.query, keep_blank_values=True)
            if parameters:
                if (
                    set(parameters) != {"run"}
                    or len(parameters["run"]) != 1
                    or not parameters["run"][0]
                ):
                    return error_response(400, "Entry query accepts exactly one non-empty run")
                return self._entry(parameters["run"][0])
            return self._entry()
        parts = decoded[1:].split("/")
        if any(not part or part.startswith(".") for part in parts):
            return error_response(404, "UI path not found")
        if parts == ["static", "index.html"]:
            return self._entry()
        if parts[0] == "static":
            return self._static(parts[1:])
        history_parts = parts[1:] if parts[0] == "api" else parts
        if history_parts and history_parts[0] == "captures":
            try:
                root = self.config_dir.parent / "data" / "live" / "raw"
                query = parse_qs(parsed.query, keep_blank_values=True)
                if len(history_parts) == 1:
                    if set(query) - {"page"} or len(query.get("page", ["1"])) != 1:
                        return error_response(400, "History accepts one page parameter")
                    page = int(query.get("page", ["1"])[0])
                    saved = (
                        capture_history.listing(root, page)
                        if parts[0] == "api"
                        else capture_history._listing_for_review(root, page)
                    )
                    document = capture_review.index(saved) if parts[0] != "api" else None
                elif len(history_parts) == 2 and not query:
                    if parts[0] == "api":
                        saved = capture_history.load(root, history_parts[1])
                        document = None
                    else:
                        saved = capture_history._load_for_review(root, history_parts[1])
                        document = (
                            capture_review._legacy_review(saved)
                            if saved.get("legacy") is True
                            else capture_review.review(saved)
                        )
                elif (
                    parts[0] != "api"
                    and history_parts[2:] in (["report"], ["report", "download"])
                    and not query
                ):
                    saved = capture_history.load(root, history_parts[1])
                    standalone = history_parts[-1] == "download"
                    try:
                        composition = report_composer.load_saved(root / history_parts[1], saved)
                    except (ConfigError, OSError):
                        # An optional presentation artifact cannot suppress the
                        # independently verified assessment and its evidence.
                        composition = {"unavailable": True}
                    document = assessment_report.render(
                        saved,
                        standalone=standalone,
                        composition=composition,
                        policy=self.configurations["weights"]["values"],
                        decision_focus=_load_decision_focus(root / history_parts[1], saved),
                    )
                    return Response(
                        200,
                        document.encode("utf-8"),
                        "application/octet-stream" if standalone else "text/html; charset=utf-8",
                    )
                else:
                    return error_response(400, "Invalid saved assessment request")
                return (
                    json_response(200, saved)
                    if document is None
                    else Response(200, document.encode("utf-8"), "text/html; charset=utf-8")
                )
            except ValueError:
                return error_response(400, "History page must be an integer")
            except (ConfigError, OSError) as error:
                return error_response(
                    409,
                    str(error)
                    if isinstance(error, ConfigError)
                    else "Saved history is unavailable",
                )
        if parts in (["api", "scope"], ["api", "weights"]):
            return json_response(200, self.configurations[parts[1]])
        if parts == ["api", "cvss-fixture"]:
            try:
                return json_response(200, self.cvss_fixture())
            except ConfigError as error:
                return error_response(409, str(error))
        if parts == ["api", "target-check"]:
            parameters = parse_qs(parsed.query, keep_blank_values=True)
            if set(parameters) != {"target"} or len(parameters["target"]) != 1:
                return error_response(400, "Target check requires exactly one target")
            try:
                return json_response(200, self.target_check(parameters["target"][0]))
            except ConfigError as error:
                return error_response(400, str(error))
        if parts == ["api", "scanner-status"]:
            nmap_binary, nmap_detail = live_assessment.nmap_probe()
            return json_response(
                200,
                {
                    "nmap": {
                        "status": "available" if nmap_binary else "unavailable",
                        "detail": nmap_detail,
                    },
                    "nikto": orchestrator.scanner_status("nikto"),
                    "nessus": {
                        "status": "import-only",
                        "detail": "Completed .nessus XML scan exports can be imported for an authorized target; the app does not launch Nessus.",
                    },
                },
            )
        if parts == ["api", "intel-status"]:
            return json_response(200, self.intelligence_status())
        if parts[0] != "api":
            return error_response(404, "UI route not found")
        try:
            if len(parts) == 4 and parts[1] == "analyst":
                return json_response(200, self.analyst_report(parts[2], parts[3]))
            assessment = self._assessment_api(parts, parse_qs(parsed.query, keep_blank_values=True))
            if assessment is not None:
                return assessment
            with open_read_store(self.database) as store:
                if parts == ["api", "runs"]:
                    return json_response(200, {"runs": store.runs(), "selected_run": self.run_id})
                if len(parts) == 3 and parts[1] == "run":
                    return json_response(200, store.run(parts[2]))
                if len(parts) == 3 and parts[1] == "eval":
                    store.run_info(parts[2])
                    return json_response(
                        409,
                        {
                            "run_id": parts[2],
                            **store.unavailable("evaluation result", parts[2]),
                        },
                    )
                if len(parts) == 4 and parts[1] == "diff":
                    store.run_info(parts[2])
                    store.run_info(parts[3])
                    return json_response(
                        409,
                        {
                            "run_ids": parts[2:],
                            **store.unavailable("diff result", f"{parts[2]} / {parts[3]}"),
                        },
                    )
        except NeedsReview as error:
            return error_response(422, str(error))
        except (ConfigError, LLMUnavailable) as error:
            return error_response(409, str(error))
        return error_response(404, "UI route not found")


class UiRequestHandler(BaseHTTPRequestHandler):
    server_version = "VulnAssess"
    sys_version = ""
    timeout = 5.0

    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _reply(self, response: Response) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if response.status == 405:
            self.send_header("Allow", "GET")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self._reply(error_response(code, message or "Invalid UI request"))

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        if self.command not in ("GET", "POST"):
            self.close_connection = True
            self._reply(error_response(405, "UI supports GET only"))
            return False
        return True

    def _same_origin(self) -> bool:
        server = cast(UiServer, self.server)
        authority = f"127.0.0.1:{server.server_address[1]}"
        if self.headers.get_all("Host", []) != [authority]:
            self._reply(error_response(403, "UI Host must match its loopback address and port"))
            return False
        origin = self.headers.get("Origin")
        allowed = (None, f"http://{authority}")
        if origin not in allowed or self.headers.get("Sec-Fetch-Site") == "cross-site":
            self._reply(error_response(403, "Cross-origin UI requests are refused"))
            return False
        return True

    def _stream_analyst(
        self,
        run_id: str,
        host_ip: str,
        provider: str = "ollama",
        *,
        allow_fallback: bool = False,
        cloud_sharing_authorized: bool = False,
    ) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        def send(event: dict[str, Any]) -> None:
            self.wfile.write(
                json.dumps(event, ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n"
            )
            self.wfile.flush()

        try:
            server = cast(UiServer, self.server)
            result = server.application.analyst_report(
                run_id,
                host_ip,
                provider=provider,
                **(
                    {"allow_fallback": True, "cloud_sharing_authorized": cloud_sharing_authorized}
                    if allow_fallback
                    else {}
                ),
                on_progress=lambda stage, state, detail: send(
                    {"type": "stage", "stage": stage, "state": state, "detail": detail}
                ),
            )
            send({"type": "result", "result": result})
        except (BrokenPipeError, ConnectionResetError):
            return
        except NeedsReview as error:
            try:
                send({"type": "needs-review", "message": str(error)})
            except (BrokenPipeError, ConnectionResetError):
                return
        except (ConfigError, LLMUnavailable) as error:
            try:
                send({"type": "error", "message": str(error)})
            except (BrokenPipeError, ConnectionResetError):
                return
        except Exception:
            try:
                send({"type": "error", "message": "Analyst request failed unexpectedly."})
            except (BrokenPipeError, ConnectionResetError):
                return

    def _stream_live(
        self,
        target: str,
        provider: str,
        reuse_recent: bool = False,
        allow_fallback: bool = False,
        cloud_sharing_authorized: bool = False,
        replay_saved: bool = False,
        plan_id: str | None = None,
        plan_hash: str | None = None,
    ) -> None:
        self.send_response(200)
        for name, value in (
            ("Content-Type", "application/x-ndjson; charset=utf-8"),
            ("Content-Security-Policy", CSP),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Cache-Control", "no-store"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("Connection", "close"),
        ):
            self.send_header(name, value)
        self.end_headers()
        self.close_connection = True

        def send(event: dict[str, Any]) -> None:
            self.wfile.write(
                json.dumps(event, ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n"
            )
            self.wfile.flush()

        try:
            server = cast(UiServer, self.server)
            result = server.application.live_report(
                target,
                provider,
                lambda stage, state, detail: send(
                    {"type": "stage", "stage": stage, "state": state, "detail": detail}
                ),
                lambda capture: send({"type": "scan", "scan": capture}),
                reuse_recent=reuse_recent,
                allow_fallback=allow_fallback,
                **({"cloud_sharing_authorized": True} if cloud_sharing_authorized else {}),
                replay_saved=replay_saved,
                **({"plan_id": plan_id, "plan_hash": plan_hash} if plan_id is not None else {}),
            )
            send({"type": "result", "result": result})
        except (BrokenPipeError, ConnectionResetError):
            return
        except NeedsReview as error:
            try:
                send({"type": "needs-review", "message": str(error)})
            except (BrokenPipeError, ConnectionResetError):
                return
        except LLMUnavailable as error:
            try:
                send({"type": "needs-review", "message": str(error)})
            except (BrokenPipeError, ConnectionResetError):
                return
        except ConfigError as error:
            try:
                send({"type": "error", "message": str(error)})
            except (BrokenPipeError, ConnectionResetError):
                return
        except Exception:
            try:
                send({"type": "error", "message": "Live assessment failed unexpectedly."})
            except (BrokenPipeError, ConnectionResetError):
                return

    def do_GET(self) -> None:
        if not self._same_origin():
            return
        server = cast(UiServer, self.server)
        try:
            parsed = urlsplit(self.path)
            decoded = unquote(parsed.path, errors="strict")
        except (ValueError, UnicodeError):
            self._reply(error_response(404, "UI route not found"))
            return
        parts = decoded.split("/")
        if (
            len(parts) == 6
            and parts[:3] == ["", "api", "analyst"]
            and parts[5] == "events"
            and not parsed.scheme
            and not parsed.netloc
            and not parsed.query
            and not parsed.fragment
            and all(parts[3:5])
            and not any(part.startswith(".") for part in parts[3:5])
            and not any(character in decoded for character in ("\\", ":", "%"))
            and not any(ord(character) < 32 or ord(character) == 127 for character in decoded)
        ):
            self._stream_analyst(parts[3], parts[4])
            return
        self._reply(server.application.get(self.path))

    def do_POST(self) -> None:
        server = cast(UiServer, self.server)
        if (
            self.path != "/api/live-assessment/events"
            and self.path != "/api/device-recheck"
            and self.path != "/api/nessus-import"
            and self.path != "/api/public-website/check"
            and self.path != "/api/helpy"
            and not self.path.startswith("/api/analyst/")
            and self.path
            not in (
                "/api/evidence-requests/propose",
                "/api/evidence-requests/approve",
                "/api/evidence-requests/reject",
                "/api/evidence-requests/analyze",
            )
            and self.path
            not in ("/api/scan-plans/propose", "/api/scan-plans/edit", "/api/scan-plans/approve")
        ):
            self._reply(error_response(405, "POST route not found"))
            return
        if not self._same_origin():
            return
        authority = f"127.0.0.1:{server.server_address[1]}"
        action = (
            "helpy"
            if self.path == "/api/helpy"
            else "public-website"
            if self.path == "/api/public-website/check"
            else "device-recheck"
            if self.path == "/api/device-recheck"
            else "evidence-request"
            if self.path.startswith("/api/evidence-requests/")
            else "scan-plan"
            if self.path.startswith("/api/scan-plans/")
            else "nessus-import"
            if self.path == "/api/nessus-import"
            else "live-assessment"
            if self.path == "/api/live-assessment/events"
            else "cloud-analyst"
        )
        if (
            self.headers.get("Origin") != f"http://{authority}"
            or self.headers.get("X-VulnAssess-Action") != action
        ):
            self._reply(error_response(403, "Explicit same-origin action required"))
            return
        if self.path == "/api/helpy":
            try:
                size = int(self.headers.get("Content-Length", "-1"))
                if (
                    self.headers.get("Content-Type") != "application/json"
                    or len(self.headers.get_all("Content-Length", [])) != 1
                    or self.headers.get("Transfer-Encoding") is not None
                    or not 0 < size <= 4096
                ):
                    raise ConfigError("Invalid Helpy request size or type")
                response = server.application.helpy_answer(json.loads(self.rfile.read(size)))
            except (ValueError, UnicodeError, ConfigError, LLMUnavailable, OSError):
                self._reply(
                    error_response(
                        409,
                        "Helpy could not answer. Check provider configuration, sharing consent and saved assessment integrity; no scan was launched.",
                    )
                )
                return
            self._reply(json_response(200, response))
            return
        if self.path == "/api/public-website/check":
            try:
                size = int(self.headers.get("Content-Length", "-1"))
                if (
                    self.headers.get("Content-Type") != "application/json"
                    or len(self.headers.get_all("Content-Length", [])) != 1
                    or self.headers.get("Transfer-Encoding") is not None
                    or not 0 < size <= 4096
                ):
                    raise ConfigError("Invalid public website request size or type")
                body = json.loads(self.rfile.read(size))
                if (
                    not isinstance(body, dict)
                    or set(body) != {"target", "confirm_metadata_only"}
                    or body["confirm_metadata_only"] is not True
                ):
                    raise ConfigError("Explicit metadata-only confirmation is required")
                public_website.target(body["target"])
                application = server.application
                if not application._live_lock.acquire(blocking=False):
                    self._reply(error_response(409, "An assessment is busy; retry later"))
                    return
                try:
                    if time.monotonic() - application._last_public_check < 10:
                        self._reply(error_response(429, "Wait 10 seconds between website checks"))
                        return
                    application._last_public_check = time.monotonic()
                    settings = Settings(application.config_dir)
                    result = public_website.check(body["target"], settings.scope.is_canary)
                finally:
                    application._live_lock.release()
                self._reply(json_response(200, result))
            except (ValueError, ConfigError, OSError):
                self._reply(
                    error_response(
                        400, "Website check refused: invalid URL, DNS or public destination"
                    )
                )
            return
        if self.path == "/api/device-recheck":
            from vulnassess.self_defence import CHECKS, collect, save_recheck

            try:
                size = int(self.headers.get("Content-Length", "-1"))
                if self.headers.get("Content-Type") != "application/json" or not 0 < size <= 256:
                    raise ValueError("Invalid recheck request")
                body = json.loads(self.rfile.read(size))
                if (
                    not isinstance(body, dict)
                    or set(body) != {"check"}
                    or not isinstance(body["check"], str)
                    or body["check"] not in CHECKS
                ):
                    raise ValueError("Unknown device check")
                settings = Settings(server.application.config_dir)
                if not settings.scope.contains("127.0.0.1") or settings.scope.is_canary(
                    "127.0.0.1"
                ):
                    raise ValueError("Local device is outside authorized scope")
                if not server.application._live_lock.acquire(blocking=False):
                    self._reply(
                        error_response(409, "A device operation is busy; try again shortly")
                    )
                    return
                try:
                    result = collect(body["check"])
                    root = (
                        server.application.config_dir.resolve().parent / "data" / "device-rechecks"
                    )
                    result = save_recheck(root, result)
                finally:
                    server.application._live_lock.release()
                self._reply(json_response(200, result))
            except (ValueError, OSError, ConfigError):
                self._reply(error_response(400, "Device recheck could not be completed"))
            return
        if self.path.startswith(("/api/scan-plans/", "/api/evidence-requests/")):
            try:
                size = int(self.headers.get("Content-Length", "-1"))
                if self.headers.get("Content-Type") != "application/json" or not 0 < size <= 32768:
                    raise ConfigError("Invalid scan plan request size or type")
                handler = (
                    server.application.evidence_request_action
                    if self.path.startswith("/api/evidence-requests/")
                    else server.application.scan_plan_action
                )
                result = handler(self.path.rsplit("/", 1)[1], json.loads(self.rfile.read(size)))
                self._reply(json_response(200, result))
            except NeedsReview as error:
                self._reply(
                    json_response(422, {"error": {"type": "NeedsReview", "message": str(error)}})
                )
            except LLMUnavailable as error:
                self._reply(error_response(503, str(error)))
            except (ValueError, ConfigError, ScopeError, OSError) as error:
                self._reply(error_response(400, str(error)))
            return
        if self.path == "/api/nessus-import":
            try:
                size = int(self.headers.get("Content-Length", "-1"))
                run_id = self.headers.get("X-VulnAssess-Run", "")
                target_ip = self.headers.get("X-VulnAssess-Target", "")
                new_run = self.headers.get("X-VulnAssess-New-Run", "false")
                if (
                    self.headers.get("Content-Type") != "application/xml"
                    or not 0 < size <= MAX_CAPTURE_BYTES
                    or not 0 < len(run_id) <= 128
                    or not 0 < len(target_ip) <= 45
                    or new_run not in ("true", "false")
                ):
                    raise ValueError("invalid Nessus report request")
                ip_address(target_ip)
                result = server.application.import_nessus_report(
                    run_id, target_ip, self.rfile.read(size), new_run=new_run == "true"
                )
            except (ValueError, AdapterError, ConfigError, ScopeError, OSError) as error:
                self._reply(error_response(400, str(error)))
                return
            self._reply(json_response(200, result))
            return
        try:
            size = int(self.headers.get("Content-Length", "-1"))
            if self.headers.get("Content-Type") != "application/json" or not 0 < size <= 1024:
                raise ValueError("invalid request size or type")
            body = json.loads(self.rfile.read(size))
            parsed = urlsplit(self.path)
            decoded = unquote(parsed.path, errors="strict")
            parts = decoded.split("/")
        except (ValueError, UnicodeError, json.JSONDecodeError):
            self._reply(error_response(400, "Invalid cloud analyst request"))
            return
        if self.path == "/api/live-assessment/events":
            if isinstance(body, dict) and body.get("event_version") != 3:
                self._reply(
                    error_response(
                        409, "Workflow page updated. Reload this page before running a scan."
                    )
                )
                return
            if (
                not isinstance(body, dict)
                or not {"target", "provider", "share_evidence", "event_version"} <= set(body)
                or not set(body)
                <= {
                    "target",
                    "provider",
                    "share_evidence",
                    "reuse_recent",
                    "event_version",
                    "allow_fallback",
                    "replay_saved",
                    "plan_id",
                    "plan_hash",
                }
                or not isinstance(body["target"], str)
                or not 0 < len(body["target"]) <= 512
                or body["provider"] not in ("ollama", "openrouter", "groq", "groq_qwen", "google")
                or type(body["share_evidence"]) is not bool
                or (body["provider"] != "ollama" and body["share_evidence"] is not True)
                or (
                    body["provider"] == "ollama"
                    and body["share_evidence"] is True
                    and not body.get("allow_fallback", False)
                )
                or type(body.get("reuse_recent", False)) is not bool
                or type(body.get("replay_saved", False)) is not bool
                or type(body.get("allow_fallback", False)) is not bool
                or type(body["event_version"]) is not int
                or body["event_version"] != 3
                or ("plan_id" in body) != ("plan_hash" in body)
                or (
                    "plan_id" in body
                    and (
                        not isinstance(body["plan_id"], str)
                        or not re.fullmatch(r"[a-f0-9]{32}", body["plan_id"])
                        or not isinstance(body["plan_hash"], str)
                        or not re.fullmatch(r"[a-f0-9]{64}", body["plan_hash"])
                        or body.get("reuse_recent")
                        or body.get("replay_saved")
                    )
                )
            ):
                self._reply(error_response(400, "Invalid live assessment request"))
                return
            self._stream_live(
                body["target"],
                body["provider"],
                reuse_recent=body.get("reuse_recent", False),
                allow_fallback=body.get("allow_fallback", False),
                cloud_sharing_authorized=body["share_evidence"],
                replay_saved=body.get("replay_saved", False),
                plan_id=body.get("plan_id"),
                plan_hash=body.get("plan_hash"),
            )
            return
        valid_cloud = body in (
            {"provider": "openrouter", "share_evidence": True},
            {"provider": "groq", "share_evidence": True},
            {"provider": "groq_qwen", "share_evidence": True},
            {"provider": "google", "share_evidence": True},
        )
        valid_local_fallback = body == {
            "provider": "ollama",
            "share_evidence": True,
            "allow_fallback": True,
        }
        if (
            not isinstance(body, dict)
            or not (valid_cloud or valid_local_fallback)
            or len(parts) != 6
            or parts[:3] != ["", "api", "analyst"]
            or parts[5] != "events"
            or not all(parts[3:5])
            or parsed.query
            or parsed.fragment
            or parsed.scheme
            or parsed.netloc
            or any(character in decoded for character in ("\\", ":", "%"))
            or any(ord(character) < 32 or ord(character) == 127 for character in decoded)
        ):
            self._reply(error_response(400, "Invalid cloud analyst request"))
            return
        self._stream_analyst(
            parts[3],
            parts[4],
            provider=body["provider"],
            **(
                {"allow_fallback": True, "cloud_sharing_authorized": True}
                if valid_local_fallback
                else {}
            ),
        )


class UiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self, application: UiApplication, port: int = 8765, host: str = "127.0.0.1"
    ) -> None:
        if host != "127.0.0.1":
            raise ConfigError(f"UI bind address {host!r} is forbidden; use 127.0.0.1")
        if type(port) is not int or not 0 <= port <= 65535:
            raise ConfigError(f"UI port must be an integer in 0..65535, got {port!r}")
        self.application = application
        try:
            super().__init__((host, port), UiRequestHandler)
        except OSError as error:
            raise ConfigError(
                f"cannot bind UI to 127.0.0.1:{port}; choose another --port ({error})"
            ) from error

    def server_bind(self) -> None:
        TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]
