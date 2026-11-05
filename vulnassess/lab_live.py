"""Live lab investigations: actual protocol proof, independent capture and fixed retests.

Packet timing is correlation, not proof that arbitrary packets establish a vulnerability.
The existing owner-policy detector and scoring engine remain authoritative.
"""

import hashlib
import json
import re
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from vulnassess import (
    analyst,
    context,
    lab_ai,
    network_service_checks,
    network_service_policy,
    scoring,
)
from vulnassess.errors import ConfigError, LLMUnavailable
from vulnassess.schema import Finding, Host, Provenance, Service
from vulnassess.settings import Settings

ENVIRONMENTS = {"office": "127.0.0.2", "iot": "127.0.0.3"}
CASE_ID = re.compile(r"live-[a-f0-9]{32}\Z")
PROVIDERS = {"google", "groq", "groq_qwen", "openrouter", "ollama"}
ACTION_ENV = {
    "redis-office": "office",
    "redis-iot": "iot",
    "ftp-file": "office",
    "ftp-anonymous": "office",
    "ftp-protected": "office",
    "ssh-credential": "office",
    "ssh-protected": "office",
    "smb-read": "office",
    "smb-protected": "office",
    "mqtt-exchange": "iot",
    "mqtt-protected": "iot",
    "snmp-public": "iot",
    "snmp-protected": "iot",
    "tls-certificate": "iot",
}


def now():
    return datetime.now(UTC).isoformat()


def checksum(document):
    return hashlib.sha256(
        json.dumps(
            {k: v for k, v in document.items() if k != "sha256"},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()


def evidence_digest(case):
    """Bind collection evidence separately from later AI/control bookkeeping."""
    mutable = {
        "sha256",
        "evidence_sha256",
        "ai",
        "ai_attempts",
        "control",
        "control_failure",
        "comparison",
        "retest",
    }
    return checksum({key: value for key, value in case.items() if key not in mutable})


class LiveLab:
    def __init__(self, root, *, traffic=None, control=None, console=None, database=None):
        from labs.service_networks.console import ACTIONS, Console
        from vulnassess.lab_control import LabControl
        from vulnassess.lab_traffic import TrafficMonitor

        self.root = Path(root).resolve()
        self.directory = self.root / "data/network-live/cases"
        self.database = database if database is not None else self.root / "data/vulnassess.db"
        self.traffic = traffic or TrafficMonitor(self.root)
        self.control = control or LabControl(self.root)
        self.console = console or Console(self.root)
        self.actions = ACTIONS
        self.lock = threading.Lock()
        self.ai_lock = threading.Lock()
        self.ai_progress: dict[str, object] = {"running": False}
        self._assessment_instance = None
        self._assessment_init_lock = threading.Lock()

    @property
    def assessments(self):
        with self._assessment_init_lock:
            if self._assessment_instance is None:
                from vulnassess.lab_assessment import LabAssessment

                self._assessment_instance = LabAssessment(self.root)
            return self._assessment_instance

    def full_assessment(self, environment):
        self._environment(environment)
        suite = self.assessments.run(self, environment)
        return self.publish_assessment(suite["id"])

    def publish_assessment(self, identifier):
        from vulnassess.lab_projection import publish

        with self.lock:
            suite = self.assessments.load(identifier)
            try:
                suite["main_assessment"] = publish(self, suite, self.database)
            except (ConfigError, OSError, ValueError, TypeError, KeyError) as error:
                suite["main_assessment"] = {"status": "failed", "error": str(error)[:240]}
            self.assessments._save(suite)
            return suite

    def report_assessment(self, identifier, provider, cloud_consent):
        """Create a separate full AI report from the verified retained snapshot."""
        from vulnassess.capture_reanalysis import reanalyze

        if (
            not isinstance(provider, str)
            or provider not in PROVIDERS
            or type(cloud_consent) is not bool
        ):
            raise ConfigError("Choose a configured AI provider and sharing setting")
        if provider != "ollama" and not cloud_consent:
            raise ConfigError("Cloud report analysis requires explicit evidence-sharing consent")
        if not self.ai_lock.acquire(blocking=False):
            raise ConfigError("A live lab explanation or full report is already running")
        try:
            suite = self.publish_assessment(identifier)
            linked = suite["main_assessment"]
            if linked["status"] != "saved":
                raise ConfigError(
                    "Publish the verified lab assessment before generating its AI report"
                )
            self.ai_progress = {
                "running": True,
                "assessment_id": identifier,
                "provider": provider,
                "stage": "prepare",
            }

            def progress(stage, state, detail):
                self.ai_progress = {
                    "running": True,
                    "assessment_id": identifier,
                    "provider": provider,
                    "stage": stage,
                    "state": state,
                    "detail": detail[:300],
                }

            record = reanalyze(
                self.root / "data/live/raw",
                linked["capture_id"],
                provider,
                progress,
                cloud_sharing_authorized=cloud_consent,
            )
            analysis = record["result"].get("analyst") or {}
            if record["analysis_source"]["source_snapshot_hash"] != linked["snapshot_hash"]:
                raise ConfigError(
                    f"Selected source changed; AI report retained as {record['capture_id']}"
                )
            if record["result"]["ai_status"] == "validated":
                expected_ids = {
                    row["id"]
                    for row in record["payload"]["findings"]
                    if row["host_ip"] == record["result"]["resolved_ip"]
                }
                reviewed_ids = [
                    identity
                    for batch in (analysis.get("batches") or [analysis])
                    for identity in batch.get("finding_coverage", {}).get("included_ids", [])
                ]
                if (
                    not analysis
                    or len(reviewed_ids) != len(set(reviewed_ids))
                    or set(reviewed_ids) != expected_ids
                ):
                    raise ConfigError(
                        f"Full finding coverage was not established; saved report is {record['capture_id']}"
                    )
            report = {
                "capture_id": record["capture_id"],
                "source_capture_id": linked["capture_id"],
                "source_snapshot_hash": record["analysis_source"]["source_snapshot_hash"],
                "ai_status": record["result"]["ai_status"],
                "provider": provider,
                "model": analysis.get("model"),
                "generated_at": record.get("analysis_attempted_at"),
                "report_url": f"/captures/{record['capture_id']}/report",
                "finding_coverage": analysis.get("batch_coverage")
                or analysis.get("finding_coverage"),
                "scan_status": record["result"]["scan_status"],
                "snapshot_hash": record["snapshot_hash"],
            }
            with self.lock:
                current = self.assessments.load(identifier)
                if current.get("main_assessment") != linked:
                    raise ConfigError(
                        "The lab publication changed; the separate saved AI report was retained"
                    )
                current["ai_reports"] = [*current.get("ai_reports", []), report][-12:]
                self.assessments._save(current)
            return current
        finally:
            self.ai_progress = {"running": False}
            self.ai_lock.release()

    def _environment(self, environment):
        if not isinstance(environment, str) or environment not in ENVIRONMENTS:
            raise ConfigError("Choose the Office or IoT lab")
        # Scope is checked again by Console.endpoint before every actual connection.
        settings = Settings(self.root / "config")
        ip = ENVIRONMENTS[environment]
        if not settings.scope.contains(ip) or settings.scope.is_canary(ip):
            raise ConfigError("This lab is not authorised by the current scope")
        return settings

    def _local_directory(self):
        for path in [self.directory, *self.directory.parents]:
            if path == self.root:
                break
            if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                raise ConfigError("Live evidence must stay in the local project directory")

    def _save(self, case):
        self._local_directory()
        self.directory.mkdir(parents=True, exist_ok=True)
        if self.directory.is_symlink():
            raise ConfigError("Live evidence must be a local directory")
        case["sha256"] = checksum(case)
        path = self.directory / (case["id"] + ".json")
        temporary = path.with_suffix(".tmp-" + uuid4().hex)
        try:
            temporary.write_text(json.dumps(case, indent=2, allow_nan=False), encoding="utf-8")
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    def load(self, identifier):
        if not isinstance(identifier, str) or not CASE_ID.fullmatch(identifier):
            raise ConfigError("Unknown live investigation")
        path = self.directory / (identifier + ".json")
        self._local_directory()
        if self.directory.is_symlink() or path.is_symlink():
            raise ConfigError("Live evidence must be a local regular file")
        try:
            with path.open("rb") as stream:
                raw = stream.read(524289)
            if len(raw) > 524288:
                raise ValueError("Evidence exceeds the read budget")

            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("Duplicate evidence key")
                    result[key] = value
                return result

            case = json.loads(raw, object_pairs_hook=unique)
            if (
                case.get("id") != identifier
                or case.get("environment") not in ENVIRONMENTS
                or case.get("sha256") != checksum(case)
            ):
                raise ValueError("Evidence integrity failed")
            return case
        except (ValueError, OSError, TypeError, AttributeError) as error:
            raise ConfigError("Live investigation is unavailable or has changed") from error

    def history(self, environment):
        if not self.directory.exists():
            return []
        rows = []
        paths = sorted(
            self.directory.glob("live-*.json"), key=lambda p: p.stat().st_mtime_ns, reverse=True
        )
        for path in paths[:100]:
            try:
                case = self.load(path.stem)
            except ConfigError:
                continue
            if case["environment"] == environment:
                rows.append(case)
            if len(rows) == 12:
                break
        return rows

    def status(self, environment):
        self._environment(environment)
        cases = self.history(environment)
        return {
            "environment": environment,
            "target": ENVIRONMENTS[environment],
            "observed_at": now(),
            "topology": self.traffic.topology(),
            "capture": self.traffic.snapshot(environment),
            "investigations": cases,
            "ai_validations": {case["id"]: self._ai_validation(case) for case in cases},
            "ai_progress": dict(self.ai_progress),
            "assessments": self.assessments.history(environment),
            "assessment_progress": getattr(self.assessments, "progress", None),
            "busy": self.lock.locked(),
            "boundary": "Live observations and saved investigations have separate timestamps. Captured packets alone do not establish a vulnerability.",
        }

    def _operation(self, environment, action, *, kind="check"):
        settings = self._environment(environment)
        if not isinstance(action, str) or ACTION_ENV.get(action) != environment:
            raise ConfigError("Operation does not belong to the selected lab")
        ip = ENVIRONMENTS[environment]
        policy = network_service_policy.load(settings.config_dir, settings.scope, ip)
        if policy is None:
            raise ConfigError("No current endpoint policy authorises this operation")
        expected_ip, entry = self.console.endpoint(environment, self.actions[action][1])
        if expected_ip != ip or entry not in policy["endpoints"]:
            raise ConfigError("Endpoint policy changed before this operation")
        clock_samples = []
        clock_error = None
        sample_clock = getattr(self.traffic, "clock_sample", None)
        if callable(sample_clock):
            try:
                clock_samples.append(sample_clock(environment))
            except (ConfigError, OSError, ValueError, RuntimeError) as error:
                clock_error = str(error)[:240]
        started = now()
        result = self.console.action(action)
        finished = now()
        if clock_samples and callable(sample_clock):
            try:
                clock_samples.append(sample_clock(environment))
            except (ConfigError, OSError, ValueError, RuntimeError) as error:
                clock_error = str(error)[:240]
        identifier = "live-" + uuid4().hex
        case = {
            "schema_version": 1,
            "id": identifier,
            "environment": environment,
            "kind": kind,
            "action": action,
            "target": ip,
            "port": entry["port"],
            "transport": entry["transport"],
            "started_at": started,
            "finished_at": finished,
            "result": result,
            "ai": {"status": "not_requested"},
        }
        try:
            case["packet_evidence"], capture = self.traffic.collect(
                environment,
                entry["port"],
                started,
                finished,
                **({"clock_samples": clock_samples} if clock_samples else {}),
            )
            if clock_error:
                case["packet_evidence"]["clock_alignment_error"] = clock_error
            self._local_directory()
            self.directory.mkdir(parents=True, exist_ok=True)
            path = self.directory / (identifier + ".pcap")
            path.write_bytes(capture)
            case["pcap"] = {
                "bytes": len(capture),
                "sha256": hashlib.sha256(capture).hexdigest(),
                "url": f"/api/network-live/evidence/{identifier}.pcap",
            }
        except (ConfigError, OSError, ValueError, RuntimeError) as error:
            case.setdefault("packet_evidence", {"packet_ids": [], "packets": []})
            case["packet_evidence"]["error"] = str(error)[:240]
        validation_error = None
        try:
            current_settings = self._environment(environment)
            current_policy = network_service_policy.load(
                current_settings.config_dir, current_settings.scope, ip
            )
        except (ConfigError, OSError, ValueError) as error:
            current_policy = None
            validation_error = str(error)[:240]
        if current_policy is None or current_policy["policy_sha256"] != policy["policy_sha256"]:
            case["policy_sha256"] = policy["policy_sha256"]
            case["findings"] = []
            case["policy_error"] = (
                "Owner policy changed during the exchange; no finding was finalized"
            )
            if validation_error:
                case["policy_error"] += ": " + validation_error
            case["evidence_url"] = f"/api/network-live/evidence/{identifier}.json"
            case["evidence_sha256"] = evidence_digest(case)
            self._save(case)
            raise ConfigError(case["policy_error"])
        intended = {
            k: v for k, v in entry.items() if k not in {"credential", "monitoring_community"}
        }
        proof = result["proof"]
        service = Service(
            entry["port"],
            entry["transport"],
            name="microsoft-ds" if entry["service"] == "smb" else entry["service"],
            tls=proof.get("protocol_confirmed") is True and bool(proof.get("tls_version")),
            banner=(
                f"{entry['service']} confirmed by bounded live protocol exchange"
                if proof.get("protocol_confirmed") is True
                else f"{entry['service']} endpoint policy; protocol not confirmed"
            ),
        )
        profile = context.build_profile(
            Host(ip=ip, services=(service,) if proof.get("protocol_confirmed") is True else ()),
            [],
            settings.scope,
            settings.roles,
            settings.controls,
        )
        case["context"] = profile.to_json()
        case["policy_sha256"] = policy["policy_sha256"]
        case["expected_policy"] = intended
        case["findings"] = []
        for key, title, cwe in network_service_checks.violations(entry, proof):
            finding = Finding.make(
                host_ip=ip,
                port=entry["port"],
                protocol=entry["transport"],
                tool="service-network",
                tool_native_id=f"policy:{entry['service']}:{entry['port']}:{key}",
                title=title,
                description="Live protocol proof contradicts the current owner-supplied endpoint policy.",
                evidence=json.dumps(
                    {
                        "target_ip": ip,
                        "port": entry["port"],
                        "protocol": entry["transport"],
                        "policy_sha256": policy["policy_sha256"],
                        "expected_policy": intended,
                        "observed": proof,
                    }
                ),
                native_severity="Medium",
                native_confidence="high",
                cwe_ids=[cwe],
                provenance=Provenance(
                    "service-network",
                    str(self.directory / (identifier + ".json")),
                    len(case["findings"]),
                    identifier,
                ),
            )
            score = scoring.score(finding, None, profile, (service,), settings.weights)
            guidance = network_service_checks.guidance(finding.to_json())
            if guidance is not None and action == "ftp-file" and proof.get("anonymous_accepted"):
                guidance["meaning"] = (
                    "Anonymous FTP access was accepted where the owner requires authentication. "
                    f"The explicitly authorised training file was retrieved ({proof['bytes_received']} bytes). "
                    "No other file or directory was requested."
                )
            case["findings"].append(
                {
                    "finding": finding.to_json(),
                    "score": score.to_json(),
                    "guidance": guidance,
                }
            )
        case["findings"].sort(key=lambda row: -row["score"]["risk"])
        case["evidence_url"] = f"/api/network-live/evidence/{identifier}.json"
        case["evidence_sha256"] = evidence_digest(case)
        self._save(case)
        return case

    def check(self, environment, action):
        if not self.lock.acquire(blocking=False):
            raise ConfigError("A lab check or configuration change is already running")
        try:
            return self._operation(environment, action)
        finally:
            self.lock.release()

    def change(self, environment, profile):
        self._environment(environment)
        if profile not in {"restricted", "baseline"}:
            raise ConfigError("Unknown fixed lab configuration")
        if not self.lock.acquire(blocking=False):
            raise ConfigError("A lab check or configuration change is already running")
        try:
            action = "ftp-anonymous" if environment == "office" else "mqtt-exchange"
            before = self._operation(environment, action, kind="before_change")
            try:
                control = self.control.set_profile(environment, profile)
            except ConfigError as error:
                before["control_failure"] = getattr(error, "receipt", {"error": str(error)[:240]})
                self._save(before)
                raise
            if control.get("status") != "verified" or control.get("profile") != profile:
                before["control_failure"] = control
                self._save(before)
                raise ConfigError(
                    "Lab configuration change was not verified; inspect the retained control receipt"
                )
            before["control"] = control
            before["retest"] = {"status": "pending", "requested_profile": profile}
            self._save(before)
            try:
                after = self._operation(environment, action, kind="after_change")
            except Exception as error:
                before["retest"] = {
                    "status": "failed",
                    "requested_profile": profile,
                    "error": str(error)[:240],
                    "meaning": "The configuration change was verified; the follow-up check failed. No successful remediation verdict is established.",
                }
                self._save(before)
                raise ConfigError(
                    "Configuration changed, but the retest failed: " + str(error)[:240]
                ) from error
            same_target = all(
                before[key] == after[key] for key in ("target", "port", "transport", "action")
            )
            same_policy = before["policy_sha256"] == after["policy_sha256"]
            conclusive = all(
                case["result"]["decision"].get("inconclusive") is False
                and case["result"]["proof"].get("protocol_confirmed") is True
                and type(case["result"]["proof"].get("anonymous_accepted")) is bool
                for case in (before, after)
            )
            status = "inconclusive"
            meaning = (
                "The configuration change was verified, but the checks do not establish a "
                "conclusive comparison under the same endpoint and owner policy. "
                "No successful remediation verdict is established."
            )
            if same_target and same_policy and conclusive:
                if after["result"]["proof"]["anonymous_accepted"] != (profile == "baseline"):
                    status = "failed"
                    meaning = (
                        "The follow-up protocol response contradicts the requested access "
                        "configuration. No successful remediation verdict is established."
                    )
                else:
                    status = "complete"
                    meaning = (
                        "IoT restriction is deny-all MQTT containment, not a usable authenticated broker."
                        if environment == "iot" and profile == "restricted"
                        else "The same listener explicitly accepted anonymous access under the restored baseline."
                        if profile == "baseline"
                        else "The same FTP listener explicitly refused anonymous access under the selected restriction."
                    )
            before["retest"] = {
                "status": status,
                "after_id": after["id"],
                "requested_profile": profile,
                "meaning": meaning,
            }
            self._save(before)
            after["comparison"] = {
                "status": status,
                "before_id": before["id"],
                "before_observed_at": before["finished_at"],
                "before_proof": before["result"]["proof"],
                "before_violations": before["result"]["decision"]["violations"],
                "before_priorities": [
                    {
                        "title": row["finding"]["title"],
                        "risk": row["score"]["risk"],
                        "band": row["score"]["band"],
                        "basis": row["score"].get("native_fallback"),
                    }
                    for row in before["findings"]
                ],
                "after_violations": after["result"]["decision"]["violations"],
                "after_proof": after["result"]["proof"],
                "same_target": same_target,
                "same_policy": same_policy,
                "control": control,
                "requested_profile": profile,
                "meaning": meaning,
            }
            self._save(after)
            return after
        finally:
            self.lock.release()

    def pcap(self, identifier):
        case = self.load(identifier)
        if "pcap" not in case:
            raise ConfigError("No independent capture was retained for this investigation")
        path = self.directory / (identifier + ".pcap")
        if path.is_symlink():
            raise ConfigError("Capture must be a local regular file")
        with path.open("rb") as stream:
            data = stream.read(8 * 1024 * 1024 + 1)
        if (
            len(data) != case["pcap"]["bytes"]
            or hashlib.sha256(data).hexdigest() != case["pcap"]["sha256"]
        ):
            raise ConfigError("Saved packet capture integrity failed")
        return data

    def _ai_validation(self, case):
        ai = case.get("ai", {})
        result = {"status": "not_requested", "case_sha256": case["sha256"]}
        if ai.get("status") == "validated_selection":
            facts = self._facts(case)
            digest = checksum(facts)
            result.update(
                status="current" if ai.get("facts_sha256") == digest else "stale",
                facts_sha256=digest,
            )
            if result["status"] == "current":
                try:
                    lab_ai.validate_saved(facts, ai)
                except LLMUnavailable:
                    result["status"] = "invalid"
        return result

    def _facts(self, case):
        findings = case["findings"]
        decision = case["result"]["decision"]
        facts = {
            "observation": {
                "kind": "observations",
                "text": f"The {case['action']} check on {case['target']}:{case['port']}/{case['transport']} "
                + (
                    "was inconclusive."
                    if decision["inconclusive"]
                    else "established: " + "; ".join(decision["violations"])
                    if decision["violations"]
                    else "did not observe a violation of the tested endpoint policy."
                ),
            },
            "capture": {
                "kind": "observations",
                "text": f"The independent capture associated {len(case.get('packet_evidence', {}).get('packet_ids', []))} packet records with this endpoint and time window. "
                "This is temporal and endpoint correlation, not proof of a causal mapping for every packet.",
            },
            "scope": {
                "kind": "limits",
                "text": "This is an intentionally configured local service lab. No OS compromise, lateral movement, business impact or CVE applicability is inferred from these observations.",
            },
            "context": {
                "kind": "why_it_matters",
                "text": f"Recorded context: exposure {case['context']['exposure']['value']}; "
                f"role {case['context']['role']['value']}. The loopback target represents an isolated training service, not an internet-facing production asset.",
            },
        }
        clock = case.get("packet_evidence", {}).get("clock_alignment", {})
        if clock.get("status") == "bounded":
            facts["capture"]["text"] += (
                f" Observer-clock association uncertainty is {clock['uncertainty_ms']:.3f} ms. "
                + clock["assumption"]
                + " "
                + clock["limit"]
            )
        if case["action"] in {"redis-office", "redis-iot"}:
            proof = case["result"]["proof"]
            facts["observation"]["text"] = (
                (
                    f"INFO server reported Redis {proof['redis_version']} on {case['target']}:{case['port']}. "
                    if proof.get("identity_established") is True
                    else "The Redis protocol responded, but service identity was not established. "
                    if proof.get("protocol_confirmed") is True
                    else "This operation did not establish a Redis protocol response or service identity. "
                )
                + "This operation collected identity evidence only; it did not test CVE applicability or exploitability."
            )
        for i, row in enumerate(findings):
            score, finding = row["score"], row["finding"]
            facts[f"priority{i}"] = {
                "kind": "why_it_matters",
                "text": f"{finding['title']} is ranked {score['risk']}/100 ({score['band']}) by the deterministic "
                f"{score.get('native_fallback') or 'recorded scoring policy'} path. This local policy triage is not CVSS or an exploitation probability. "
                + str(score.get("reason", "")),
            }
            guidance = row.get("guidance") or {}
            facts[f"impact{i}"] = {
                "kind": "why_it_matters",
                "text": str(guidance.get("meaning") or finding["description"]),
            }
            for j, action in enumerate(guidance.get("patch", [])[:2]):
                facts[f"fix{i}_{j}"] = {"kind": "next_steps", "text": action}
        facts["retest"] = {
            "kind": "next_steps",
            "text": "Repeat the identical endpoint-policy check after the configuration change and compare explicit protocol acceptance or refusal, using the same target, port and policy.",
        }
        if case["action"] in {"redis-office", "redis-iot"}:
            facts["retest"]["text"] = (
                "Obtain the authorised package revision and patch status, then compare them with "
                "vendor advisories. An upstream Redis version alone does not confirm an exploitable CVE."
            )
        if case.get("comparison"):
            c = case["comparison"]
            before_proof, after_proof = c.get("before_proof", {}), c.get("after_proof", {})
            verified = (
                c.get("status") == "complete"
                and c.get("same_target") is True
                and c.get("same_policy") is True
                and case["result"]["decision"].get("inconclusive") is False
                and all(
                    proof.get("protocol_confirmed") is True
                    and type(proof.get("anonymous_accepted")) is bool
                    for proof in (before_proof, after_proof)
                )
                and after_proof == case["result"]["proof"]
                and c.get("requested_profile") in {"baseline", "restricted"}
                and after_proof.get("anonymous_accepted")
                == (c.get("requested_profile") == "baseline")
            )
            meaning = (
                c["meaning"]
                if verified
                else "This comparison does not establish a successful remediation or access change. "
                "Historical interpretation is not treated as verified protocol evidence."
            )
            facts["retest"]["text"] = (
                "The recorded same-endpoint retest is complete. "
                + (
                    "The intentionally insecure training baseline was restored; this is not remediation. "
                    if c.get("requested_profile") == "baseline"
                    else "Preserve the tested access restriction, "
                )
                + "Repeat this check after future configuration changes, and assess other endpoints separately. "
                + meaning
                if verified
                else "The recorded comparison does not verify a successful access change. "
                "Repeat the same endpoint and policy check and obtain an explicit protocol result. "
                + meaning
            )
            protocol_change = ""
            if before_proof and after_proof:
                protocol_change = (
                    " Protocol response before: "
                    + str(before_proof.get("response") or before_proof.get("connack_hex"))
                    + "; after: "
                    + str(after_proof.get("response") or after_proof.get("connack_hex"))
                    + "."
                )
            facts["change"] = {
                "kind": "observations",
                "text": f"Before change: {c['before_violations']}. After change: {c['after_violations']}. "
                f"Recorded same endpoint: {c['same_target']}; recorded same owner policy: {c['same_policy']}. {meaning}"
                + protocol_change,
            }
            if c.get("before_priorities"):
                facts["earlier_priority"] = {
                    "kind": "why_it_matters",
                    "text": "Before the change, the deterministic policy recorded these priorities: "
                    + json.dumps(c["before_priorities"])
                    + ". The retest does not assign a zero-risk score or clear unrelated services.",
                }
        return facts

    def explain(self, identifier, provider, cloud_consent, *, client=None):
        if (
            not isinstance(provider, str)
            or provider not in PROVIDERS
            or type(cloud_consent) is not bool
        ):
            raise ConfigError("Choose a configured AI provider and sharing setting")
        if provider != "ollama" and not cloud_consent:
            raise ConfigError("Cloud analysis requires consent to share these bounded lab facts")
        if not self.ai_lock.acquire(blocking=False):
            raise ConfigError("A live lab explanation is already running")
        attempt: dict[str, object] | None = None
        started = time.monotonic()
        self.ai_progress = {
            "running": True,
            "case_id": identifier,
            "provider": provider,
            "stage": "prepare",
        }
        try:
            case = self.load(identifier)
            if case.get("policy_error"):
                raise ConfigError(
                    "Repeat the check under a stable endpoint policy before AI analysis"
                )
            facts = self._facts(case)
            attempt = {
                "id": "ai-" + uuid4().hex,
                "provider": provider,
                "started_at": now(),
                "facts_sha256": checksum(facts),
                "stage": "prepare",
            }
            prompt, schema, options = lab_ai.request(facts)
            client = client or analyst.provider_client(provider)
            attempt.update(
                model=client.model, stage="generate", request_characters=len(prompt), **options
            )
            self.ai_progress = {**self.ai_progress, "stage": "generate"}
            output = client.generate_structured(
                prompt, schema, num_predict=options["num_predict"], num_ctx=options["num_ctx"]
            )
            attempt["stage"] = "validate"
            self.ai_progress = {**self.ai_progress, "stage": "validate"}
            raw_selection = output
            output, duplicates = lab_ai.selection(facts, output, deduplicate=True)
            attempt["selection_sha256"] = checksum({"selection": raw_selection})
            ai = {
                "status": "validated_selection",
                "provider": provider,
                "model": client.model,
                "generated_at": now(),
                "facts_sha256": checksum(facts),
                "sections": {
                    section: [
                        {"reference": ref, "text": facts[ref]["text"]} for ref in output[section]
                    ]
                    for section in lab_ai.SECTIONS
                },
                "normalisation": {"duplicate_references_removed": duplicates},
                "method": "AI selects and orders verified facts. Wording and numerical scores remain bound to server-side evidence; this is not free-form factual generation.",
            }
            # Generation may outlive a configuration change. Serialize only the
            # final merge with lab operations, then revalidate the exact facts.
            # Never write the pre-generation snapshot over newer case metadata.
            with self.lock:
                current = self.load(identifier)
                if current.get("policy_error") or checksum(self._facts(current)) != checksum(facts):
                    raise LLMUnavailable(
                        "Investigation facts changed during AI generation; repeat the explanation "
                        "using the current evidence"
                    )
                current["ai"] = ai
                attempt.update(
                    status="validated_selection",
                    stage="complete",
                    finished_at=now(),
                    elapsed_ms=round((time.monotonic() - started) * 1000),
                )
                current["ai_attempts"] = [*current.get("ai_attempts", []), attempt][-8:]
                self._save(current)
                return current
        except (LLMUnavailable, ConfigError, OSError, ValueError, TypeError) as error:
            if attempt is not None:
                attempt.update(
                    status="failed",
                    error_type=type(error).__name__,
                    finished_at=now(),
                    elapsed_ms=round((time.monotonic() - started) * 1000),
                )
                # Retain bounded outcome metadata, not raw provider output or
                # exception text that might contain credentials or target prose.
                with self.lock:
                    current = self.load(identifier)
                    current["ai_attempts"] = [*current.get("ai_attempts", []), attempt][-8:]
                    self._save(current)
            raise
        finally:
            self.ai_progress = {"running": False}
            self.ai_lock.release()
