"""Hash-verified frozen assessment bundles.

SQLite observation/intelligence reads are run-bound; exports also freeze the
remaining draft assessment state and current configuration.
"""

import json
from pathlib import Path
from typing import Any

from vulnassess import cvss31, scoring
from vulnassess.audit import load_json_payload
from vulnassess.control_applicability import POLICY_VERSION
from vulnassess.errors import ConfigError, IntelUnavailable
from vulnassess.role_model import ROLES
from vulnassess.schema import SOURCES, ContextProfile, Enrichment, Finding, Host

SNAPSHOT_SCHEMA_VERSION = 1
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024


def _canonical(payload: Any) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _digest(payload: Any) -> str:
    from hashlib import sha256

    return sha256(_canonical(payload).encode("utf-8")).hexdigest()


def build_snapshot(
    settings, store, run_id: str, *, model_hash: str | None = None
) -> dict[str, Any]:
    """Validate captured state; legacy uncertain range metadata remains unknown."""
    try:
        payload = _build_snapshot(settings, store, run_id, model_hash=model_hash)
        return validate_snapshot(payload)
    except ConfigError as error:
        raise ConfigError(f"invalid assessment snapshot for run {run_id!r}: {error}") from error
    except (KeyError, ValueError, TypeError, AttributeError, RecursionError) as error:
        raise ConfigError(f"invalid assessment snapshot for run {run_id!r}: {error}") from error


def _build_snapshot(
    settings, store, run_id: str, *, model_hash: str | None = None
) -> dict[str, Any]:
    run = store.run_info(run_id)
    if run is None:
        raise ConfigError(f"MISSING: run {run_id!r}")
    findings = store.findings(run_id)
    finding_ids = {finding.id for finding in findings}
    scores = store.scores(run_id)
    profiles = store.profiles(run_id)
    hosts = store.hosts(run_id)
    rationales = store.rationales(run_id)
    captured_enrichments = store.enrichments_for_run(run_id)
    enrichments = {
        finding.id: [item.to_json() for item in captured_enrichments.get(finding.id, [])]
        for finding in findings
    }
    score_ids = {score.finding_id for score in scores}
    if score_ids - finding_ids:
        raise ConfigError(
            f"run {run_id!r} has score rows without findings: {sorted(score_ids - finding_ids)}"
        )
    profile_hosts = {profile.host_ip for profile in profiles}
    host_ips = {host.ip for host in hosts}
    if profile_hosts - host_ips:
        raise ConfigError(
            f"run {run_id!r} has context profiles without hosts: {sorted(profile_hosts - host_ips)}"
        )
    rationale_ids = set(rationales)
    if rationale_ids - finding_ids:
        raise ConfigError(
            f"run {run_id!r} has rationales without findings: {sorted(rationale_ids - finding_ids)}"
        )

    feed_meta = {
        key: {
            "path": value.get("path"),
            "sha256": value.get("sha256"),
            "file_date": value.get("file_date"),
            "rows": value.get("rows"),
        }
        for key, value in store.feeds_meta(run_id=run_id).items()
    }
    core = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "evidence_status": "NOT RUN",
        "data_kind": "assessment_state",
        "run": run,
        "configuration": {
            "hash_current": settings.config_hash(),
            "hash_at_run_start": run.get("config_hash"),
            "drift": settings.config_hash() != run.get("config_hash"),
            "validated": settings.raw,
        },
        "feed_snapshot": feed_meta,
        "model_hash": model_hash,
        "hosts": [host.to_json() for host in hosts],
        "findings": [finding.to_json() for finding in findings],
        "enrichments": enrichments,
        "profiles": [profile.to_json() for profile in profiles],
        "scores": [score.to_json() for score in scores],
        "rationales": {
            finding_id: rationale.to_json() for finding_id, rationale in sorted(rationales.items())
        },
        "history": store.history_status(run_id),
        "limitations": store.history_status(run_id)["limitations"],
    }
    return {**core, "snapshot_hash": _digest(core)}


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{name} must be an object with string keys")
    return value


def _text(value: Any, name: str, *, nonblank: bool = True) -> str:
    if not isinstance(value, str) or (nonblank and not value.strip()):
        raise ValueError(f"{name} must be {'nonblank ' if nonblank else ''}text")
    return value


def _records(value: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array of objects")
    return [_object(item, f"{name}[{index}]") for index, item in enumerate(value)]


def _index(records: list[dict[str, Any]], key: str, name: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        identifier = _text(record.get(key), f"{name}.{key}")
        if identifier in result:
            raise ValueError(f"duplicate {name}.{key} identity {identifier!r}")
        result[identifier] = record
    return result


def _number(value: Any, name: str, minimum: float, maximum: float) -> None:
    if type(value) not in (int, float) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be a finite number in [{minimum}, {maximum}]")


def _strings(value: Any, name: str) -> None:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array of strings")
    for item in value:
        _text(item, name)


def _optional_text(record: dict[str, Any], names: tuple[str, ...], label: str) -> None:
    for name in names:
        if name in record and record[name] is not None:
            _text(record[name], f"{label}.{name}", nonblank=False)


def _feature(value: Any, name: str) -> dict[str, Any]:
    feature = _object(value, name)
    if {"value", "confidence", "source", "evidence"} - feature.keys():
        raise ValueError(f"{name} is missing a required feature field")
    _number(feature["confidence"], f"{name}.confidence", 0, 1)
    source = _text(feature["source"], f"{name}.source")
    if source not in SOURCES:
        raise ValueError(f"{name}.source is unsupported")
    _text(feature["evidence"], f"{name}.evidence")
    return feature


def _validate_hosts(hosts: dict[str, dict[str, Any]]) -> None:
    for host in hosts.values():
        _optional_text(host, ("hostname", "os_guess"), "hosts")
        for service in _records(host.get("services", []), "hosts.services"):
            port = service.get("port")
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("hosts.services.port must be an integer in [1, 65535]")
            if service.get("protocol") not in ("tcp", "udp"):
                raise ValueError("hosts.services.protocol must be tcp or udp")
            if "tls" in service and type(service["tls"]) is not bool:
                raise ValueError("hosts.services.tls must be Boolean")
            _optional_text(
                service, ("name", "product", "version", "cpe", "banner"), "hosts.services"
            )


def _validate_findings(
    findings: dict[str, dict[str, Any]], hosts: dict[str, dict[str, Any]]
) -> None:
    for finding in findings.values():
        host_ip = _text(finding.get("host_ip"), "findings.host_ip")
        if host_ip not in hosts:
            raise ValueError("finding references a host outside this snapshot")
        for name in ("tool", "tool_native_id", "title", "evidence"):
            _text(finding.get(name), f"findings.{name}", nonblank=name in {"tool", "evidence"})
        port = finding.get("port")
        if port is not None and (type(port) is not int or not 1 <= port <= 65535):
            raise ValueError("findings.port must be null or an integer in [1, 65535]")
        _optional_text(
            finding,
            (
                "protocol",
                "url",
                "description",
                "native_severity",
                "native_confidence",
                "first_seen",
                "last_seen",
            ),
            "findings",
        )
        for name in ("cve_ids", "cwe_ids", "reference_urls"):
            if name in finding:
                _strings(finding[name], f"findings.{name}")
        provenance = _object(finding.get("provenance"), "findings.provenance")
        for name in ("tool", "raw_path", "run_id"):
            _text(provenance.get(name), f"findings.provenance.{name}")
        if provenance["tool"] != finding["tool"]:
            raise ValueError("findings.provenance.tool contradicts finding tool")
        index = provenance.get("record_index")
        if type(index) is not int or index < 0:
            raise ValueError("findings.provenance.record_index must be a nonnegative integer")


def _validate_profiles(
    profiles: dict[str, dict[str, Any]], hosts: dict[str, dict[str, Any]]
) -> None:
    for host_ip, profile in profiles.items():
        if host_ip not in hosts:
            raise ValueError("profile references a host outside this snapshot")
        role = _feature(profile.get("role"), "profiles.role")["value"]
        exposure = _feature(profile.get("exposure"), "profiles.exposure")["value"]
        if not isinstance(role, str) or role not in ROLES:
            raise ValueError("profiles.role.value is unsupported")
        if exposure not in ("internal", "internet_facing"):
            raise ValueError("profiles.exposure.value is unsupported")
        _optional_text(profile, ("segment",), "profiles")
        controls = _object(profile.get("controls", {}), "profiles.controls")
        for name, feature in controls.items():
            if name not in ("waf", "auth_required", "tls", "rate_limiting"):
                raise ValueError(f"profiles.controls has unsupported key {name!r}")
            value = _feature(feature, f"profiles.controls.{name}")["value"]
            if value is not None and type(value) is not bool:
                if name != "waf" or not isinstance(value, str) or not value.strip():
                    raise ValueError(f"profiles.controls.{name}.value has an unsupported type")
        for name, feature in _object(profile.get("manual", {}), "profiles.manual").items():
            value = _feature(feature, f"profiles.manual.{name}")["value"]
            if name == "criticality":
                if type(value) is not int or not 1 <= value <= 5:
                    raise ValueError("profiles.manual.criticality.value must be an integer 1-5")
            elif name != "environment" or value not in ("prod", "test"):
                raise ValueError("profiles.manual has unsupported key or environment value")


def _validate_enrichments(raw: dict[str, Any], findings: dict[str, dict[str, Any]]) -> None:
    for finding_id, entries in raw.items():
        if finding_id not in findings:
            raise ValueError("enrichments references a finding outside this snapshot")
        seen: set[str] = set()
        for entry in _records(entries, "enrichments"):
            if entry.get("finding_id") != finding_id:
                raise ValueError("enrichments.finding_id contradicts its owner")
            cve_id = _text(entry.get("cve_id"), "enrichments.cve_id")
            if cve_id in seen:
                raise ValueError("duplicate enrichments.cve_id for finding")
            seen.add(cve_id)
            if entry.get("match_method") not in ("explicit", "cpe_range"):
                raise ValueError("enrichments.match_method is unsupported")
            if entry["match_method"] == "explicit" and cve_id not in findings[finding_id].get(
                "cve_ids", []
            ):
                raise ValueError("explicit enrichment CVE is not named by its finding")
            _number(entry.get("match_confidence"), "enrichments.match_confidence", 0, 1)
            for field, maximum in (
                ("cvss31_base", 10),
                ("cvss40_base", 10),
                ("epss", 1),
                ("epss_percentile", 1),
            ):
                if field in entry and entry[field] is not None:
                    _number(entry[field], f"enrichments.{field}", 0, maximum)
            if "kev" in entry and type(entry["kev"]) is not bool:
                raise ValueError("enrichments.kev must be Boolean")
            if (
                "version_end_inclusive" in entry
                and entry["version_end_inclusive"] is not None
                and type(entry["version_end_inclusive"]) is not bool
            ):
                raise ValueError("enrichments.version_end_inclusive must be Boolean or null")
            for field in ("patch_references",):
                if field in entry:
                    _strings(entry[field], f"enrichments.{field}")
            if "feed_dates" in entry:
                for value in _object(entry["feed_dates"], "enrichments.feed_dates").values():
                    _text(value, "enrichments.feed_dates", nonblank=False)
            _optional_text(
                entry,
                ("cvss31_vector", "cvss40_vector", "kev_date_added", "description", "version_end"),
                "enrichments",
            )


def _same_json(left: Any, right: Any) -> bool:
    """Compare JSON facts without equating Boolean declarations with numbers."""
    if type(left) is bool or type(right) is bool:
        return type(left) is type(right) and left == right
    if type(left) in (int, float) and type(right) in (int, float):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _same_json(value, right[key]) for key, value in left.items()
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _same_json(first, second) for first, second in zip(left, right)
        )
    return left == right


def _validate_score_links(
    entry: dict[str, Any],
    enrichments: dict[str, Any],
    profiles: dict[str, dict[str, Any]],
) -> None:
    """Check retained input correspondence, not score arithmetic or original capture truth."""
    cve_id = entry.get("cve_id")
    version = entry.get("cvss_version_used")
    if version not in (None, "3.1", "4.0"):
        raise ValueError("scores.cvss_version_used is unsupported")
    if cve_id is not None:
        _text(cve_id, "scores.cve_id")
        selected = next(
            (item for item in enrichments.get(entry["finding_id"], []) if item["cve_id"] == cve_id),
            None,
        )
        if selected is None:
            raise ValueError("scores.cve_id has no enrichment for its finding")
        for name in ("kev", "epss_percentile"):
            if name in entry and not _same_json(entry[name], selected.get(name)):
                raise ValueError(f"scores.{name} contradicts its selected enrichment")
        if version is not None:
            vector_key = "cvss31_vector" if version == "3.1" else "cvss40_vector"
            vector = selected.get(vector_key)
            if not isinstance(vector, str) or not vector.strip():
                raise ValueError("scores.cvss_version_used has no selected enrichment vector")
            if entry.get("base_vector") != vector:
                raise ValueError("scores.base_vector contradicts its selected enrichment")
    elif (
        version is not None or entry.get("kev") is True or entry.get("epss_percentile") is not None
    ):
        raise ValueError("scores intelligence assertions have no selected CVE")

    inputs = entry.get("inputs", {})
    for source, target in (
        ("role", "role"),
        ("exposure", "exposure"),
        ("manual", "manual"),
        ("observed_controls", "controls"),
    ):
        if source not in inputs:
            continue
        profile = profiles.get(entry["host_ip"])
        if profile is None:
            raise ValueError(f"scores.inputs.{source} has no profile for its host")
        expected = profile.get(target, {}) if target in ("controls", "manual") else profile[target]
        if not _same_json(inputs[source], expected):
            raise ValueError(f"scores.inputs.{source} contradicts its host profile")


def _validate_scores(
    scores: dict[str, dict[str, Any]],
    findings: dict[str, dict[str, Any]],
    enrichments: dict[str, Any],
    profiles: dict[str, dict[str, Any]],
) -> None:
    for finding_id, entry in scores.items():
        if finding_id not in findings:
            raise ConfigError("assessment snapshot contains a score without its finding")
        if entry.get("host_ip") != findings[finding_id]["host_ip"]:
            raise ValueError("scores.host_ip contradicts its finding")
        _number(entry.get("risk"), "scores.risk", 0, 100)
        if entry.get("band") not in ("Critical", "High", "Medium", "Low"):
            raise ValueError("scores.band is unsupported")
        _text(entry.get("weights_hash"), "scores.weights_hash")
        if "kev" in entry and type(entry["kev"]) is not bool:
            raise ValueError("scores.kev must be Boolean")
        for field in ("inputs", "env_modifications"):
            if field in entry:
                _object(entry[field], f"scores.{field}")
        for value in entry.get("env_modifications", {}).values():
            _text(value, "scores.env_modifications", nonblank=False)
        for field, maximum in (("base_score", 10), ("env_score", 10), ("epss_percentile", 1)):
            if field in entry and entry[field] is not None:
                _number(entry[field], f"scores.{field}", 0, maximum)
        if "threat_multiplier" in entry and entry["threat_multiplier"] is not None:
            value = entry["threat_multiplier"]
            if type(value) not in (int, float) or not 0 <= value < float("inf"):
                raise ValueError("scores.threat_multiplier must be finite and nonnegative or null")
        _optional_text(
            entry,
            (
                "cve_id",
                "cvss_version_used",
                "base_vector",
                "env_vector",
                "native_fallback",
                "reason",
                "fix",
            ),
            "scores",
        )
        _validate_score_links(entry, enrichments, profiles)


def _check_cvss_numbers(entry: dict[str, Any]) -> bool:
    """Check recorded v3.1 numbers with the existing implementation, not a new formula."""
    checked = False
    if entry.get("cvss_version_used") == "3.1":
        for field, vector_field, calculate in (
            ("base_score", "base_vector", cvss31.base_score),
            ("env_score", "env_vector", cvss31.environmental_score),
        ):
            value, vector = entry.get(field), entry.get(vector_field)
            if value is not None and vector:
                expected = calculate(cvss31.parse(vector))
                if not _same_json(value, expected):
                    raise ValueError(f"scores.{field} contradicts its retained {vector_field}")
                checked = True
    return checked


def _check_current_replay(entry: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    """Check supplied canonical fields, preserving missing metadata and narrative freedom."""
    missing = []
    for field in (
        "cve_id",
        "cvss_version_used",
        "base_vector",
        "base_score",
        "env_vector",
        "env_score",
        "env_modifications",
        "epss_percentile",
        "threat_multiplier",
        "kev",
        "native_fallback",
        "risk",
        "band",
        "weights_hash",
    ):
        if field not in entry:
            missing.append(field)
        else:
            actual_value, expected_value = entry[field], expected[field]
            if field in ("base_vector", "env_vector") and actual_value and expected_value:
                actual_value = cvss31.parse(actual_value)
                expected_value = cvss31.parse(expected_value)
            if not _same_json(actual_value, expected_value):
                raise ValueError(f"scores.{field} does not match deterministic replay")
    inputs = entry.get("inputs", {})
    for field in ("role", "exposure", "manual", "controls", "observed_controls", "context_policy"):
        if field not in inputs:
            missing.append(f"inputs.{field}")
        elif not _same_json(inputs[field], expected["inputs"][field]):
            raise ValueError(f"scores.inputs.{field} does not match deterministic replay")
    decisions = inputs.get("control_applicability")
    if decisions is None:
        missing.append("inputs.control_applicability")
    else:
        decisions = _object(decisions, "scores.inputs.control_applicability")
        for key, decision in expected["inputs"]["control_applicability"].items():
            if key not in decisions:
                missing.append(f"inputs.control_applicability.{key}")
                continue
            actual = _object(decisions[key], f"scores.inputs.control_applicability.{key}")
            for field, value in decision.items():
                if field == "limitation":
                    continue  # Narrative wording is not a canonical numerical input.
                if field not in actual:
                    missing.append(f"inputs.control_applicability.{key}.{field}")
                elif not _same_json(actual[field], value):
                    raise ValueError(
                        f"scores.inputs.control_applicability.{key}.{field} contradicts replay"
                    )
    return missing


def _score_arithmetic_summary(payload: dict[str, Any]) -> dict[str, Any]:
    """Read-only replay of supported retained state; caller validates structure first.

    This is reproduction by the current implementation, not independent CVSS
    conformance, historical-policy authentication, or evidence truth.
    """
    entries = payload["scores"]
    summary: dict[str, Any] = {
        "total": len(entries),
        "replayed": 0,
        "cvss_checked": 0,
        "unknown": [],
    }
    weights = payload["configuration"]["validated"].get("weights.yaml")
    digest = scoring.weights_hash(weights) if isinstance(weights, dict) else None
    profiles = {item["host_ip"]: item for item in payload["profiles"]}
    hosts = {item["ip"]: item for item in payload["hosts"]}
    findings = {item["id"]: item for item in payload["findings"]}
    for entry in entries:
        identifier = entry["finding_id"]
        try:
            if _check_cvss_numbers(entry):
                summary["cvss_checked"] += 1
            if digest is not None and entry["weights_hash"] == digest:
                expected_band = scoring.band(entry["risk"], weights)
                if entry["band"] != expected_band:
                    raise ValueError("scores.band contradicts risk under its retained weights")
            reason = None
            if entry.get("cvss_version_used") == "4.0":
                reason = "CVSS 4.0 arithmetic is not implemented by the retained v3.1 scorer"
            elif digest is None:
                reason = "retained weights.yaml is unavailable"
            elif entry["weights_hash"] != digest:
                reason = "the score's historical weights are not retained in this snapshot"
            elif entry.get("inputs", {}).get("context_policy") != POLICY_VERSION:
                reason = "the score's retained context policy is missing or unsupported"
            elif entry["host_ip"] not in profiles:
                reason = "the score's context profile is unavailable"
            elif "services" not in hosts[entry["host_ip"]]:
                reason = "the score's service observations were not retained"
            if reason is not None:
                summary["unknown"].append(f"{identifier}: score arithmetic NOT RUN: {reason}")
                continue
            finding = Finding.from_json(findings[identifier])
            candidates = [
                Enrichment.from_json(item) for item in payload["enrichments"].get(identifier, [])
            ]
            profile = ContextProfile.from_json(profiles[entry["host_ip"]])
            host = Host.from_json(hosts[entry["host_ip"]])
            expected = scoring.score(
                finding, scoring.best_enrichment(candidates), profile, host.services, weights
            ).to_json()
            missing = _check_current_replay(entry, expected)
            if missing:
                summary["unknown"].append(
                    f"{identifier}: score arithmetic NOT RUN: incomplete retained fields: {', '.join(missing)}"
                )
            else:
                summary["replayed"] += 1
        except (
            KeyError,
            ValueError,
            TypeError,
            AttributeError,
            ConfigError,
            IntelUnavailable,
        ) as error:
            raise ConfigError(
                f"assessment snapshot score {identifier!r} arithmetic replay: {error}"
            ) from error
    return summary


def _validate_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    _object(payload, "root")
    if (
        type(payload.get("schema_version")) is not int
        or payload["schema_version"] != SNAPSHOT_SCHEMA_VERSION
    ):
        raise ConfigError(
            f"assessment snapshot schema must be {SNAPSHOT_SCHEMA_VERSION}, got "
            f"{payload.get('schema_version')!r}"
        )
    claimed = payload.get("snapshot_hash")
    core = {key: value for key, value in payload.items() if key != "snapshot_hash"}
    computed = _digest(core)
    if claimed != computed:
        raise ConfigError(
            f"assessment snapshot hash mismatch: artifact says {claimed!r}, computed {computed!r}"
        )
    required = {
        "run",
        "configuration",
        "feed_snapshot",
        "hosts",
        "findings",
        "enrichments",
        "profiles",
        "scores",
        "rationales",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise ConfigError(f"assessment snapshot is missing key {missing[0]!r}")
    extra = set(payload) - (
        required
        | {
            "schema_version",
            "snapshot_hash",
            "evidence_status",
            "data_kind",
            "model_hash",
            "history",
            "limitations",
        }
    )
    if extra:
        raise ValueError(f"unknown root key {sorted(extra)[0]!r}")
    run = _object(payload["run"], "run")
    _text(run.get("run_id"), "run.run_id")
    _text(run.get("config_hash"), "run.config_hash")
    configuration = _object(payload["configuration"], "configuration")
    for key in ("hash_current", "hash_at_run_start"):
        _text(configuration.get(key), f"configuration.{key}")
    if configuration["hash_at_run_start"] != run["config_hash"]:
        raise ValueError("configuration.hash_at_run_start contradicts run.config_hash")
    drift = configuration.get("drift")
    if type(drift) is not bool or drift != (
        configuration["hash_current"] != configuration["hash_at_run_start"]
    ):
        raise ValueError("configuration.drift contradicts its declared hashes")
    _object(configuration.get("validated"), "configuration.validated")
    feeds = _object(payload["feed_snapshot"], "feed_snapshot")
    for name, value in feeds.items():
        meta = _object(value, f"feed_snapshot.{name}")
        _optional_text(meta, ("path", "sha256", "file_date"), "feed_snapshot")
        if "rows" in meta and meta["rows"] is not None:
            rows = meta["rows"]
            if type(rows) is not int or rows < 0:
                raise ValueError("feed_snapshot.rows must be a nonnegative integer or null")
    if "model_hash" in payload and payload["model_hash"] is not None:
        _text(payload["model_hash"], "model_hash")
    if "data_kind" in payload:
        _text(payload["data_kind"], "data_kind")
    if "evidence_status" in payload and payload["evidence_status"] not in (
        "VERIFIED",
        "NOT RUN",
        "TESTED WITH MOCKS",
        "MISSING",
    ):
        raise ValueError("evidence_status is unsupported")
    if "history" in payload:
        _object(payload["history"], "history")
    if "limitations" in payload:
        _strings(payload["limitations"], "limitations")
    hosts = _index(_records(payload["hosts"], "hosts"), "ip", "hosts")
    findings = _index(_records(payload["findings"], "findings"), "id", "findings")
    profiles = _index(_records(payload["profiles"], "profiles"), "host_ip", "profiles")
    scores = _index(_records(payload["scores"], "scores"), "finding_id", "scores")
    _validate_hosts(hosts)
    _validate_findings(findings, hosts)
    _validate_profiles(profiles, hosts)
    enrichments = _object(payload["enrichments"], "enrichments")
    _validate_enrichments(enrichments, findings)
    _validate_scores(scores, findings, enrichments, profiles)
    for finding_id, value in _object(payload["rationales"], "rationales").items():
        if finding_id not in findings:
            raise ValueError("rationales references a finding outside this snapshot")
        rationale = _object(value, "rationales")
        if rationale.get("finding_id") != finding_id:
            raise ValueError("rationales.finding_id contradicts its owner")
        _text(rationale.get("text"), "rationales.text")
        if rationale.get("source") not in ("llm", "template"):
            raise ValueError("rationales.source is unsupported")
        _optional_text(rationale, ("model",), "rationales")
        if "validation" in rationale:
            _object(rationale["validation"], "rationales.validation")
    _score_arithmetic_summary(payload)
    return payload


def validate_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate structure, links and supported score replay, never capture authenticity."""
    try:
        return _validate_snapshot(payload)
    except ConfigError:
        raise
    except (KeyError, ValueError, TypeError, AttributeError, RecursionError) as error:
        raise ConfigError(f"invalid assessment snapshot: {error}") from error


def save_snapshot(payload: dict[str, Any], path: str | Path) -> Path:
    validate_snapshot(payload)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(_canonical(payload) + "\n", encoding="utf-8")
    temporary.replace(path)
    return path


def load_snapshot(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    payload = load_json_payload(path, "assessment snapshot", max_bytes=MAX_SNAPSHOT_BYTES)
    if not isinstance(payload, dict):
        raise ConfigError(f"invalid assessment snapshot {path}: expected an object")
    try:
        return validate_snapshot(payload)
    except ConfigError as error:
        raise ConfigError(f"invalid assessment snapshot {path}: {error}") from error
