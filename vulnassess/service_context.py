"""Pure endpoint summaries for JSON service records; no host control inheritance."""

import re
from ipaddress import ip_address

__all__ = ["endpoint_context", "service_evidence_text"]

_FINGERPRINT_KEYS = ("name", "product", "version", "cpe", "fingerprint", "banner")
_HTTP_CHECKS = ("auth_required", "waf", "rate_limiting", "tls")
_DATABASE_CHECKS = (
    "network_acl", "auth_required", "bind_configuration", "service_privileges", "tls", "command_acl"
)
_HTTP = re.compile(r"\bhttps?\b|\bweb[ -]server\b", re.IGNORECASE)
_DATABASE = re.compile(
    r"\b(?:redis|mysql|mariadb|postgres(?:ql)?|mongodb|mssql|microsoft sql server)\b",
    re.IGNORECASE,
)
_ADMIN = re.compile(
    r"\b(?:weblogic|admin(?:istration|istrative)?|management)[\s_-]*"
    r"(?:console|interface|portal|server|panel)?\b",
    re.IGNORECASE,
)


def _text(value: object) -> str:
    return " ".join(value.split()) if isinstance(value, str) else ""


def _fingerprint(service: dict) -> str:
    return "; ".join(
        dict.fromkeys(filter(None, (_text(service.get(k)) for k in _FINGERPRINT_KEYS)))
    )


def _address_free(text: str, service: dict) -> str:
    # Retain fingerprint content without introducing endpoint addresses into prose.
    text = re.sub(r"\b[a-z][a-z0-9+.-]*://[^\s/;]+", "[address omitted]", text, flags=re.I)
    for key in ("ip", "host_ip", "address", "host", "hostname"):
        address = _text(service.get(key))
        if address:
            text = re.sub(re.escape(address), "[address omitted]", text, flags=re.I)

    def redact(match: re.Match) -> str:
        try:
            ip_address(match[0])
        except ValueError:
            return match[0]
        return "[address omitted]"

    return re.sub(r"(?<![\w:])[\da-fA-F:.]*[.:][\da-fA-F:.]+(?![\w:])", redact, text)


def _fact(value=None, *, scope="endpoint", source="", evidence="") -> dict:
    return {"value": value, "scope": scope, "source": source, "evidence": evidence}


def _tls(service: dict) -> dict:
    observed = service.get("tls") is True
    return _fact(
        True if observed else None,
        source=_text(service.get("tls_source")) or ("scanner TLS metadata" if observed else ""),
        evidence=_text(service.get("tls_evidence"))
        or ("tls=True" if observed else "not established"),
    )


def service_evidence_text(service: dict) -> str:
    """Return address-free port/protocol, TLS provenance, then fingerprint.

    Only the literal boolean ``tls=True`` establishes a TLS observation. Missing,
    false or malformed TLS flags remain unknown, regardless of port or service name.
    Optional string ``tls_source`` / ``tls_evidence`` annotate that observation;
    they do not independently establish TLS.
    """
    tls = _tls(service)
    status = "observed" if tls["value"] is True else "unknown"
    detail = tls["source"] if tls["value"] is True else "not established"
    parts = [f"{service.get('port', 'unknown')}/{_text(service.get('protocol')) or 'unknown'}"]
    parts.append(f"tls={status} ({detail})")
    fingerprint = _fingerprint(service)
    if fingerprint:
        parts.append(fingerprint)
    if _text(service.get("tls_source")) and tls["value"] is None:
        parts.append(f"tls_source={tls['source']}")
    if _text(service.get("tls_evidence")):
        parts.append(f"tls_evidence={tls['evidence']}")
    return _address_free("; ".join(parts), service)


def _control(service: dict, key: str) -> dict:
    controls = service.get("controls")
    record = controls.get(key) if isinstance(controls, dict) else None
    if not isinstance(record, dict):
        return _fact()
    value = record.get("value")
    valid_value = type(value) is bool or (key == "waf" and bool(_text(value)))
    evidence = _text(record.get("evidence"))
    source = _text(record.get("source"))
    if (
        not valid_value
        or not evidence
        or evidence.lower() in {"none observed", "unknown", "not established"}
        or not source
        or record.get("scope") != "endpoint"
        or type(service.get("port")) is not int
        or type(record.get("port")) is not int
        or record["port"] != service["port"]
        or not _text(service.get("protocol"))
        or record.get("protocol") != service.get("protocol")
    ):
        return _fact()
    return _fact(value, source=source, evidence=evidence)


def _protocol_controls(service: dict, fingerprint: str) -> tuple[dict, dict, list]:
    # Explicit application names take precedence over incidental banner content.
    application = "; ".join(_text(service.get(key)) for key in ("name", "protocol"))
    if _HTTP.search(application):
        family = "http"
    elif _DATABASE.search(application):
        family = "database"
    elif _HTTP.search(fingerprint):
        family = "http"
    elif _DATABASE.search(fingerprint):
        family = "database"
    else:
        family = "unknown"

    checks = {"http": _HTTP_CHECKS, "database": _DATABASE_CHECKS}.get(family, ())
    controls = {
        "tls": _tls(service),
        **{key: _control(service, key) for key in _HTTP_CHECKS if key != "tls"},
    }
    if family == "database":
        controls.update({key: _control(service, key) for key in checks if key not in controls})
    relevance = {}
    for key in controls:
        if family == "database" and key in ("waf", "rate_limiting"):
            reason = "HTTP control does not apply to a native database protocol."
            controls[key] = {**_fact(scope="not_applicable"), "reason": reason}
            relevance[key] = {
                "value": False, "scope": "not_applicable", "reason": reason
            }
        else:
            relevance[key] = {
                "value": True if key in checks else None,
                "scope": "endpoint",
                "reason": (
                    "Relevant to the identified application protocol."
                    if key in checks else "Application protocol is unknown."
                ),
            }
    return controls, relevance, list(checks)


def endpoint_context(service: dict, host_context: dict | None = None) -> dict:
    """Return port, protocol, role_candidate, host_role, controls and exposure.

    Facts are plain JSON dictionaries with value/scope/source/evidence; unknown
    values are None. TLS is True or None, never False. Other controls may include
    explicit negative observations. To supply one, use service['controls'][key]
    with value, source, nonempty evidence, scope='endpoint', and an exact matching
    port/protocol. Host controls are never consulted.

    control_relevance describes protocol applicability independently of observed
    control values. Native databases retain HTTP control keys with scope
    'not_applicable' and a reason. relevant_checks lists protocol-specific checks;
    unidentified protocols have no established checklist and unknown relevance.

    Host role is retained separately from fingerprint-derived endpoint candidates.
    Exposure is host context, not endpoint reachability: its origin is 'host', or
    'scope' when the supplied exposure explicitly declares scope/origin='scope'.
    Without host exposure its value is None and origin is 'unknown'.
    """
    host = host_context if host_context is not None else {}
    role = host.get("role")
    host_role = _text(role.get("value") if isinstance(role, dict) else role) or None
    fingerprint = _fingerprint(service)
    candidate = "unknown"
    if _ADMIN.search(fingerprint):
        candidate = "management_interface"
    elif _DATABASE.search(fingerprint):
        candidate = "database"
    elif _HTTP.search(fingerprint):
        candidate = "web_frontend"

    controls, control_relevance, relevant_checks = _protocol_controls(service, fingerprint)
    exposure = host.get("exposure")
    record = exposure if isinstance(exposure, dict) else {"value": exposure}
    value = _text(record.get("value")) or None
    origin = "unknown" if value is None else "host"
    if value is not None and (record.get("scope") == "scope" or record.get("origin") == "scope"):
        origin = "scope"
    exposure_fact = _fact(
        value,
        scope=origin,
        source=_text(record.get("source")),
        evidence=_text(record.get("evidence")),
    )
    exposure_fact["origin"] = origin
    return {
        "port": service.get("port"),
        "protocol": _text(service.get("protocol")) or None,
        "role_candidate": candidate,
        "host_role": host_role,
        "controls": controls,
        "control_relevance": control_relevance,
        "relevant_checks": relevant_checks,
        "exposure": exposure_fact,
    }
