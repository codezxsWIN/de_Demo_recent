"""Operation-scoped facts for new network-policy findings, never host controls.

These narrow guards complement citation/semantic validation. They do not claim
general natural-language entailment or infer exploitability from a successful login.
"""

import re

from vulnassess.errors import LLMUnavailable
from vulnassess.network_triage import proof_category
from vulnassess.schema import Finding

DESCRIPTIONS = {
    ("ftp", "login"): (
        "An anonymous FTP login was accepted.",
        "No file listing or retrieval was tested.",
    ),
    ("ssh", "login"): (
        "SSH accepted the designated credential forbidden by the endpoint policy.",
        "No command, shell, forwarding or host compromise was tested.",
    ),
    ("smb", "file_read"): (
        "An anonymous SMB client read the owner-authorised proof file.",
        "This does not establish access to sensitive files or other shares.",
    ),
    ("mqtt", "login"): (
        "The MQTT broker accepted an anonymous connection.",
        "This alone does not establish publish or subscribe permission.",
    ),
    ("mqtt", "message_exchange"): (
        "An anonymous MQTT client completed a nonce publish/subscribe exchange on the owner-authorised topic.",
        "Other topics, device commands and device control were not tested.",
    ),
    ("snmp", "management_read"): (
        "An SNMP GET using the public community returned a management value.",
        "This is a default-community read, not proof of no authentication, write access or device control.",
    ),
    ("smb", "signing_optional"): (
        "SMB negotiation reported that signing is not required.",
        "Optional signing does not mean signing is disabled; no relay or tampering was demonstrated.",
    ),
    ("tls", "expired_certificate"): (
        "A TLS handshake returned an expired certificate.",
        "Issuer trust and hostname were not validated; TLS was not absent.",
    ),
}
SUBJECTS = {
    "ftp": r"\bftp\b",
    "ssh": r"\bssh\b",
    "smb": r"\bsmb\b|\bmicrosoft-ds\b",
    "mqtt": r"\bmqtt\b|\bbroker\b",
    "snmp": r"\bsnmp\b",
    "tls": r"\btls\b|\bssl\b|\bcertificate\b",
}
OPERATIONS = {
    "login": r"accept|login|credential|authenticat",
    "file_read": r"read|retriev|file|access",
    "message_exchange": r"publish|subscrib|message|exchange",
    "management_read": r"public|community|management|read|returned",
    "signing_optional": r"signing|optional|not.required",
    "expired_certificate": r"expir|validity",
}
PORTS = re.compile(r"\b(?:port\s+(\d{1,5})|(\d{1,5})/(?:tcp|udp))\b", re.I)
AUTH_ASSERTION = re.compile(
    r"\bunauthenticated\b|\b(?:no|without|lacks?)\s+auth(?:entication)?\b", re.I
)
GLOBAL = re.compile(
    r"\b(?:all|every|entire|other)\s+(?:\w+\s+)?(?:services?|ports?|endpoints?|hosts?|shares?|topics?|network)\b|host-wide|network-wide",
    re.I,
)


def observation(record):
    """Preserve exact target/protocol/policy binding before exposing a fact to AI."""
    if record.get("tool") != "service-network":
        return None
    try:
        finding = Finding.from_json(record)
        selected = proof_category(finding)
        if selected is None:
            return None
        category, digest = selected
        service = finding.tool_native_id.split(":")[1]
        statement, limit = DESCRIPTIONS[service, category]
        return {
            "service": service,
            "category": category,
            "port": finding.port,
            "transport": finding.protocol,
            "statement": statement,
            "limit": limit,
            "policy_sha256": digest,
        }
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def bindings(findings, evidence, *, prepared=False):
    result = []
    for finding in findings:
        fact = finding.get("protocol_observation") if prepared else None
        ids = {finding["evidence_id"]} if fact and finding.get("evidence_id") else set()
        if fact and prepared:
            fact = {**fact, "port": finding.get("port"), "transport": finding.get("protocol")}
        if fact is None:
            fact = observation(finding)
            if fact:
                ids = {
                    item["id"]
                    for item in evidence
                    if item.get("kind") == "service-network_finding"
                    and item.get("text") == finding.get("evidence")
                }
        if fact and ids:
            result.append({**fact, "evidence_ids": ids})
    return result


def _claim_text(result, path):
    try:
        value = result
        for part in path.split("."):
            value = value[int(part)] if isinstance(value, list) else value[part]
        return value if isinstance(value, str) else ""
    except (ValueError, TypeError, KeyError, IndexError):
        return ""


def supports_auth(text, result, facts):
    """Allow only the cited operation, with its named service and matching port."""
    if GLOBAL.search(text):
        return False
    ports = {int(a or b) for a, b in PORTS.findall(text)}
    cited = {
        identity
        for claim in result.get("claims", [])
        if _claim_text(result, claim.get("path", "")) == text
        for identity in claim.get("evidence_ids", [])
    }
    named = {service for service, pattern in SUBJECTS.items() if re.search(pattern, text, re.I)}
    for fact in facts:
        service, category = fact["service"], fact["category"]
        if (
            service not in {"ftp", "mqtt", "smb"}
            or named != {service}
            or not cited.intersection(fact["evidence_ids"])
            or (ports and ports != {fact["port"]})
        ):
            continue
        if service == "ftp" and category == "login" and re.search(r"\blogin\b", text, re.I):
            return not re.search(r"\bread|\bwrit|\bfiles?|\bcommands?", text, re.I)
        if service == "smb" and category == "file_read" and re.search(r"\bread|\bfile", text, re.I):
            return not re.search(r"\bwrit|\bcommands?|\bshell|\bsensitive", text, re.I)
        if service == "mqtt":
            if re.search(r"publish|subscrib|message.exchange", text, re.I):
                return category == "message_exchange" and not re.search(
                    r"device|commands?|other topics", text, re.I
                )
            return bool(re.search(r"\bconnect(?:ion)?\b", text, re.I))
    return False


def validate_interpretation(result, facts, *, require_summary=False):
    if not facts:
        return
    summary = result.get("summary", "")
    summary_citations = {
        identity
        for claim in result.get("claims", [])
        if claim.get("path") == "summary"
        for identity in claim.get("evidence_ids", [])
    }
    if require_summary and not any(
        claim.get("path") == "summary" and claim.get("label") == "observed"
        for claim in result.get("claims", [])
    ):
        raise LLMUnavailable(
            "Needs review: network policy interpretation must label its proven summary as observed"
        )
    # A useful observed-policy summary must describe its own cited operation,
    # rather than returning a generic unknown-controls sentence.
    if require_summary and not any(
        re.search(SUBJECTS[f["service"]], summary, re.I)
        and re.search(OPERATIONS[f["category"]], summary, re.I)
        and summary_citations.intersection(f["evidence_ids"])
        for f in facts
    ):
        raise LLMUnavailable(
            "Needs review: network policy interpretation must describe a cited protocol observation"
        )
    for claim in result.get("claims", []):
        if claim.get("label") not in {"observed", "inferred"}:
            continue
        text = _claim_text(result, claim.get("path", ""))
        cited = set(claim.get("evidence_ids", []))
        for fact in facts:
            if not cited.intersection(fact["evidence_ids"]) or not re.search(
                SUBJECTS[fact["service"]], text, re.I
            ):
                continue
            if fact["category"] == "signing_optional" and re.search(
                r"signing\s+(?:(?:is|was)\s+)?disabled|no\s+smb\s+signing|does\s+not\s+support\s+signing",
                text,
                re.I,
            ):
                raise LLMUnavailable(
                    "Needs review: network policy interpretation confuses optional signing with disabled signing"
                )
            if (
                fact["service"] in {"ftp", "mqtt", "smb"}
                and fact["category"] in {"login", "file_read", "message_exchange"}
                and re.search(
                    r"(?:authentication|control status)\s+(?:(?:is|was)\s+)?(?:unknown|not established)",
                    text,
                    re.I,
                )
            ):
                raise LLMUnavailable(
                    "Needs review: network policy interpretation ignores observed access; scope uncertainty to untested operations"
                )
