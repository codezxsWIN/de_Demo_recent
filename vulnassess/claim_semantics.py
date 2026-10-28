"""Narrow evidence checks for TLS, redirects, topology, and procedural labels.

Call after the structural/quotation checks in ai_boundary.verify_claims.
This is a deterministic guard for known assertion families, not a general
entailment checker. Only cited evidence text supplies protocol observations;
service booleans, port conventions, and claim quotations cannot supply them.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Iterator

from vulnassess.errors import LLMUnavailable


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


_PROCEDURAL_PATH = _rx(
    r"^(?:recommended_actions\.\d+\.action|"
    r"investigations\.\d+\.(?:verification|alternative)|uncertainties\.\d+)$"
)
_TLS = r"(?:tls|ssl)(?:/tls|/ssl)?"
_TLS_ASSERTION = _rx(
    rf"\b{_TLS}\s*=\s*(?:true|false|1|0)\b|"
    rf"\b{_TLS}(?:\s+(?:is|are|was|were|has been))?\s+(?:not\s+)?"
    r"(?:enabled|disabled|configured|absent|present|active|observed|supported)\b|"
    rf"\b{_TLS}[- ](?:enabled|protected|secured)\b|"
    rf"\b(?:no|without|lacks?|lacking)\s+{_TLS}\b|"
    rf"\b(?:uses?|supports?|provides?)\s+{_TLS}\b|"
    r"\b(?:un)?encrypted\s+transport\b|"
    r"\btransport\s+(?:is\s+)?(?:un)?encrypted\b"
)
_TLS_NEGATIVE = _rx(
    r"=\s*(?:false|0)\b|\b(?:not|no|without|lacks?|lacking|disabled|absent|unencrypted)\b"
)
_PRESUPPOSED_TLS = _rx(
    r"=\s*(?:true|false|1|0)\b|(?:tls|ssl)-(?:enabled|protected|secured)\b|"
    r"(?:tls|ssl) (?:enabled|protected|secured)\s+(?:ports|services|listeners|endpoints)\b"
)
_TLS_POSITIVE_OBSERVATION = _rx(
    r"\btunnel\s*=\s*['\"]?ssl\b|\btls\s*=\s*['\"]?observed\b|"
    r"\b(?:tls|ssl)(?:v?\d(?:\.\d)?)?\s+handshake\s*(?:[:=]\s*)?"
    r"(?:succeeded|successful|completed|negotiated)\b|"
    r"\bnegotiated\s+(?:tls|ssl)v?\d(?:\.\d)?\b"
)
_TLS_NEGATIVE_OBSERVATION = _rx(
    r"\btls[_ -](?:test|probe)(?:[_ -]result)?\s*[:=]\s*"
    r"(?:negative|unsupported|not[_ -]supported|no[_ -]tls)\b|"
    r"\b(?:tls|ssl)\s+(?:test|probe)\s+(?:confirmed|established)\s+"
    r"(?:no\s+(?:tls|ssl)|(?:tls|ssl)\s+(?:is\s+)?(?:disabled|unsupported))\b"
)
_REDIRECT = _rx(r"\bredirect(?:s|ed|ing|ion)?\b")
_TOPOLOGY = _rx(
    r"\breverse[- ]prox(?:y|ies|ying)\b|\bprox(?:ies|ying)\s+(?:to|for)\b|"
    r"\b(?:fronts|in\s+front\s+of|behind)\b|\bbypass(?:es|ed|ing)?\b"
)
_QUESTION = _rx(
    r"\b(?:whether|if)\b|^\s*(?:does?|is|are|can|could|would|might|has|have)\b|"
    r"\b(?:verify|check|test|determine|investigate|confirm)\b"
)
_UNKNOWN_BEFORE = _rx(
    r"(?:\b(?:unknown|unverified|not established|not determined)\s*[:,-]?\s*|"
    r"\b(?:no|without|lacks?)\s+(?:confirmed\s+)?(?:evidence|confirmation)\s+(?:of|that)\s*)$"
)
_UNKNOWN_AFTER = _rx(
    r"^\s*(?:(?:configuration|status|observation|handshake)\s+)?"
    r"(?:evidence\b|(?:is\s+|are\s+|remains?\s+)?"
    r"(?:unknown|unverified|not\s+(?:established|confirmed|determined|observed))\b)"
)
_PORT_LIST = r"\d{1,5}(?:(?:\s*[,/]\s*|\s+(?:and|or)\s+)\d{1,5})*"
_PORT = _rx(
    rf"\bports?(?:id)?\s*[:=]?\s*(?P<list>{_PORT_LIST})\b|"
    r"\b(?P<first>\d{1,5})/(?:tcp|udp)\b|"
    r"\b(?:tcp|udp)[/ ](?P<last>\d{1,5})\b|"
    r"https?://[^\s/:]+:(?P<url>\d{1,5})\b|"
    r"^\s*(?P<row>\d{1,5})\s+(?:tcp|udp)\b"
)
_SENTENCE = _rx(r"(?<=[.!?;])\s+|\n+|\s*[,;]?\s+\b(?:but|however|whereas|while)\b\s*")
_EVIDENCE_UNIT = _rx(r"[\n;]+\s*(?=(?:ports?\s*[:=]?\s*\d|\d{1,5}(?:/|\s+)(?:tcp|udp)))")
_STATUS = _rx(r"\bHTTP/\d(?:\.\d)?\s+(\d{3})\b|\bstatus(?:[_ -]code)?\s*[:=]\s*(\d{3})\b")
_LOCATION = _rx(r"\blocation\s*[:=]\s*['\"]?([^\s'\"<>]+)")
_NON_OBSERVATION_KIND = _rx(
    r"(?:policy|baseline|intelligence|recommendation|hypothesis|probe_option|scan_plan)"
)
_SERVER_TLS_FIELD = _rx(r"^\s*tls\s*=\s*(observed|unknown)(?=\s*(?:\(|;|$))")
_LEGACY_FINGERPRINT_END = _rx(r"[;\n<]|\bbanner\b|\bfingerprint\s*[:=]")


def _normalise(text: str) -> str:
    return unicodedata.normalize("NFKC", text).replace("\u2011", "-").casefold()


def _port_groups(text: str) -> list[tuple[int, int, set[int]]]:
    return [
        (
            match.start(),
            match.end(),
            {int(n) for n in re.findall(r"\d+", match.group(match.lastgroup or 0))},
        )
        for match in _PORT.finditer(text)
    ]


def _ports(text: str) -> set[int]:
    return {port for _, _, ports in _port_groups(text) for port in ports}


def _assertion_ports(text: str, match: re.Match[str], count: int) -> set[int]:
    groups = _port_groups(text)
    if count == 1:
        return {port for _, _, ports in groups for port in ports}
    # Separate assertions in one sentence may describe different listeners.
    # An explicit "on port ..." after the assertion takes precedence.
    for start, _, ports in groups:
        if start >= match.end() and re.fullmatch(r"\s+(?:on|for|at)\s+", text[match.end() : start]):
            return ports
    if not groups:
        return set()
    return min(
        groups,
        key=lambda group: max(group[0] - match.end(), match.start() - group[1], 0),
    )[2]


def _nonfactual(text: str, match: re.Match[str], *, presupposed: bool = False) -> bool:
    before, after = text[: match.start()], text[match.end() :]
    if _UNKNOWN_BEFORE.search(before) or _UNKNOWN_AFTER.search(after):
        return True
    # Do not let the question at the beginning excuse a later factual clause.
    # "TLS=false" and "TLS-enabled ports" in questions are presuppositions.
    if presupposed:
        return False
    local_before = re.split(r",|\band\b|\bbecause\b|\bsince\b|\bgiven\b", before)[-1]
    return bool(_QUESTION.search(local_before))


def _units(item: dict) -> Iterator[str]:
    if _NON_OBSERVATION_KIND.search(str(item.get("kind", ""))):
        return
    if item.get("kind") == "harbordesk_finding":
        try:
            proof = json.loads(item["text"])
        except (ValueError, TypeError):
            return
        if not isinstance(proof, dict) or proof.get("observed_intentional_weakness") is not True:
            return
        data = proof.get("evidence")
        if not isinstance(data, dict) or "check_error" in data:
            return
        if (
            proof.get("id") == "HD-14"
            and data.get("protocol") == "FTP"
            and data.get("tls_negotiated") is False
        ):
            yield "2121/tcp tls_test=negative"
        if (
            proof.get("id") == "HD-20"
            and data.get("request_scheme") == "http"
            and data.get("tls_negotiated") is False
        ):
            yield "8787/tcp tls_test=negative"
        if proof.get("id") in ("HD-15", "HD-16") and data.get("tls_version") in (
            "TLSv1.2",
            "TLSv1.3",
        ):
            yield f"8443/tcp negotiated {data['tls_version']}"
        return
    text = _normalise(item["text"])
    if item.get("kind") in {"nmap_service", "observed_service"}:
        # One service evidence ID describes one leading listener. The server
        # projection is "port/protocol; tls=STATE (source); FINGERPRINT".
        # Source annotations and all later fingerprint/banner text are untrusted
        # and must never supply another TLS state or another listener.
        heading = _PORT.match(text)
        if heading is None:
            return
        tail = text[heading.end() :].lstrip()
        if tail.startswith(";"):
            marker = _SERVER_TLS_FIELD.match(tail[1:])
            if marker is not None:
                yield f"{heading[0]}; tls={marker[1]}"
            return
        # Legacy simple tunnel records remain usable before any fingerprint
        # boundary, but do not recover observations from later arbitrary text.
        head = _LEGACY_FINGERPRINT_END.split(text, maxsplit=1)[0]
        first_marker = _rx(r"\btls\s*=\s*(\w+)").search(head)
        if first_marker and first_marker[1] != "observed":
            return
        if len(_port_groups(head)) == 1:
            yield head
        return
    yield from _EVIDENCE_UNIT.split(text)


def _tls_support(cited: list[dict], negative: bool) -> tuple[bool, set[int]]:
    pattern = _TLS_NEGATIVE_OBSERVATION if negative else _TLS_POSITIVE_OBSERVATION
    found, ports = False, set()
    for item in cited:
        for unit in _units(item):
            matches = list(pattern.finditer(unit))
            for match in matches:
                if _nonfactual(unit, match) or re.search(
                    r"\b(?:not|no|without)\s*$", unit[: match.start()]
                ):
                    continue
                found = True
                ports.update(_assertion_ports(unit, match, max(2, len(matches))))
    return found, ports


def _reject(path: str, assertion: str, ports: set[int] | None = None) -> None:
    detail = f" for ports {', '.join(map(str, sorted(ports)))}" if ports else ""
    raise LLMUnavailable(f"Needs review: unsupported {assertion}{detail} at {path}")


def _verify_tls(text: str, path: str, cited: list[dict]) -> None:
    for clause in _SENTENCE.split(text):
        assertions = list(_TLS_ASSERTION.finditer(clause))
        for match in assertions:
            if _nonfactual(clause, match, presupposed=bool(_PRESUPPOSED_TLS.search(match[0]))):
                continue
            negative = bool(_TLS_NEGATIVE.search(match[0]))
            found, supported_ports = _tls_support(cited, negative)
            ports = _assertion_ports(clause, match, len(assertions))
            if not found or ports - supported_ports:
                _reject(
                    path,
                    "negative TLS assertion" if negative else "TLS assertion",
                    ports - supported_ports,
                )


def _redirect_support(cited: list[dict]) -> list[tuple[set[int], str | None]]:
    observations = []
    for item in cited:
        for unit in _units(item):
            statuses = [int(m[1] or m[2]) for m in _STATUS.finditer(unit)]
            location = _LOCATION.search(unit)
            # Location alone is useful when the status was not retained. A 200
            # or 201 with a Location header is not a redirect observation.
            if any(status in {301, 302, 303, 307, 308} for status in statuses) or (
                location and not statuses
            ):
                # Destination URL ports do not describe the responding listener.
                source = unit[: location.start()] if location else unit
                observations.append((_ports(source), location[1] if location else None))
    return observations


def _verify_redirects(text: str, path: str, cited: list[dict]) -> None:
    observations = _redirect_support(cited)
    for clause in _SENTENCE.split(text):
        for match in _REDIRECT.finditer(clause):
            if _nonfactual(clause, match):
                continue
            if re.search(r"\b(?:no|not|never|without)\s*$", clause[: match.start()]):
                _reject(path, "negative HTTP redirect assertion")
            destination = _rx(r"\bto\s+(https?://[^\s,;?]+|https?\b)").search(clause[match.end() :])
            source = clause[: match.end()]
            on_port = _rx(r"^\s+on\s+(port\s*\d+)").search(clause[match.end() :])
            ports = _ports(source + (on_port[0] if on_port else ""))
            eligible = [
                (observed_ports, location)
                for observed_ports, location in observations
                if not destination
                or (
                    location
                    and (
                        location.rstrip("./") == destination[1].rstrip("./")
                        or location.startswith(destination[1] + "://")
                    )
                )
            ]
            supported_ports = {port for observed_ports, _ in eligible for port in observed_ports}
            if not eligible or ports - supported_ports:
                _reject(path, "HTTP redirect assertion", ports - supported_ports)


def _fixture_application_bypass(clause: str, match: re.Match[str], cited: list[dict]) -> bool:
    """A reproduced fixture login/object failure does not assert proxy topology."""
    domain = r"(?:authentication|login|password|(?:object[- ](?:level[- ])?)?authorization|object[- ]ownership|access[- ]control)"
    phrases = _rx(
        rf"{domain}\s+bypass(?:es|ed|ing)?\b|\bbypass(?:es|ed|ing)?\s+(?:the\s+)?{domain}\b"
    )
    phrase = next(
        (
            item[0]
            for item in phrases.finditer(clause)
            if item.start() <= match.start() < item.end()
        ),
        None,
    )
    if phrase is None:
        return False
    for item in cited:
        if item.get("kind") != "harbordesk_finding":
            continue
        try:
            proof = json.loads(item["text"])
        except (ValueError, TypeError):
            continue
        if not isinstance(proof, dict) or proof.get("observed_intentional_weakness") is not True:
            continue
        evidence = proof.get("evidence")
        if not isinstance(evidence, dict) or "check_error" in evidence:
            continue
        if proof.get("id") == "HD-03" and not _rx("object|authorization|access.control").search(
            phrase
        ):
            if (
                evidence.get("normal_wrong_password_status") == 401
                and evidence.get("injected_fixture_login_status") == 200
            ):
                return True
        if proof.get("id") in ("HD-04", "HD-09", "HD-10") and _rx(
            "object|authorization|access.control"
        ).search(phrase):
            if (
                evidence.get("signed_in_fixture") == "demo"
                and evidence.get("returned_order_owner") == "other-demo"
            ) or (
                evidence.get("authenticated_fixture") == "demo"
                and evidence.get("returned_owner") == "other-demo"
                and evidence.get("status") == 200
            ):
                return True
        if proof.get("id") == "HD-18" and _rx("authorization|access.control").search(phrase):
            if (
                evidence.get("baseline_admin_status") == 403
                and evidence.get("role_assignment_status") == 200
                and evidence.get("elevated_role") == "admin"
                and evidence.get("elevated_admin_status") == 200
            ):
                return True
    return False


def _verify_topology(text: str, path: str, label: str, cited: list[dict]) -> None:
    for clause in _SENTENCE.split(text):
        for match in _TOPOLOGY.finditer(clause):
            if _nonfactual(clause, match):
                continue
            if (
                label == "hypothesis"
                and path.endswith(".hypothesis")
                and _rx(r"\b(?:may|might|could|possibly)\b").search(clause[: match.start()])
            ):
                continue
            bypass = match[0].startswith("bypass")
            if bypass and _fixture_application_bypass(clause, match, cited):
                continue
            marker = _rx(
                r"\bbypass\s*=\s*(?:observed|confirmed)\b"
                if bypass
                else r"\breverse[_ -]proxy\s*=\s*(?:observed|confirmed)\b|\bproxy_pass\s+https?://"
            )
            # Fingerprint cooccurrence and host context do not establish routing.
            supported = any(
                _rx(r"(?:topology|proxy|routing|bypass|configuration|trace)").search(
                    item.get("kind", "")
                )
                and not item.get("kind", "").startswith("context_")
                and any(
                    not _nonfactual(unit, m) for unit in _units(item) for m in marker.finditer(unit)
                )
                for item in cited
            )
            if not supported:
                _reject(path, "bypass topology" if bypass else "reverse-proxy topology")


def verify_semantic_claims(
    claims: list[dict], evidence: list[dict], claim_text: dict[str, str]
) -> None:
    """Raise LLMUnavailable for targeted unsupported assertions; otherwise return None.

    Labels do not exempt facts embedded in questions or hypotheses. Procedural
    and uncertainty fields cannot carry the observed label. Authentication
    possibilities are deliberately outside this guard's assertion families.
    Metadata and quote validation remain the existing boundary's responsibility.
    """
    by_id = {}
    for item in evidence:
        identity = item["id"]
        if identity in by_id:
            raise LLMUnavailable("Needs review: duplicate semantic evidence ID")
        by_id[identity] = item
    for claim in claims:
        path, label = claim["path"], claim["label"]
        if label == "observed" and _PROCEDURAL_PATH.fullmatch(path):
            raise LLMUnavailable(
                f"Needs review: observed label on procedural/uncertainty field at {path}"
            )
        if path not in claim_text or not isinstance(claim_text[path], str):
            raise LLMUnavailable(f"Needs review: missing semantic claim text at {path}")
        identities = claim["evidence_ids"]
        if any(identity not in by_id for identity in identities):
            raise LLMUnavailable(f"Needs review: unknown semantic evidence citation at {path}")
        cited = [by_id[identity] for identity in identities]
        text = _normalise(claim_text[path])
        if any(item.get("kind") == "nvd-cpe_finding" for item in cited):
            assertion = _rx(
                r"\b(?:confirmed|proven|definitively)\b|\bvulnerable\s+to\b|\b(?:remote code execution|host compromise)\s+(?:was\s+)?(?:achieved|demonstrated)\b"
            )
            for sentence in _SENTENCE.split(text):
                for match in assertion.finditer(sentence):
                    modal_candidate = match.group(0).startswith("vulnerable") and _rx(
                        r"\b(?:may|might|could|possibly|potentially)\b(?:(?!\b(?:but|and|because|however)\b).){0,40}$"
                    ).search(sentence[: match.start()])
                    if (
                        not _nonfactual(sentence, match)
                        and not _rx(r"\b(?:not|unconfirmed|unverified|unknown)\s*$").search(
                            sentence[: match.start()]
                        )
                        and not modal_candidate
                    ):
                        raise LLMUnavailable(
                            f"Needs review: product-version CVE asserted as confirmed at {path}"
                        )
        if (
            "cve-2022-0543" in text
            and not _rx(
                r"\b(?:candidate|associated with|consistent with|package-dependent|unconfirmed|not confirmed)\b"
            ).search(text)
            and _rx(
                r"\b(?:confirmed|proven|definitively)\b|\b(?:exposes|has|vulnerable to)\s+cve-2022-0543\b"
            ).search(text)
        ):
            raise LLMUnavailable(
                f"Needs review: package-dependent CVE asserted as confirmed at {path}"
            )
        if path.endswith(".alternative") and _rx(
            r"^\s*(?:restrict|install|patch|upgrade|update|disable|enable|configure|enforce|remove|apply)\b"
        ).search(text):
            raise LLMUnavailable(f"Needs review: investigation alternative is an action at {path}")
        _verify_tls(text, path, cited)
        _verify_redirects(text, path, cited)
        _verify_topology(text, path, label, cited)
