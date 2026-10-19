"""The canonical data model. Frozen dataclasses with JSON in/out, no third-party types."""

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, cast
from uuid import NAMESPACE_URL, uuid5

EVIDENCE_MAX = 2048
TRUNCATION_MARKER = "\u2026[truncated]"
SOURCES = ("rule", "model", "llm", "manual")
EXPOSURES = ("internal", "internet_facing")


def _json_number(value: Any, name: str, minimum: float, maximum: float) -> float:
    """Validate the declared JSON type before the legacy numeric normalisation."""
    if type(value) not in (int, float) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be a finite number in [{minimum}, {maximum}]")
    return float(value)


def _json_bool(data: dict[str, Any], name: str) -> bool:
    value = data.get(name, False)
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean when supplied")
    return value


def _json_array(data: dict[str, Any], name: str) -> list[Any]:
    value = data.get(name, [])
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a JSON array when supplied")
    return cast(list[Any], value)


def _json_object(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object with string keys when supplied")
    mapping = cast(dict[object, Any], value)
    if any(not isinstance(key, str) for key in mapping):
        raise ValueError(f"{name} must be a JSON object with string keys when supplied")
    return cast(dict[str, Any], dict(mapping))


def cap_evidence(text: str) -> str:
    """Keep the first EVIDENCE_MAX verbatim characters and say so when the rest was cut."""
    if len(text) <= EVIDENCE_MAX:
        return text
    return text[:EVIDENCE_MAX] + TRUNCATION_MARKER


@dataclass(frozen=True)
class Provenance:
    tool: str
    raw_path: str
    record_index: int
    run_id: str

    def to_json(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "raw_path": self.raw_path,
            "record_index": self.record_index,
            "run_id": self.run_id,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Provenance":
        index = data["record_index"]
        if type(index) is not int or index < 0:
            raise ValueError("record_index must be a nonnegative integer")
        return cls(
            tool=data["tool"],
            raw_path=data["raw_path"],
            record_index=index,
            run_id=data["run_id"],
        )


@dataclass(frozen=True)
class Service:
    port: int
    protocol: str
    name: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    banner: str | None = None
    tls: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "name": self.name,
            "product": self.product,
            "version": self.version,
            "cpe": self.cpe,
            "banner": self.banner,
            "tls": self.tls,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Service":
        port = data["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("port must be an integer in [1, 65535]")
        if "tls" in data and type(data["tls"]) is not bool:
            raise ValueError("Service.tls must be a boolean when supplied")
        return cls(
            port=port,
            protocol=data["protocol"],
            name=data.get("name"),
            product=data.get("product"),
            version=data.get("version"),
            cpe=data.get("cpe"),
            banner=data.get("banner"),
            tls=data.get("tls", False),
        )


@dataclass(frozen=True)
class Host:
    ip: str
    hostname: str | None = None
    os_guess: str | None = None
    services: tuple[Service, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "os_guess": self.os_guess,
            "services": [service.to_json() for service in self.services],
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Host":
        return cls(
            ip=data["ip"],
            hostname=data.get("hostname"),
            os_guess=data.get("os_guess"),
            services=tuple(Service.from_json(item) for item in data.get("services", [])),
        )


@dataclass(frozen=True)
class Finding:
    id: str
    host_ip: str
    tool: str
    tool_native_id: str
    title: str
    description: str
    evidence: str
    provenance: Provenance
    port: int | None = None
    protocol: str | None = None
    url: str | None = None
    cve_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    reference_urls: tuple[str, ...] = ()
    native_severity: str | None = None
    native_confidence: str | None = None
    first_seen: str = ""
    last_seen: str = ""

    def __post_init__(self) -> None:
        if not self.evidence or not self.evidence.strip():
            raise ValueError("Finding.evidence must not be empty")

    @staticmethod
    def fingerprint(
        host_ip: str,
        port: int | None,
        protocol: str | None,
        tool: str,
        tool_native_id: str,
        url: str | None,
    ) -> str:
        parts = [host_ip, str(port or ""), protocol or "", tool, tool_native_id, url or ""]
        return sha256("|".join(parts).encode("utf-8")).hexdigest()

    @classmethod
    def make(cls, **fields: Any) -> "Finding":
        """Cap evidence, freeze sequences and derive the identity from the fingerprint."""
        fields["evidence"] = cap_evidence(str(fields.get("evidence") or ""))
        for key in ("cve_ids", "cwe_ids", "reference_urls"):
            fields[key] = tuple(fields.get(key) or ())
        fingerprint = cls.fingerprint(
            fields["host_ip"],
            fields.get("port"),
            fields.get("protocol"),
            fields["tool"],
            fields["tool_native_id"],
            fields.get("url"),
        )
        fields["id"] = str(uuid5(NAMESPACE_URL, fingerprint))
        return cls(**fields)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_ip": self.host_ip,
            "port": self.port,
            "protocol": self.protocol,
            "url": self.url,
            "tool": self.tool,
            "tool_native_id": self.tool_native_id,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "cve_ids": list(self.cve_ids),
            "cwe_ids": list(self.cwe_ids),
            "reference_urls": list(self.reference_urls),
            "native_severity": self.native_severity,
            "native_confidence": self.native_confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "provenance": self.provenance.to_json(),
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Finding":
        return cls(
            id=data["id"],
            host_ip=data["host_ip"],
            port=data.get("port"),
            protocol=data.get("protocol"),
            url=data.get("url"),
            tool=data["tool"],
            tool_native_id=data["tool_native_id"],
            title=data["title"],
            description=data.get("description", ""),
            evidence=data["evidence"],
            cve_ids=tuple(_json_array(data, "cve_ids")),
            cwe_ids=tuple(_json_array(data, "cwe_ids")),
            reference_urls=tuple(_json_array(data, "reference_urls")),
            native_severity=data.get("native_severity"),
            native_confidence=data.get("native_confidence"),
            first_seen=data.get("first_seen", ""),
            last_seen=data.get("last_seen", ""),
            provenance=Provenance.from_json(data["provenance"]),
        )


@dataclass(frozen=True)
class Feature:
    """One inferred fact: what, how sure, from where, and the words that justify it."""

    value: Any
    confidence: float
    source: str
    evidence: str

    def __post_init__(self) -> None:
        # type() rather than isinstance(): bool is an int subclass and must be rejected
        if type(self.confidence) not in (int, float):
            raise ValueError("Feature.confidence must be a number in [0, 1]")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError(f"Feature.confidence {self.confidence} is outside [0, 1]")
        if self.source not in SOURCES:
            raise ValueError(f"Feature.source must be one of {SOURCES}, got {self.source!r}")
        if not self.evidence or not self.evidence.strip():
            raise ValueError("Feature.evidence must not be empty; use 'none observed' for absence")

    def to_json(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "confidence": self.confidence,
            "source": self.source,
            "evidence": self.evidence,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Feature":
        return cls(
            value=data["value"],
            confidence=_json_number(data["confidence"], "confidence", 0, 1),
            source=data["source"],
            evidence=data["evidence"],
        )


@dataclass
class ContextProfile:
    host_ip: str
    role: Feature
    exposure: Feature
    segment: str | None = None
    controls: dict[str, Feature] = field(default_factory=dict[str, Feature])
    manual: dict[str, Feature] = field(default_factory=dict[str, Feature])

    def to_json(self) -> dict[str, Any]:
        return {
            "host_ip": self.host_ip,
            "role": self.role.to_json(),
            "exposure": self.exposure.to_json(),
            "segment": self.segment,
            "controls": {key: value.to_json() for key, value in self.controls.items()},
            "manual": {key: value.to_json() for key, value in self.manual.items()},
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "ContextProfile":
        return cls(
            host_ip=data["host_ip"],
            role=Feature.from_json(data["role"]),
            exposure=Feature.from_json(data["exposure"]),
            segment=data.get("segment"),
            controls={
                key: Feature.from_json(value) for key, value in data.get("controls", {}).items()
            },
            manual={key: Feature.from_json(value) for key, value in data.get("manual", {}).items()},
        )


@dataclass(frozen=True)
class Enrichment:
    finding_id: str
    cve_id: str
    match_method: str
    match_confidence: float
    cvss31_vector: str | None = None
    cvss31_base: float | None = None
    cvss40_vector: str | None = None
    cvss40_base: float | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_date_added: str | None = None
    patch_references: tuple[str, ...] = ()
    description: str = ""
    version_end: str | None = None
    feed_dates: dict[str, str] = field(default_factory=dict[str, str])
    # None also covers legacy records whose boundary semantics were not retained.
    version_end_inclusive: bool | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "cve_id": self.cve_id,
            "match_method": self.match_method,
            "match_confidence": self.match_confidence,
            "cvss31_vector": self.cvss31_vector,
            "cvss31_base": self.cvss31_base,
            "cvss40_vector": self.cvss40_vector,
            "cvss40_base": self.cvss40_base,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "kev": self.kev,
            "kev_date_added": self.kev_date_added,
            "patch_references": list(self.patch_references),
            "description": self.description,
            "version_end": self.version_end,
            "version_end_inclusive": self.version_end_inclusive,
            "feed_dates": dict(self.feed_dates),
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Enrichment":
        inclusive = data.get("version_end_inclusive")
        return cls(
            finding_id=data["finding_id"],
            cve_id=data["cve_id"],
            match_method=data["match_method"],
            match_confidence=_json_number(data["match_confidence"], "match_confidence", 0, 1),
            cvss31_vector=data.get("cvss31_vector"),
            cvss31_base=data.get("cvss31_base"),
            cvss40_vector=data.get("cvss40_vector"),
            cvss40_base=data.get("cvss40_base"),
            epss=data.get("epss"),
            epss_percentile=data.get("epss_percentile"),
            kev=_json_bool(data, "kev"),
            kev_date_added=data.get("kev_date_added"),
            patch_references=tuple(_json_array(data, "patch_references")),
            description=data.get("description", ""),
            version_end=data.get("version_end"),
            # Legacy range metadata stays unknown, never truthiness-coerced into
            # an inclusive/exclusive or vendor-fixed-release assertion.
            version_end_inclusive=inclusive if type(inclusive) is bool else None,
            feed_dates=_json_object(data, "feed_dates"),
        )


@dataclass(frozen=True)
class ScoreBreakdown:
    """Everything the report needs to show why a finding sits where it does."""

    finding_id: str
    host_ip: str
    risk: float
    band: str
    reason: str
    fix: str
    weights_hash: str
    cve_id: str | None = None
    cvss_version_used: str | None = None
    base_vector: str | None = None
    base_score: float | None = None
    env_vector: str | None = None
    env_score: float | None = None
    env_modifications: dict[str, str] = field(default_factory=dict[str, str])
    epss_percentile: float | None = None
    threat_multiplier: float | None = None
    kev: bool = False
    native_fallback: str | None = None
    inputs: dict[str, Any] = field(default_factory=dict[str, Any])

    def to_json(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "host_ip": self.host_ip,
            "cve_id": self.cve_id,
            "cvss_version_used": self.cvss_version_used,
            "base_vector": self.base_vector,
            "base_score": self.base_score,
            "env_vector": self.env_vector,
            "env_score": self.env_score,
            "env_modifications": dict(self.env_modifications),
            "epss_percentile": self.epss_percentile,
            "threat_multiplier": self.threat_multiplier,
            "kev": self.kev,
            "native_fallback": self.native_fallback,
            "risk": self.risk,
            "band": self.band,
            "inputs": self.inputs,
            "weights_hash": self.weights_hash,
            "reason": self.reason,
            "fix": self.fix,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "ScoreBreakdown":
        return cls(
            finding_id=data["finding_id"],
            host_ip=data["host_ip"],
            cve_id=data.get("cve_id"),
            cvss_version_used=data.get("cvss_version_used"),
            base_vector=data.get("base_vector"),
            base_score=data.get("base_score"),
            env_vector=data.get("env_vector"),
            env_score=data.get("env_score"),
            env_modifications=_json_object(data, "env_modifications"),
            epss_percentile=data.get("epss_percentile"),
            threat_multiplier=data.get("threat_multiplier"),
            kev=_json_bool(data, "kev"),
            native_fallback=data.get("native_fallback"),
            risk=_json_number(data["risk"], "risk", 0, 100),
            band=data["band"],
            inputs=data.get("inputs", {}),
            weights_hash=data["weights_hash"],
            reason=data.get("reason", ""),
            fix=data.get("fix", ""),
        )


@dataclass(frozen=True)
class Rationale:
    """One plain-English sentence. It explains a rank; it never changes one."""

    finding_id: str
    text: str
    source: str
    model: str | None = None
    validation: dict[str, Any] = field(default_factory=dict[str, Any])

    def __post_init__(self) -> None:
        if self.source not in ("llm", "template"):
            raise ValueError("Rationale.source must be 'llm' or 'template'")
        if not self.text or not self.text.strip():
            raise ValueError("Rationale.text must not be empty")

    def to_json(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "text": self.text,
            "source": self.source,
            "model": self.model,
            "validation": dict(self.validation),
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Rationale":
        return cls(
            finding_id=data["finding_id"],
            text=data["text"],
            source=data["source"],
            model=data.get("model"),
            validation=_json_object(data, "validation"),
        )
