"""The model layer: a local LLM may reword a verdict, never compute one.

Everything sent to the model is delimited, length-capped, stripped of control characters and
prefixed "untrusted data follows". Everything returned is validated before use, and any number
the model writes must already appear in the facts we gave it. A failure of any kind falls back to
the deterministic sentence from `scoring.describe`, and says so in the validation record.

This is the only module permitted to import a network client.
"""

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from copy import deepcopy
from ipaddress import ip_address
from pathlib import Path
from typing import Callable, cast
from urllib.parse import urlsplit

from vulnassess import scoring
from vulnassess.ai_boundary import (
    CONTROL_TOKENS,
    INJECTION_SENTINEL,
    SYSTEM_BOUNDARY_PROMPT,
    append_audit,
    digest,
    envelope,
    normalise_quote,
    verify_claims,
)
from vulnassess.control_applicability import POLICY_VERSION
from vulnassess.errors import ConfigError, LLMUnavailable, ProviderUnavailable
from vulnassess.schema import ContextProfile, Finding, Rationale, ScoreBreakdown
from vulnassess.score_facts import threat_description

DEFAULT_HOST = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2:3b"
MAX_FACT_CHARS = 600
MAX_SENTENCE_CHARS = 240
MAX_RESPONSE_BYTES = 64 * 1024
MAX_STREAM_BYTES = 16 * MAX_RESPONSE_BYTES
MAX_TIMEOUT_SECONDS = 2400.0
RATIONALE_SCHEMA_VERSION = "rationale.v1"
RATIONALE_WORDING_POLICY = "bounded-rationale-facts-v1"
RATIONALE_AUDIT_PATH = Path("data/ai_audit.jsonl")
RATIONALE_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "text", "claims"],
    "properties": {
        "schema_version": {"type": "string", "enum": [RATIONALE_SCHEMA_VERSION]},
        "text": {"type": "string"},
        "claims": {
            "type": "array",
            "minItems": 1,
            "maxItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "path",
                    "label",
                    "evidence_ids",
                    "quotes",
                    "finding_ids",
                    "confidence",
                    "verification_action",
                    "score",
                ],
                "properties": {
                    "path": {"type": "string", "enum": ["text"]},
                    "label": {
                        "type": "string",
                        "enum": ["observed", "inferred", "hypothesis", "unknown"],
                    },
                    "evidence_ids": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                    "quotes": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["evidence_id", "text"],
                            "properties": {
                                "evidence_id": {"type": "string"},
                                "text": {"type": "string"},
                            },
                        },
                    },
                    "finding_ids": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "verification_action": {"type": ["string", "null"]},
                    "score": {"type": ["number", "null"]},
                },
            },
        },
    },
}
FENCE = "-----"
UNTRUSTED_PREFIX = "untrusted data follows"
INSTRUCTION = (
    "Rewrite the verdict below as one plain-English sentence for a network defender.\n"
    "Rules: exactly one sentence; at most 240 characters; use only the facts given; "
    "do not invent or restate any number that is not in the facts; no URLs; no markdown; "
    "reply with the sentence and nothing else.\n"
    "Use supplied fact phrases joined by plain connective words; preserve every qualifier. "
    "A KEV listing is not current target exploitation; an EPSS percentile is not a probability; "
    "an unobserved control is not an absent control. Do not add causal or safety claims.\n"
)
NUMBER = re.compile(r"\d+(?:\.\d+)?")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _loopback_endpoint(host: str) -> str:
    try:
        parsed = urlsplit(host)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ConfigError(f"Invalid Ollama endpoint {host!r}: {error}") from error
    if (
        parsed.scheme != "http"
        or hostname is None
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ConfigError(
            f"Ollama endpoint must be an HTTP loopback origin with an explicit port, got {host!r}"
        )
    try:
        loopback = ip_address(hostname).is_loopback
    except ValueError:
        loopback = hostname.lower() == "localhost"
    if not loopback:
        raise ConfigError(
            f"Ollama endpoint {host!r} is not local; use localhost, 127.0.0.1, or [::1]"
        )
    return host.rstrip("/")


def sanitise(text: str, limit: int = MAX_FACT_CHARS) -> str:
    """Strip control characters, collapse whitespace, cap length, and neutralise the fence."""
    cleaned = CONTROL.sub(" ", str(text))
    cleaned = cleaned.replace(FENCE, " ")
    cleaned = " ".join(cleaned.split())
    return cleaned[:limit]


def _retained_context(
    breakdown: ScoreBreakdown, profile: ContextProfile, finding: Finding
) -> ContextProfile:
    """Bind explanation inputs to the scored finding, not later asset metadata."""
    if (
        not isinstance(breakdown, ScoreBreakdown)
        or not isinstance(profile, ContextProfile)
        or not isinstance(finding, Finding)
        or breakdown.finding_id != finding.id
        or breakdown.host_ip != finding.host_ip
        or breakdown.host_ip != profile.host_ip
    ):
        raise ConfigError("Rationale finding/host binding does not match the retained score")
    inputs = breakdown.inputs
    required = {"role", "exposure", "controls", "manual"}
    if not isinstance(inputs, dict) or not required.issubset(inputs):
        raise ConfigError(
            "MISSING: retained score context requires role, exposure, controls and manual"
        )
    try:
        json.dumps(inputs, allow_nan=False)
        retained = ContextProfile.from_json(
            {
                "host_ip": breakdown.host_ip,
                "role": inputs["role"],
                "exposure": inputs["exposure"],
                "controls": inputs["controls"],
                "manual": inputs["manual"],
            }
        )
        scoring._validate_profile(retained)
    except (
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
        OverflowError,
        RecursionError,
        ConfigError,
    ) as error:
        raise ConfigError(
            "Rationale retained score context is invalid; review its inputs"
        ) from error
    return retained


def facts_for(
    breakdown: ScoreBreakdown, profile: ContextProfile, finding: Finding
) -> dict[str, str]:
    """The only things the model is allowed to see. No score, so it cannot restate one."""
    profile = _retained_context(breakdown, profile, finding)
    waf = profile.controls.get("waf")
    control = (
        f"{sanitise(str(waf.value), 64)} recorded signal; applicability and mitigation unverified"
        if waf and waf.value
        else "none observed"
    )
    # New scores carry their own finding-scoped decision. Do not reintroduce
    # broad host observations into the explanation after scoring withheld them.
    decisions = breakdown.inputs.get("control_applicability", {})
    if not isinstance(decisions, dict):
        raise ConfigError("Rationale retained score context has invalid control decisions")
    if (
        breakdown.inputs.get("context_policy") == POLICY_VERSION
        and "waf" in profile.controls
        and "waf" not in decisions
    ):
        raise ConfigError("MISSING: retained score context has no finding-scoped WAF decision")
    decision = decisions.get("waf") if isinstance(decisions, dict) else None
    if "waf" in decisions and (
        not isinstance(decision, dict)
        or decision.get("status") not in {"withheld", "applied", "eligible", "unknown"}
    ):
        raise ConfigError("Rationale retained score context has an unsupported WAF decision")
    if isinstance(decision, dict):
        if decision.get("status") == "withheld":
            control = "host-level control signal withheld for this finding"
        elif (
            decision.get("status") in {"applied", "eligible"}
            and breakdown.inputs.get("context_policy") == POLICY_VERSION
        ):
            scoped = breakdown.inputs.get("controls", {}).get("waf", {})
            vendor = sanitise(str(scoped.get("value", "WAF")), 64)
            control = f"{vendor} signal on affected HTTP record; mitigation unverified"
        elif decision.get("status") not in {"applied", "eligible"}:
            control = "none observed"
    environment = profile.manual.get("environment")
    threat = threat_description(breakdown.kev, breakdown.epss_percentile)
    return {
        "verdict": sanitise(breakdown.band, 32),
        "asset role": sanitise(str(profile.role.value).replace("_", " "), 64),
        "exposure": "internet-facing"
        if profile.exposure.value == "internet_facing"
        else "internal",
        "environment": sanitise(str(environment.value), 32) if environment else "not stated",
        "exploitation": threat,
        "compensating control": control,
        "finding": sanitise(finding.title, 160),
    }


def build_prompt(facts: dict[str, str]) -> str:
    body = "\n".join(f"{key}: {value}" for key, value in facts.items())
    return f"{INSTRUCTION}\n{UNTRUSTED_PREFIX}\n{FENCE}\n{body}\n{FENCE}\n"


def allowed_numbers(facts: dict[str, str]) -> set[str]:
    return {token for value in facts.values() for token in NUMBER.findall(value)}


def _phrase(value: str) -> str:
    return " ".join(value.casefold().replace("-", " ").replace("_", " ").split())


def _fact_phrases(facts: dict[str, str]) -> dict[str, list[str]]:
    """Bounded factual slots, not a bag of words borrowed from scanner prose."""
    phrases: dict[str, list[str]] = {}
    for key in ("verdict", "asset role", "exposure"):
        value = facts.get(key)
        if value:
            phrases[key] = [f"{key} unknown", f"unknown {key}"] if value == "unknown" else [value]
            labels = {
                "verdict": ("priority", "risk"),
                "asset role": ("role",),
                "exposure": ("exposure",),
            }[key]
            phrases[key] += [
                phrase
                for label in labels
                for phrase in (f"{value} {label}", f"{label} is {value}", f"{label} {value}")
            ]
    environment = facts.get("environment")
    if environment in ("test", "prod", "production"):
        phrases["environment"] = [
            environment,
            f"{environment} environment",
            f"environment is {environment}",
        ]
        if environment == "prod":
            phrases["environment"] += ["production", "production environment"]
    elif environment == "not stated":
        phrases["environment"] = ["environment not stated"]
    threat = facts.get("exploitation", "")
    if threat in (
        "matched CVE listed in retained CISA KEV snapshot",
        "no exploitation data retained",
    ) or re.fullmatch(
        r"EPSS relative ranking: \d{1,3}(?:st|nd|rd|th) percentile(?: \(rounded\))?", threat
    ):
        phrases["exploitation"] = [threat]
    control = facts.get("compensating control", "")
    if control == "none observed":
        phrases["compensating control"] = [
            "no compensating control observed",
            "controls not established",
        ]
    elif control:
        # Matching the whole phrase makes dropping scope/uncertainty fail closed.
        phrases["compensating control"] = [control]
        if "; " in control:
            phrases["compensating control"].append(control.replace("; ", " (") + ")")
    title = facts.get("finding")
    if title:
        phrases["finding"] = [f'recorded finding "{title}"']
    return phrases


def _wording_problems(text: str, facts: dict[str, str]) -> tuple[list[str], list[str]]:
    remaining = _phrase(text)
    used: set[str] = set()
    fragments = [
        (key, _phrase(value)) for key, values in _fact_phrases(facts).items() for value in values
    ]
    for key, fragment in sorted(fragments, key=lambda item: (-len(item[1]), item[0])):
        pattern = r"(?<![a-z0-9])" + re.escape(fragment) + r"(?![a-z0-9])"
        marker = key.replace(" ", "_")
        if key == "verdict" and fragment == _phrase(facts[key]):
            marker = "verdict_value"
        remaining, count = re.subn(pattern, f"@{marker}@", remaining)
        if count:
            used.add(key)
    # Typed phrases in bounded sentence forms, not freely permutable fact words.
    # This is not a general natural-language entailment claim.
    subject = (
        r"(?:(?:this|the|an|a) )?(?:@exposure@ "
        r"(?:@asset_role@|host|asset|service|finding)|@asset_role@|host|asset|service|finding)"
    )
    fact = r"(?:@environment@|@exploitation@|@compensating_control@)"
    prefix = (
        rf"(?:@verdict@ for (?:{subject}|@finding@)|"
        rf"{subject} (?:is|has) @verdict@|{subject} has {fact}|"
        r"@verdict_value@: @exposure@ @asset_role@)"
    )
    tail = rf"(?:,? (?:(?:with|and) )?(?:a |an )?{fact})*"
    declaration = r"the inferred @asset_role@, with @exposure@ and a @environment@"
    problems: list[str] = []
    if not used:
        problems.append("no supported fact phrase in rewrite")
    if not re.fullmatch(rf"(?:{prefix}{tail}|{declaration})\.", " ".join(remaining.split())):
        problems.append("unsupported wording or relationships outside the supplied factual slots")
    return problems, sorted(used)


def validate(sentence: str, facts: dict[str, str]) -> tuple[bool, dict[str, object]]:
    """Accept bounded fact-slot rewrites, not arbitrary allegedly grounded prose."""
    if not isinstance(sentence, str):
        return False, {
            "accepted": False,
            "problems": ["rationale must be a string"],
            "facts_used": [],
        }
    text = sentence.strip()
    problems: list[str] = []
    if not text:
        problems.append("empty response")
    if "\n" in text or "\r" in text:
        problems.append("more than one line")
    if len(text) > MAX_SENTENCE_CHARS:
        problems.append(f"longer than {MAX_SENTENCE_CHARS} characters")
    if CONTROL.search(text) or not text.isascii():
        problems.append("non-printable or non-ascii characters")
    for banned in ("```", "<", "{", "}", "@"):
        if banned in text:
            problems.append(f"contains {banned!r}")
    if re.search(r"https?://|www\.", text, re.IGNORECASE):
        problems.append("contains a URL")
    if text and not text.endswith("."):
        problems.append("does not end in a full stop")
    if text.count(".") > 4:
        problems.append("more than one sentence")
    if not isinstance(facts, dict) or any(
        not isinstance(value, str) or not value.strip() for value in facts.values()
    ):
        return False, {
            "accepted": False,
            "problems": ["rationale facts must be strings"],
            "facts_used": [],
        }
    permitted = allowed_numbers(facts)
    invented = sorted({token for token in NUMBER.findall(text) if token not in permitted})
    if invented:
        problems.append(f"invented number(s) {invented}")
    if problems:
        return False, {"accepted": False, "problems": problems, "facts_used": []}
    wording, used = _wording_problems(text, facts)
    problems.extend(wording)
    return (not problems), {"accepted": not problems, "problems": problems, "facts_used": used}


class OllamaClient:
    """A thin local Ollama caller. Absence is reported, never worked around."""

    source = "local_ollama_grounded_analysis"

    def __init__(
        self, host: str = DEFAULT_HOST, model: str = DEFAULT_MODEL, timeout: float = 30.0
    ) -> None:
        self.host = _loopback_endpoint(host)
        if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
            raise ConfigError(
                f"Ollama timeout must be in (0, {MAX_TIMEOUT_SECONDS}] seconds, got {timeout}"
            )
        self.model = model
        self.timeout = timeout

    def _request(self, path: str, payload: dict | None = None) -> dict:
        url = f"{self.host}{path}"
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                content_length = response.headers.get("Content-Length")
                if content_length is not None and int(content_length) > MAX_RESPONSE_BYTES:
                    raise LLMUnavailable(
                        f"Ollama response from {url} exceeds {MAX_RESPONSE_BYTES} bytes"
                    )
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise LLMUnavailable(
                        f"Ollama response from {url} exceeds {MAX_RESPONSE_BYTES} bytes"
                    )
                return json.loads(body.decode("utf-8"))
        except (urllib.error.URLError, OSError) as error:
            raise ProviderUnavailable(
                f"Ollama did not answer at {url}: {type(error).__name__}. "
                f"A human must run: ollama serve   and   ollama pull {self.model}"
            ) from error
        except (json.JSONDecodeError, ValueError) as error:
            raise LLMUnavailable(
                f"Ollama returned an invalid response at {url}: {type(error).__name__}"
            ) from error

    def available(self) -> bool:
        models = self._request("/api/tags").get("models", [])
        names = {str(item.get("name", "")) for item in models}
        if self.model not in names and not any(
            name.split(":")[0] == self.model.split(":")[0] for name in names
        ):
            raise LLMUnavailable(
                f"MISSING model {self.model!r} at {self.host}; "
                f"a human must run: ollama pull {self.model}"
            )
        return True

    def generate(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0, "seed": 0, "num_predict": 120},
        }
        return str(self._request("/api/generate", payload).get("response", ""))

    def generate_structured(
        self,
        prompt: str,
        schema: dict[str, object],
        *,
        num_predict: int = 600,
        num_ctx: int = 2048,
        on_progress: Callable[[int], None] | None = None,
        on_raw: Callable[[bytes], None] | None = None,
    ) -> dict:
        """Generate JSON in JSON mode over a streamed /api/chat exchange.

        /api/generate echoes the full prompt-token context array in every response, so a
        large real-target case would exceed the response guard no matter how small the
        model's answer is. Streaming /api/chat additionally means an abandoned request is
        detected at the next token instead of after a full silent generation, so a
        timed-out analyst call cannot leave a zombie generation blocking every later one.
        """
        if not 1 <= num_predict <= 2048:
            raise ConfigError("structured generation num_predict must be in 1..2048")
        if not 512 <= num_ctx <= 131072:
            raise ConfigError("structured generation num_ctx must be in 512..131072")
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_BOUNDARY_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": True,
            "format": schema,
            "options": {
                "temperature": 0,
                "seed": 0,
                "num_ctx": num_ctx,
                "num_predict": num_predict,
            },
        }
        request = urllib.request.Request(
            f"{self.host}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        deadline = time.monotonic() + self.timeout
        parts: list[str] = []
        received_bytes = 0
        content_bytes = 0
        last_reported = 0
        completed = False
        canary_tail = b""
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                while line := response.readline(MAX_RESPONSE_BYTES + 1):
                    received_bytes += len(line)
                    if len(line) > MAX_RESPONSE_BYTES or received_bytes > MAX_STREAM_BYTES:
                        raise LLMUnavailable("Ollama stream exceeds the bounded response budget")
                    if time.monotonic() > deadline:
                        raise ProviderUnavailable(
                            f"Ollama generation exceeded {self.timeout:g}s at {self.host}"
                        )
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise LLMUnavailable("Ollama stream event must be a JSON object")
                    if event.get("error"):
                        detail = sanitise(str(event["error"]), MAX_SENTENCE_CHARS)
                        raise ProviderUnavailable(f"Ollama error at {self.host}: {detail}")
                    message = event.get("message", {})
                    if not isinstance(message, dict) or not isinstance(
                        message.get("content", ""), str
                    ):
                        raise LLMUnavailable("Ollama stream message must contain text")
                    content = message.get("content", "")
                    emitted = content.encode("utf-8")
                    content_bytes += len(emitted)
                    if content_bytes > MAX_RESPONSE_BYTES:
                        raise LLMUnavailable(
                            f"Ollama structured output exceeds {MAX_RESPONSE_BYTES} bytes"
                        )
                    parts.append(content)
                    canary = INJECTION_SENTINEL.encode("ascii")
                    if canary in canary_tail + emitted:
                        if on_raw is not None:
                            on_raw(canary)
                        raise LLMUnavailable("Needs review: untrusted instruction canary triggered")
                    canary_tail = (canary_tail + emitted)[-(len(canary) - 1) :]
                    if on_progress is not None and content_bytes - last_reported >= 512:
                        on_progress(content_bytes)
                        last_reported = content_bytes
                    if event.get("done") is True:
                        completed = True
                        break
        except TimeoutError as error:
            raise ProviderUnavailable(
                f"Ollama response timed out after {self.timeout:g}s at {self.host}; "
                "the model may be too slow for this request"
            ) from error
        except (urllib.error.URLError, OSError) as error:
            raise ProviderUnavailable(
                f"Ollama did not answer at {self.host}/api/chat: {type(error).__name__}. "
                f"A human must run: ollama serve   and   ollama pull {self.model}"
            ) from error
        except (ValueError, TypeError) as error:
            raise LLMUnavailable(
                f"Ollama returned an invalid stream at {self.host}/api/chat: {type(error).__name__}"
            ) from error
        if not completed:
            raise ProviderUnavailable("Ollama stream ended before explicit completion")
        raw_output = "".join(parts).encode("utf-8")
        if on_raw is not None:
            on_raw(raw_output)
        try:
            result = json.loads(raw_output)
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            raise LLMUnavailable("Ollama returned invalid structured analyst output") from error
        if not isinstance(result, dict):
            raise LLMUnavailable("Ollama analyst output must be a JSON object")
        return result


def rationale_for(
    breakdown: ScoreBreakdown,
    profile: ContextProfile,
    finding: Finding,
    client: OllamaClient | None = None,
) -> Rationale:
    """A validated model sentence when one is available, the deterministic sentence otherwise."""
    try:
        facts = facts_for(breakdown, profile, finding)
    except ConfigError as error:
        # No provider call or historical prose publication on an unbound input.
        return Rationale(
            finding_id=breakdown.finding_id,
            text="Assessment rationale needs review; retained context could not be bound to this finding.",
            source="template",
            model=None,
            validation={
                "accepted": False,
                "status": "needs_review",
                "context_basis": "unavailable",
                "problems": [str(error)],
            },
        )
    if client is None:
        return Rationale(
            finding_id=breakdown.finding_id,
            text=breakdown.reason,
            source="template",
            model=None,
            validation={
                "accepted": True,
                "problems": [],
                "note": "no model configured",
                "context_basis": "retained_score_inputs",
            },
        )
    evidence = [
        {"id": f"E{index}", "text": f"{key}: {value}"}
        for index, (key, value) in enumerate(facts.items(), 1)
    ]
    prompt = (
        "Rewrite the deterministic verdict as one short sentence. Do not change a score. "
        f"Valid finding ID: {breakdown.finding_id}. "
        "Return schema rationale.v1 with one claim for path text; cite a verbatim quote "
        "from each factual slot used. Label the rewrite inferred; quote each entire fact block. "
        "Use supplied fact phrases with plain connective words; preserve scope and uncertainty. "
        "Use either 'BAND priority for this EXPOSURE ROLE, with FACT.' or "
        "'This EXPOSURE ROLE has FACT.'; use full supplied phrases for FACT. "
        "Do not add negation, guarantees, causal claims, current compromise, absolute exploitation "
        "probability or remediation actions. Unknown facts stay unknown.\n"
        + UNTRUSTED_PREFIX
        + "\n"
        + "\n".join(envelope(item["id"], item["text"], limit=MAX_FACT_CHARS) for item in evidence)
    )
    audit = {
        "stage": RATIONALE_SCHEMA_VERSION,
        "model": getattr(client, "model", "unknown"),
        "finding_id": breakdown.finding_id,
        "prompt_hash": digest({"system": SYSTEM_BOUNDARY_PROMPT, "user": prompt}),
        "input_hash": digest(evidence),
        "score_inputs_hash": digest(breakdown.inputs),
        "output_hash": None,
        "decision": "validate",
        "outcome": "needs_review",
    }
    try:

        def capture_raw(raw: bytes) -> None:
            audit["output_hash"] = hashlib.sha256(raw).hexdigest()
            audit["canary_seen"] = (
                bool(audit.get("canary_seen")) or INJECTION_SENTINEL.encode("ascii") in raw
            )

        response = client.generate_structured(
            prompt, RATIONALE_SCHEMA, num_predict=600, num_ctx=4096, on_raw=capture_raw
        )
        if audit["output_hash"] is None:
            try:
                audit["output_hash"] = digest(response)
            except (TypeError, ValueError):
                audit["output_hash"] = digest(repr(response))
        if audit.get("canary_seen") or INJECTION_SENTINEL in json.dumps(
            response, ensure_ascii=True
        ):
            audit["flagged_evidence_ids"] = [
                item["id"] for item in evidence if CONTROL_TOKENS.search(item["text"])
            ]
            raise LLMUnavailable("untrusted instruction canary triggered")
        if (
            not isinstance(response, dict)
            or set(response) != {"schema_version", "text", "claims"}
            or response["schema_version"] != RATIONALE_SCHEMA_VERSION
        ):
            raise LLMUnavailable("rationale schema is invalid")
        verify_claims(response["claims"], evidence, {breakdown.finding_id}, {}, {"text"})
        if response["claims"][0]["finding_ids"] != [breakdown.finding_id]:
            raise LLMUnavailable("rationale claim does not cite its finding")
        answer = response["text"]
        if not isinstance(answer, str):
            raise LLMUnavailable("rationale text is invalid")
        accepted, record = validate(answer, facts)
        if not accepted:
            raise LLMUnavailable("; ".join(cast(list[str], record["problems"])))
        claim = response["claims"][0]
        if claim["label"] != "inferred":
            raise LLMUnavailable("a factual rationale rewrite must be labelled inferred")
        quoted = {quote["evidence_id"]: normalise_quote(quote["text"]) for quote in claim["quotes"]}
        used = cast(list[str], record["facts_used"])
        for key, item in zip(facts, evidence, strict=True):
            if key in used and quoted.get(item["id"]) != normalise_quote(item["text"]):
                raise LLMUnavailable(f"rationale needs the complete supporting quote for {key}")
        audit["outcome"] = "validated"
    except LLMUnavailable as error:
        audit["decision"] = "reject"
        audit["reason"] = type(error).__name__
        if audit.get("canary_seen"):
            audit["flagged_evidence_ids"] = [
                item["id"] for item in evidence if CONTROL_TOKENS.search(item["text"])
            ]
        return Rationale(
            finding_id=breakdown.finding_id,
            text=breakdown.reason,
            source="template",
            model=getattr(client, "model", None),
            validation={
                "accepted": False,
                "status": "needs_review",
                "problems": [
                    "untrusted instruction canary triggered"
                    if audit.get("canary_seen")
                    else str(error)
                ],
            },
        )
    except Exception as error:
        audit["decision"] = "reject"
        audit["reason"] = type(error).__name__
        return Rationale(
            finding_id=breakdown.finding_id,
            text=breakdown.reason,
            source="template",
            model=getattr(client, "model", None),
            validation={
                "accepted": False,
                "status": "needs_review",
                "problems": ["model boundary failed unexpectedly"],
            },
        )
    finally:
        append_audit(audit, RATIONALE_AUDIT_PATH)
    return Rationale(
        finding_id=breakdown.finding_id,
        text=answer.strip(),
        source="llm",
        model=client.model,
        validation={
            **record,
            "status": "validated",
            "context_basis": "retained_score_inputs",
            "wording_policy": RATIONALE_WORDING_POLICY,
            "claims": deepcopy(response["claims"]),
        },
    )


def explain_run(run_id: str, store, client: OllamaClient | None = None) -> dict[str, int]:
    profiles = {profile.host_ip: profile for profile in store.profiles(run_id)}
    findings = {finding.id: finding for finding in store.findings(run_id)}
    scores = store.scores(run_id)
    # Resolve every required association before any provider call or write.
    # Skipping an orphan otherwise makes an incomplete run look successful.
    for breakdown in scores:
        for label, present in (
            ("profile", breakdown.host_ip in profiles),
            ("finding", breakdown.finding_id in findings),
        ):
            if not present:
                raise ConfigError(
                    f"MISSING: {label} for scored finding {breakdown.finding_id!r} "
                    f"in run {run_id!r}; restore its associated records before explaining"
                )
    counts = {"llm": 0, "template": 0}
    for breakdown in scores:
        profile = profiles[breakdown.host_ip]
        finding = findings[breakdown.finding_id]
        rationale = rationale_for(breakdown, profile, finding, client)
        store.upsert_rationale(run_id, rationale)
        counts[rationale.source] += 1
    return counts
