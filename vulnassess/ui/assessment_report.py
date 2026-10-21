"""Printable, read-only reports from verified saved checkpoints; no tool or model calls."""

import base64
import re
from hashlib import sha256
from html import escape
from pathlib import Path

from vulnassess.ai_boundary import INJECTION_SENTINEL, SCHEMA_VERSION, verify_claims
from vulnassess.analyst import validate_control_grounding, validate_prose_identifiers
from vulnassess.assessment_derivations import derive
from vulnassess.claim_semantics import verify_semantic_claims
from vulnassess.decision_focus import validate_document as validate_decision_focus
from vulnassess.errors import ConfigError, LLMUnavailable
from vulnassess.finding_assurance import assurance
from vulnassess.priority_trace import priority_trace
from vulnassess.report_composer import catalog, validate_document
from vulnassess.score_facts import missing_severity_basis
from vulnassess.service_context import endpoint_context, service_evidence_text

CSS_PATH = Path(__file__).with_name("static") / "assessment-report.css"
CLAIM_PATH = re.compile(
    r"summary|context_effect\.explanation|recommended_actions\.\d+\.(action|reason)"
    r"|correlations\.\d+\.observation|investigations\.\d+\.(hypothesis|verification|alternative)"
    r"|uncertainties\.\d+"
)


def text(value):
    return escape(str(value)) if value is not None else "Unknown — not recorded"


def paragraph(value, css=""):
    return f'<p class="{css}">{text(value)}</p>'


def listing(values, empty="Not recorded; no absence is established."):
    return (
        "<ul>" + "".join(f"<li>{text(value)}</li>" for value in values) + "</ul>"
        if values
        else paragraph(empty, "muted")
    )


def facts(values):
    return (
        "<dl>"
        + "".join(f"<dt>{text(key)}</dt><dd>{text(value)}</dd>" for key, value in values)
        + "</dl>"
    )


def _device(data):
    if not data:
        return ""
    content = '<section id="device"><h2>Your device · Self-defence</h2>'
    content += paragraph(data.get("boundary"), "notice")
    content += facts(
        [
            ("Device checked at", data.get("checked_at")),
            ("Active network profiles", ", ".join(data.get("active_profiles", [])) or "Unknown"),
            (
                "Registered antivirus",
                ", ".join(data.get("antivirus_providers", [])) or "Not verified",
            ),
            ("Latest recorded hotfix", data.get("last_recorded_update")),
        ]
    )
    content += paragraph(
        "Antivirus registration is not proof of active protection. A recorded hotfix does not establish that every update is installed.",
        "muted",
    )
    content += "<h3>What to do first</h3>" + paragraph(
        "Fixed, evidence-based precautions, not AI claims or vulnerability scores. Review changes yourself; this report changes no settings."
    )
    checks = {item["id"]: item for item in data.get("checks", [])}
    for index, action in enumerate(data.get("action_queue", []), 1):
        content += f"<article><h4>{index}. {text(action.get('title'))}</h4>"
        content += paragraph(action.get("kind"), "meta")
        content += paragraph(action.get("reason")) + paragraph(action.get("action"))
        content += paragraph("Supporting check IDs: " + ", ".join(action.get("basis", [])), "meta")
        content += (
            listing(
                [checks[key]["observation"] for key in action.get("basis", []) if key in checks],
                "Other supporting observations are listed in the device inventory below.",
            )
            + "</article>"
        )
    if not data.get("action_queue"):
        content += paragraph(
            "No precaution queue was recorded. This is not a clean bill of health."
        )
    content += "<h3>Protection checks and precautions</h3>"
    for check in data.get("checks", []):
        content += f"<article><h4>{text(check.get('title'))}</h4>"
        content += paragraph(
            f"Check {check.get('id')} · {check.get('state', 'unknown')} · {check.get('attention', 'not recorded')}",
            "meta",
        )
        content += paragraph(check.get("observation"))
        content += (
            paragraph("Precaution: " + str(check.get("precaution", "Not recorded"))) + "</article>"
        )
    content += "<h3>Applications accepting connections</h3>"
    content += paragraph(
        "A network listener is not proof of internet reachability. An empty inventory does not prove no exposure. Collection is bounded to 64 listeners."
    )
    content += listing(
        [
            f"{item.get('application', 'Unknown')} · TCP/{item.get('port')} · {item.get('binding', 'Unknown')}"
            for item in data.get("listeners", [])
        ]
    )
    content += paragraph(data.get("limitations"), "notice") + "</section>"
    return content


def _finding_guidance(finding):
    """Explain only recognized scanner observations; never promote them to proven exploits."""
    title = str(finding.get("title") or "").casefold()
    if finding.get("tool") == "redis-check" and "CVE-2022-0543" in finding.get("cve_ids", []):
        return (
            "Redis Lua sandbox exposure",
            "The bounded Lua type check observed package.loadlib exposed in the Redis Lua environment, the vulnerable configuration associated with CVE-2022-0543. Library loading and OS command execution were not attempted.",
            "Check the installed Redis package's distribution and vendor patch status against the retained advisory. After remediation, repeat the bounded type check; do not attempt library loading or command execution.",
            "Apply the vendor-fixed package under change control, restrict this Redis endpoint to approved clients, and review authentication and least-privilege ACLs. Network access restrictions reduce exposure but do not replace the package fix.",
        )
    if finding.get("tool") != "nikto":
        return (
            "Other scanner observation",
            "The retained scanner record needs analyst confirmation.",
            "Reproduce the observation on the recorded endpoint and compare the raw evidence.",
            "Choose a change only after the affected component and impact are confirmed.",
        )
    headers = {
        "content-security-policy": (
            "Browser content policy was not observed in this response.",
            "Check the actual policy on the affected response paths; a missing header alone does not establish script injection.",
            "Design and test a suitable policy, starting with report-only where appropriate.",
        ),
        "strict-transport-security": (
            "An HTTPS transport policy header was not observed in this response.",
            "Confirm the hostname's HTTPS and redirect behavior before changing HSTS; this scan does not prove downgrade exposure.",
            "Enable an appropriately scoped HSTS policy only after HTTPS behavior is verified.",
        ),
        "x-content-type-options": (
            "The browser MIME-sniffing control was not observed in this response.",
            "Check response content types and whether the header is absent on affected paths.",
            "Set nosniff after checking that served content types are correct.",
        ),
        "referrer-policy": (
            "A referrer disclosure policy was not observed in this response.",
            "Check whether sensitive URL information could be sent as a referrer from affected pages.",
            "Choose a referrer policy appropriate to the application's navigation needs.",
        ),
        "permissions-policy": (
            "A browser feature-permission policy was not observed in this response.",
            "Inventory which browser capabilities the application actually uses.",
            "Restrict unused capabilities without breaking required features.",
        ),
    }
    prefix = "suggested security header missing: "
    if title.startswith(prefix):
        header = title[len(prefix) :].rstrip(". ")
        if header in headers:
            meaning, verify, improve = headers[header]
            return "Response-header hardening", meaning, verify, improve
    if title.startswith("retrieved x-powered-by header:"):
        return (
            "Technology disclosure",
            "The response disclosed a technology/version string; this is not proof that version is vulnerable.",
            "Confirm the header is served by the recorded endpoint and identify the component that sets it.",
            "Remove unnecessary version disclosure and assess the actual installed version separately.",
        )
    if "junk http methods" in title:
        return (
            "HTTP method behavior",
            "The server responded to an unexpected method; the scanner itself warns this may be a false positive.",
            "Compare status, body, and allowed-method behavior for the specific affected path.",
            "Reject unsupported methods consistently if verification confirms unintended behavior.",
        )
    if "content-encoding" in title and "breach" in title:
        return (
            "Compression exposure to verify",
            "Compression was observed; BREACH requires additional conditions that this scan did not establish.",
            "Check whether secrets and attacker-influenced content appear together in compressed responses.",
            "If those conditions exist, mitigate on sensitive responses rather than disabling compression indiscriminately.",
        )
    return (
        "Other scanner observation",
        "The retained Nikto message is a lead, not a verified exploit.",
        "Reproduce it on the recorded endpoint and inspect the raw scanner response.",
        "Apply a targeted change only after confirmation.",
    )


def _practical_assessment(result, payload):
    findings = payload.get("findings", [])
    groups = {}
    for index, finding in enumerate(findings, 1):
        theme = _finding_guidance(finding)[0]
        groups.setdefault(theme, []).append((index, finding))
    cves = sorted({cve for finding in findings for cve in finding.get("cve_ids", [])})
    content = '<section id="practical"><h2>What this assessment means</h2>'
    content += '<div class="report-snapshot">'
    for label, value in (
        ("Collection", result.get("scan_status", "unknown")),
        (
            "Observed services",
            sum(len(host.get("services", [])) for host in payload.get("hosts", [])),
        ),
        ("Scanner observations", len(findings)),
        ("Scanner-named CVEs", len(cves)),
    ):
        content += f"<div><strong>{text(value)}</strong><span>{text(label)}</span></div>"
    content += "</div>"
    if findings:
        content += paragraph(
            "The items below are scanner observations requiring verification, not confirmed exploitation. "
            "A deterministic priority orders follow-up; it is not a probability of compromise.",
            "notice",
        )
        content += '<h3>Evidence grouped by what to check</h3><div class="report-groups">'
        for theme, items in groups.items():
            content += f"<article><h4>{text(theme)} · {len(items)}</h4><ul>"
            for index, finding in items:
                content += f'<li><a href="#finding-{index}">{text(finding.get("title") or finding.get("id"))}</a></li>'
            content += "</ul></article>"
        content += "</div>"
    else:
        content += paragraph(
            "No scanner observation was retained. Review coverage before drawing any safety conclusion.",
            "notice",
        )
    content += "<h3>Decision for this run</h3>"
    if cves:
        content += paragraph(
            f"{len(cves)} scanner-named CVE ID(s) were retained. Review the recorded feed snapshots, "
            "version match, and affected endpoint before applying a CVE-specific fix."
        )
    else:
        content += paragraph(
            "No scanner-named CVE was retained. NVD, EPSS, and CISA KEV cannot establish a match for "
            "this endpoint from these observations; this is not evidence that no CVE applies."
        )
    content += paragraph(
        "First verify the recorded observations on the exact authorized endpoint, then make targeted "
        "configuration changes, and re-check the same responses. Broader application testing or imported "
        "Nessus evidence is a separate coverage step, not something this report claims to have done."
    )
    return content + "</section>"


def _proof_supports(proof, finding):
    return (
        proof.get("status") == "verified"
        and proof.get("target_ip") == finding.get("host_ip")
        and proof.get("port") == finding.get("port")
        and proof.get("protocol") == finding.get("protocol") == "tcp"
        and finding.get("id") in proof.get("finding_ids", [])
    )


def _derivations(record, focus=None):
    cards = derive(record)
    content = '<section id="decisions"><h2>What the evidence means · conclusions and decisions</h2>'
    content += paragraph(
        "Evidence-derived conclusions, not new scanner findings or proof of compromise. Each conclusion names its supporting observations, limits and the outcome that would change it.",
        "meta",
    )
    choices = {}
    if focus:
        try:
            plan = validate_decision_focus(focus, record, cards)
            for rank, choice in enumerate(plan["next_decisions"], 1):
                choices[(choice["derivation_id"], choice["action_id"])] = rank
            content += paragraph(
                f"AI verification focus selected by {focus['model']} · source and action premises verified. The model selected existing supported decisions; it did not author the underlying evidence or change finding priorities.",
                "report-composed",
            )
        except (LLMUnavailable, KeyError, TypeError, ValueError):
            content += paragraph(
                "AI focus could not be verified. The evidence-derived decision record remains available without model selection.",
                "notice",
            )
    else:
        content += paragraph(
            "Evidence-derived decision record · no validated AI focus selection retained for this capture.",
            "meta",
        )
    all_findings = len(record["payload"].get("findings", []))
    covered = {
        identity for card in cards if card["kind"] != "coverage" for identity in card["finding_ids"]
    }
    if all_findings > len(covered):
        content += paragraph(
            f"Decision coverage: {len(covered)} of {all_findings} findings shown here. The findings section retains the complete inventory; omitted findings were not interpreted by this decision view.",
            "notice",
        )
    for card in cards:
        content += f'<article class="derivation-card" id="{text(card["id"])}"><p class="eyebrow">EVIDENCE → CONCLUSION → DECISION</p><h3>{text(card["title"])}</h3>'
        content += (
            '<div class="derivation-conclusion"><h4>What we can conclude</h4>'
            + paragraph(card["conclusion"]["text"])
            + "</div>"
        )
        content += paragraph(
            "Inferred from: " + ", ".join(card["conclusion"]["premise_ids"]), "meta"
        )
        content += "<h4>Why this matters</h4>" + paragraph(card["significance"])
        content += '<details class="derivation-sources"><summary>Supporting observations · trace every premise</summary>'
        for observation in card["observations"]:
            content += f'<blockquote><strong>{text(observation["id"])}</strong><br>{text(observation["text"])}<br><span class="meta">{text(observation["source"])}</span></blockquote>'
        content += (
            '</details><div class="derivation-boundaries"><div><h4>Not established</h4>'
            + listing(card["limits"])
            + "</div><div><h4>Competing explanation / limitation</h4>"
            + listing(card["alternatives"])
            + "</div></div>"
        )
        content += "<h4>Decisions to take</h4>"
        for action in card["actions"]:
            content += '<div class="derivation-action">'
            if rank := choices.get((card["id"], action["id"])):
                content += paragraph(f"AI next-verification focus {rank}", "decision-focus")
            content += f"<h4>{text(action['task'])}</h4>" + paragraph(action["reason"])
            content += facts(
                [
                    ("Expected outcome", action["expected"]),
                    ("If the check fails", action["if_fail"]),
                    ("If the check passes", action["if_pass"]),
                ]
            )
            content += (
                paragraph("Supporting premises: " + ", ".join(action["premise_ids"]), "meta")
                + "</div>"
            )
        content += (
            "<h4>What would change this conclusion?</h4>"
            + listing(card["changes_conclusion"])
            + "</article>"
        )
    return content + "</section>"


def _findings(payload, proofs=(), policy=None):
    content = '<section id="findings"><h2>Findings and deterministic priorities</h2>'
    content += paragraph(
        "These are retained engine values, not AI-generated scores. A native scanner fallback is not CVSS. Missing severity is not Low risk by default."
    )
    scores = {row["finding_id"]: row for row in payload.get("scores", [])}
    for index, finding in enumerate(payload.get("findings", []), 1):
        theme, meaning, verify, improve = _finding_guidance(finding)
        content += (
            f'<article id="finding-{index}"><h3>{text(finding.get("title") or finding["id"])}</h3>'
        )
        content += paragraph(theme, "meta")
        if status := assurance(finding):
            content += (
                '<div class="finding-assurance"><h4>Finding status — distinct evidence levels</h4>'
                + facts(
                    [
                        ("Observed condition", status["condition"]),
                        ("CVE applicability", status["cve"]),
                        ("Package identity", status["package"]),
                        ("Exploitability", status["exploitability"]),
                        ("How to read this priority", status["priority"]),
                    ]
                )
                + "</div>"
            )
            for proof in proofs:
                if not _proof_supports(proof, finding):
                    continue
                content += '<details open class="bounded-proof"><summary>Exact bounded probe · verified against capture manifest</summary>'
                content += (
                    "<h4>Request · escaped wire representation</h4><pre>"
                    + text(repr(proof["request"]))
                    + "</pre>"
                )
                content += (
                    "<h4>Response · escaped Redis RESP bytes</h4><pre>"
                    + text(repr(proof["response"]))
                    + "</pre>"
                )
                content += paragraph(proof["establishes"]) + paragraph(
                    proof["limitations"], "notice"
                )
                content += paragraph("Source SHA-256: " + proof["sha256"], "meta") + "</details>"
            if not any(_proof_supports(p, finding) for p in proofs):
                content += paragraph(
                    "Exact raw proof is unavailable or could not be verified for this report; no underlying response is invented.",
                    "notice",
                )
            content += (
                '<details open class="verification-outcomes"><summary>Verification outcomes · owner-assisted, not checks already performed</summary>'
                + facts(
                    [
                        (
                            "Package applicability",
                            "Compare owner-provided distribution, exact package revision and vendor security status. Expected: a vendor-fixed package. If affected: patch under change control; if inventory is unavailable: retain candidate status rather than claiming a confirmed CVE.",
                        ),
                        (
                            "Lua sandbox after remediation",
                            "Repeat only the bounded type check from the approved vantage. Expected: the vulnerable loader exposure is no longer observed and vendor patch status is confirmed. A changed response alone does not establish full security.",
                        ),
                        (
                            "Network and command access",
                            "Review approved client networks, bind settings and command ACLs. Expected: only intended clients and required commands are allowed. If access exceeds policy: restrict the affected endpoint and least-privilege ACLs; a PING response alone cannot validate Lua-command permissions.",
                        ),
                        (
                            "Service privileges",
                            "Review the service account and runtime/container configuration with the owner. Expected: only the privileges required by the service. If excess privileges are found: reduce them under change control. These privileges were not established by this remote probe.",
                        ),
                    ]
                )
                + "</details>"
            )
        score = scores.get(finding["id"])
        content += paragraph(
            f"{finding.get('tool', 'Scanner')} · {finding.get('port', 'Unknown')}/{finding.get('protocol', 'unknown')}"
            + (
                f" · priority {score.get('risk')} / 100 ({score.get('band', 'Unknown')})"
                if score is not None
                else " · unscored"
            ),
            "finding-strip",
        )
        if score is not None:
            trace = priority_trace(
                score, payload.get("scoring_policy", {}).get("weights") or policy
            )
            content += '<details open class="priority-explanation"><summary>Why this priority? · deterministic arithmetic</summary>'
            content += paragraph(f"Trace: {trace['status']} · {trace['reason']}", "meta")
            content += (
                "<ol>"
                + "".join(
                    "<li>"
                    + facts([(step["label"], step["value"])])
                    + paragraph(step["detail"])
                    + "</li>"
                    for step in trace["steps"]
                )
                + "</ol>"
            )
            content += paragraph(
                "EPSS probability estimates exploitation of this CVE in the wild, not compromise of this host. This policy uses EPSS percentile for its multiplier. A capped 100 does not prove superiority over another ranking method.",
                "notice",
            )
            content += "</details>"
        content += '<details class="finding-technical"><summary>Scanner evidence, score inputs and source record</summary>'
        if score is None:
            content += paragraph("Unscored — severity review required", "notice")
        else:
            content += paragraph(
                f"Recorded priority: {score.get('risk')} / 100 · {score.get('band', 'Unknown')}",
                "priority",
            )
            if missing_severity_basis(score):
                content += paragraph(
                    "Needs severity review: this historical value has no severity basis; not established Low risk.",
                    "notice",
                )
            content += facts(
                [
                    ("CVSS base score", score.get("base_score")),
                    ("Environmental score", score.get("env_score")),
                    ("Native fallback", score.get("native_fallback")),
                    ("Weights hash", score.get("weights_hash")),
                ]
            )
            content += paragraph(score.get("reason"))
            if score.get("fix"):
                content += paragraph("Recorded remediation: " + str(score["fix"]))
        content += facts(
            [
                ("Finding ID", finding["id"]),
                (
                    "Observed endpoint",
                    f"{finding.get('host_ip', 'Unknown')} · {finding.get('port', 'Unknown')}/{finding.get('protocol', 'unknown')}",
                ),
                ("Scanner", finding.get("tool")),
                ("Recorded CVEs", ", ".join(finding.get("cve_ids", [])) or "None recorded"),
                ("Source record", finding.get("provenance", {}).get("record_index")),
            ]
        )
        content += (
            "<h4>Scanner evidence</h4><blockquote>"
            + text(finding.get("evidence"))
            + "</blockquote>"
        )
        content += "</details>"
        content += '<div class="report-guidance"><div><h4>What it indicates</h4>' + paragraph(
            meaning
        )
        content += "</div><div><h4>How to verify</h4>" + paragraph(verify)
        content += "</div><div><h4>Potential improvement</h4>" + paragraph(improve)
        content += "</div></div></article>"
    if not payload.get("findings"):
        content += paragraph(
            "No vulnerability findings were recorded. This does not establish that the target is safe.",
            "notice",
        )
    return content + "</section>"


def _context(payload):
    content = '<section id="context"><h2>Context, services and coverage</h2>'
    profiles = {item.get("host_ip"): item for item in payload.get("context", [])}
    for host in payload.get("hosts", []):
        content += f"<h3>Observed services · {text(host.get('ip'))}</h3>"
        for service in host.get("services", []):
            endpoint = endpoint_context(service, profiles.get(host.get("ip")))
            content += '<article class="endpoint-context">'
            content += f"<h4>{text(service.get('port'))}/{text(service.get('protocol'))} · {text(service.get('product') or service.get('name'))}</h4>"
            content += paragraph(service_evidence_text(service), "meta")
            content += facts(
                [
                    ("Endpoint role candidate", endpoint["role_candidate"].replace("_", " ")),
                    (
                        "TLS at this endpoint",
                        "Observed in scanner metadata"
                        if endpoint["controls"]["tls"]["value"] is True
                        else "Unknown — no positive TLS observation",
                    ),
                    *[
                        (
                            key.replace("_", " "),
                            fact["value"]
                            if fact["value"] is not None
                            else "Unknown at this endpoint",
                        )
                        for key, fact in endpoint["controls"].items()
                        if key != "tls" and fact.get("scope") != "not_applicable"
                    ],
                ]
            )
            irrelevant = [
                key
                for key, value in endpoint["control_relevance"].items()
                if value["value"] is False
            ]
            if irrelevant:
                content += paragraph(
                    "HTTP-oriented signals not applied to this native endpoint: "
                    + ", ".join(irrelevant)
                    + ". Unknown native controls still require verification.",
                    "meta",
                )
            if endpoint["role_candidate"] == "management_interface":
                content += paragraph(
                    "Potential management-interface exposure: the fingerprint does not prove console accessibility or unauthenticated access. Verify the authorized endpoint's response and access policy before classifying a vulnerability.",
                    "notice",
                )
                content += "<h4>Verification guide · not an executed check</h4>" + facts(
                    [
                        (
                            "Observed",
                            "Scanner fingerprint suggests a management HTTP service; product version and access policy may remain unverified.",
                        ),
                        (
                            "Unknown",
                            "Console availability, enforced authentication, network restrictions and intermediary protection.",
                        ),
                        (
                            "Authorized verification",
                            "Review the expected console response and owner-provided access policy. A login page alone does not prove all protected resources enforce authentication. Do not attempt a bypass.",
                        ),
                        (
                            "Decision from outcome",
                            "If reachable beyond the intended management boundary, restrict access with an approved management network or allowlist. If authentication is not enforced on protected resources, investigate and remediate before exposure. If controls are verified, record that evidence rather than retaining an unsupported finding.",
                        ),
                    ]
                )
            content += "</article>"
    for context in payload.get("context", []):
        content += f"<h3>Host-wide aggregate context · {text(context.get('host_ip'))}</h3>"
        content += paragraph(
            "This is the existing aggregate scoring input, not a claim that every endpoint has one role. Per-service role candidates are shown above; mixed-service hosts need owner confirmation.",
            "meta",
        )
        for name, fact in [
            *((key, context[key]) for key in ("role", "exposure") if key in context),
            *context.get("controls", {}).items(),
        ]:
            content += facts(
                [
                    (
                        "Host-aggregate TLS (not every service)"
                        if name == "tls"
                        else name.replace("_", " "),
                        fact.get("value"),
                    ),
                    (
                        "Source / heuristic confidence (not calibrated probability)",
                        f"{fact.get('source', 'unknown')} / {fact.get('confidence', 'unknown')}",
                    ),
                    ("Supporting observation", fact.get("evidence")),
                ]
            )
    content += paragraph(
        "Unknown means not established, not absent. Recorded context is not independently proven network topology or an assertion that a control protects every service.",
        "notice",
    )
    content += "<h3>Scanner coverage as recorded</h3>" + listing(
        [f"{key}: {value}" for key, value in payload.get("scanner_coverage", {}).items()]
    )
    return content + "</section>"


def _claim_text(analysis, path):
    if not isinstance(path, str) or not CLAIM_PATH.fullmatch(path):
        raise LLMUnavailable("Unknown report claim path")
    value = analysis
    for part in path.split("."):
        value = value[int(part)] if isinstance(value, list) else value[part]
    if not isinstance(value, str) or not value.strip() or INJECTION_SENTINEL in value:
        raise LLMUnavailable("Invalid report claim text")
    return value


def _validated_batches(analyst, payload):
    batches = analyst.get("batches") or [analyst]
    if not isinstance(batches, list):
        raise LLMUnavailable("Invalid report batches")
    scores = {row["finding_id"]: row["risk"] for row in payload.get("scores", [])}
    finding_ids = {row["id"] for row in payload.get("findings", [])}
    validated = []
    for batch in batches:
        analysis = batch["analysis"]
        if analysis.get("schema_version") != SCHEMA_VERSION or INJECTION_SENTINEL in str(analysis):
            raise LLMUnavailable("Unknown report analysis schema")
        claims = analysis["claims"]
        prose = {claim["path"]: _claim_text(analysis, claim["path"]) for claim in claims}
        expected = {"summary", "context_effect.explanation"}
        for section, fields in (
            ("recommended_actions", ("action", "reason")),
            ("correlations", ("observation",)),
            ("investigations", ("hypothesis", "verification", "alternative")),
        ):
            for index, item in enumerate(analysis.get(section, [])):
                for field in fields:
                    _claim_text(analysis, f"{section}.{index}.{field}")
                    expected.add(f"{section}.{index}.{field}")
        for index, uncertainty in enumerate(analysis.get("uncertainties", [])):
            # The engine adds a coverage notice after model validation. It is not model prose.
            if not re.fullmatch(
                r"Partial coverage: \d+/\d+ findings included; \d+ services and \d+ intelligence records omitted\.",
                uncertainty,
            ):
                expected.add(f"uncertainties.{index}")
        evidence = batch["evidence"]
        if (
            not isinstance(evidence, list)
            or any(
                not isinstance(item, dict)
                or not isinstance(item.get("id"), str)
                or not isinstance(item.get("text"), str)
                for item in evidence
            )
            or len({item["id"] for item in evidence}) != len(evidence)
        ):
            raise LLMUnavailable("Report evidence index is invalid")
        verify_claims(claims, evidence, finding_ids, scores, expected, prose)
        verify_semantic_claims(claims, evidence, prose)
        validate_control_grounding(
            analysis,
            [service for host in payload.get("hosts", []) for service in host.get("services", [])],
            [
                *prose.values(),
                *[claim["verification_action"] for claim in claims if claim["verification_action"]],
            ],
        )
        retained_case = {
            "services": [
                service for host in payload.get("hosts", []) for service in host.get("services", [])
            ],
            "findings": [
                {
                    **finding,
                    "intelligence": [
                        item
                        for item in payload.get("enrichments", [])
                        if item["finding_id"] == finding["id"]
                    ],
                }
                for finding in payload.get("findings", [])
            ],
            "retained_payload": payload,
        }
        validate_prose_identifiers(
            [
                *prose.values(),
                *[claim["verification_action"] for claim in claims if claim["verification_action"]],
            ],
            retained_case,
            evidence,
        )
        validated.append((batch, prose))
    return validated


def _heading(path):
    if path == "summary":
        return "AI assessment summary"
    if path == "context_effect.explanation":
        return "Why the context matters"
    parts = path.split(".")
    number = int(parts[1]) + 1
    if parts[0] == "recommended_actions":
        return f"Next step {number} · {'what to do' if parts[2] == 'action' else 'why it matters'}"
    if parts[0] == "correlations":
        return f"Related observations · {number}"
    if parts[0] == "uncertainties":
        return f"What remains unknown · {number}"
    label = {
        "hypothesis": "unverified possibility",
        "verification": "how to verify",
        "alternative": "alternative explanation",
    }[parts[2]]
    return f"Investigation {number} · {label}"


def _reading_view(batches, plan):
    index = catalog(batches)

    def source(ref):
        item = index[ref]
        batch, _ = batches[item["batch"] - 1]
        return item, batch["analysis"]

    def citations(item, analysis, paths):
        refs = sorted(
            {
                identity
                for claim in analysis["claims"]
                if claim["path"] in paths
                for identity in claim["evidence_ids"]
            }
        )
        return (
            '<p class="report-citation"><a href="#ai-audit">'
            + text(f"Source: batch {item['batch']} · {', '.join(refs)}")
            + "</a></p>"
        )

    content = f'<div class="ai-reading-view ai-layout-{plan["layout"]}">'
    for ref in plan["executive"]:
        item, analysis = source(ref)
        content += paragraph(analysis["summary"], "ai-executive")
        content += citations(item, analysis, {"summary"})
    headings = {
        "actions": "Recommended actions",
        "context": "Why this context matters",
        "investigations": "Further verification",
        "uncertainties": "Questions still open",
    }
    for kind in plan["section_order"]:
        if not plan[kind]:
            continue
        content += f'<div class="ai-reading-section"><h3>{headings[kind]}</h3>'
        for number, ref in enumerate(plan[kind], 1):
            item, analysis = source(ref)
            offset = item.get("offset")
            if kind == "actions":
                action = analysis["recommended_actions"][offset]
                content += f'<article class="ai-action"><span class="ai-action-number">{number:02d}</span><div><h4>{text(action["action"])}</h4>'
                content += paragraph(action["reason"])
                content += (
                    citations(
                        item,
                        analysis,
                        {
                            f"recommended_actions.{offset}.action",
                            f"recommended_actions.{offset}.reason",
                        },
                    )
                    + "</div></article>"
                )
            elif kind == "context":
                content += paragraph(analysis["context_effect"]["explanation"])
                content += citations(item, analysis, {"context_effect.explanation"})
            elif kind == "investigations":
                investigation = analysis["investigations"][offset]
                content += '<article class="ai-investigation">' + paragraph(
                    "Unverified question", "meta"
                )
                content += paragraph(investigation["hypothesis"])
                content += "<h4>Verification</h4>" + paragraph(investigation["verification"])
                content += "<h4>Alternative explanation</h4>" + paragraph(
                    investigation["alternative"]
                )
                content += (
                    citations(
                        item,
                        analysis,
                        {
                            f"investigations.{offset}.{field}"
                            for field in ("hypothesis", "verification", "alternative")
                        },
                    )
                    + "</article>"
                )
            else:
                content += paragraph(analysis["uncertainties"][offset])
                content += citations(item, analysis, {f"uncertainties.{offset}"})
        content += "</div>"
    return content + "</div>"


def _ai(result, payload, composition=None):
    content = '<section id="ai"><h2>AI explanation and verification plan</h2>'
    status = result.get("ai_status", "not_attempted")
    content += paragraph("Recorded AI status: " + status.replace("_", " "), "meta")
    content += paragraph(
        "Assessment highlights and recommended next steps, with supporting evidence available in the appendix."
    )
    analyst = result.get("analyst")
    if status != "validated" or not isinstance(analyst, dict):
        return (
            content
            + paragraph(
                "Evidence-only report. No validated, retained AI analysis is available. No rejected output is included.",
                "notice",
            )
            + "</section>"
        )
    try:
        batches = _validated_batches(analyst, payload)
    except (LLMUnavailable, KeyError, TypeError, ValueError, IndexError, AttributeError):
        content = content.replace(
            "Recorded AI status: validated",
            "Current report validation: needs review · historical AI status: validated",
        )
        return (
            content
            + paragraph(
                "Needs review: retained AI claim metadata, labels or supporting citations do not pass the current evidence checks. All AI prose is withheld; scan evidence remains available.",
                "notice",
            )
            + "</section>"
        )
    document = composition or analyst.get("report_document")
    if document:
        try:
            plan = validate_document(document, batches)
        except (LLMUnavailable, TypeError, ValueError):
            content += paragraph(
                "AI report composition could not be verified. The validated source analysis is shown using the standard layout.",
                "notice",
            )
            document = None
    if not document:
        sources = catalog(batches)
        plan = {
            "layout": "brief",
            "section_order": ["actions", "context", "investigations", "uncertainties"],
        }
        for kind, limit in (
            ("executive", 1),
            ("context", 1),
            ("actions", 6),
            ("investigations", 2),
            ("uncertainties", 4),
        ):
            seen = set()
            plan[kind] = []
            for ref, item in sources.items():
                normalized = re.sub(r"\W+", " ", item["text"].casefold())
                if item["kind"] == kind and normalized not in seen and len(plan[kind]) < limit:
                    plan[kind].append(ref)
                    seen.add(normalized)
    else:
        content += paragraph(
            f"Report composed by {document['model']} · {plan['layout']} layout · selections checked against validated source claims.",
            "report-composed",
        )
    content += paragraph(
        f"{len(payload.get('findings', []))} recorded observations · {len(batches)} validated analysis batch(es). "
        "Selected assessment highlights follow; the findings section and appendix retain the full record.",
        "meta",
    )
    content += _reading_view(batches, plan)
    content += '<details id="ai-audit" class="report-audit"><summary>Evidence and validation appendix · all source batches</summary>'
    content += paragraph(
        "AI explains retained evidence; it neither authorizes scans nor edits priorities. Model confidence is self-reported, not a measured probability of correctness.",
        "muted",
    )
    content += paragraph(
        "Citations and finding references belong to their batch. Relationships across batches were not assessed. Every displayed AI sentence below has retained claim metadata and content-aligned quotes.",
        "muted",
    )
    for index, (batch, prose) in enumerate(batches, 1):
        content += f"<h3>Batch {index} · {text(batch.get('model', analyst.get('model')))}</h3>"
        for claim in batch["analysis"]["claims"]:
            path = claim["path"]
            content += f"<article><h4>{text(_heading(path))}</h4>" + paragraph(prose[path])
            content += paragraph(
                f"{claim['label']} · model confidence {claim['confidence']} · batch {index} · citations: {', '.join(claim['evidence_ids'])}",
                "meta",
            )
            if claim["finding_ids"]:
                content += paragraph("Finding IDs: " + ", ".join(claim["finding_ids"]), "meta")
            if claim["verification_action"]:
                content += paragraph("Verify: " + claim["verification_action"])
            content += f"<details><summary>Supporting evidence quotes · {len(claim['quotes'])} retained source excerpt(s)</summary>"
            for quote in claim["quotes"]:
                content += f'<blockquote><span class="meta">Batch {index} · {text(quote["evidence_id"])}</span><br>{text(quote["text"])}</blockquote>'
            content += "</details></article>"
    return content + "</details></section>"


def _render(record, *, standalone=False, composition=None, policy=None, decision_focus=None):
    """Caller must use capture_history.load; never render client-submitted report JSON."""
    result, payload = record["result"], record["payload"]
    summary = result["assessment_summary"]
    identity = text(record["capture_id"])
    stylesheet = '<link rel="stylesheet" href="/static/tokens.css"><link rel="stylesheet" href="/static/assessment-report.css">'
    if standalone:
        tokens = re.search(
            r":root\.report-theme\s*\{[^}]*\}",
            CSS_PATH.with_name("tokens.css").read_text(encoding="utf-8"),
        )
        if tokens is None:
            raise ConfigError("Report style tokens are unavailable")
        css = tokens.group(0) + "\n" + CSS_PATH.read_text(encoding="utf-8")
        integrity = base64.b64encode(sha256(css.encode("utf-8")).digest()).decode("ascii")
        csp_policy = f"default-src 'none'; style-src 'sha256-{integrity}'; base-uri 'none'; form-action 'none'"
        stylesheet = f'<meta http-equiv="Content-Security-Policy" content="{escape(csp_policy, quote=True)}"><style>{css}</style>'
    content = '<!doctype html><html lang="en" class="report-theme"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer">'
    content += "<title>VulnAssess · Assessment report</title>" + stylesheet + "</head><body>"
    if not standalone:
        content += f'<nav class="toolbar" aria-label="Report actions"><a href="/captures/{identity}">Evidence &amp; provenance</a><a href="/captures/{identity}/report/download" download="VulnAssess-{identity}.html">Download report · HTML</a><span>Print / save PDF: Ctrl+P or your browser’s Print menu</span></nav>'
    content += (
        '<main><header><p class="eyebrow">VULNASSESS / EVIDENCE-LED ASSESSMENT</p><h1>'
        + (
            "Your device security report"
            if payload.get("self_defence")
            else "Network assessment report"
        )
        + "</h1>"
    )
    content += paragraph(result["target"], "target")
    if reference := record.get("analysis_source"):
        content += paragraph(
            f"Retained-evidence AI reanalysis of {reference['source_capture']}. No new scanner or intelligence refresh was performed. Original scan time is shown below; reanalysis is not a fresh assessment.",
            "notice",
        )
    content += (
        facts(
            [
                ("Collection", result.get("scan_status")),
                ("Captured at", record.get("captured_at")),
                ("Resolved address", result.get("resolved_ip")),
                ("Historical AI status", result.get("ai_status")),
                ("Capture ID", record["capture_id"]),
            ]
        )
        + "</header>"
    )
    content += '<nav class="contents" aria-label="Report sections"><a href="#brief">Brief</a><a href="#practical">What it means</a>'
    if payload.get("self_defence"):
        content += '<a href="#device">Your device</a>'
    content += '<a href="#decisions">Conclusions &amp; decisions</a><a href="#findings">Findings</a><a href="#context">Context &amp; coverage</a><a href="#ai">AI &amp; next steps</a><a href="#provenance">Provenance</a></nav>'
    content += '<section id="brief"><h2>Assessment brief</h2>'
    content += paragraph(
        "Historical, read-only report. Opening or downloading it does not scan, refresh intelligence, contact AI or restore permission to scan.",
        "notice",
    )
    content += paragraph(
        "This is an assessment of bounded observations, not a safety certificate or proof that no vulnerabilities exist."
    )
    if result.get("scan_status") == "partial":
        content += paragraph(
            "Partial scan — requested checks failed. Coverage is incomplete even if AI validated.",
            "notice",
        )
    content += facts(
        [
            (label, len(payload[key]) if key in payload else None)
            for label, key in [
                ("Hosts observed", "hosts"),
                ("Findings recorded", "findings"),
                ("Recorded priorities", "scores"),
            ]
        ]
    )
    content += "<h3>Coverage gaps and unknowns</h3>" + listing(summary.get("coverage_gaps", []))
    content += (
        listing(
            [
                f"{item.get('stage', 'Check')}: {item.get('detail', item.get('reason', 'Failure recorded'))}"
                for item in payload.get("collection_failures", [])
            ],
            "No collection failure list recorded; refer to scanner coverage and collection status.",
        )
        + "</section>"
    )
    content += (
        _device(payload.get("self_defence"))
        + _derivations(record, decision_focus)
        + _ai(result, payload, composition)
        + _practical_assessment(result, payload)
        + _findings(payload, record.get("bounded_protocol_proofs", []), policy)
        + _context(payload)
    )
    content += '<section id="provenance"><h2>Intelligence, integrity and audit trail</h2>'
    content += paragraph(
        "Feed facts are retained snapshots, not a new live lookup. No CVE means CVE enrichment may be not applicable. KEV membership does not prove this host was exploited."
    )
    for name, feed in payload.get("feeds_meta", {}).items():
        content += f"<h3>{text(name)}</h3>" + facts(
            list(feed.items()) if isinstance(feed, dict) else [("Recorded metadata", feed)]
        )
    for row in summary.get("cve_evidence", []):
        content += (
            f"<article><h3>{text(row.get('cve_id'))}</h3>"
            + facts(
                [
                    (key.replace("_", " "), row.get(key))
                    for key in ("finding_id", "cvss_base", "epss", "kev_status", "feed_dates")
                ]
            )
            + "</article>"
        )
    content += "<h3>AI provider attempts</h3>" + listing(
        [
            f"{item.get('provider', 'Unknown')}: {item.get('status', 'Unknown')}"
            for item in result.get("ai_attempts", [])
        ]
    )
    content += facts(
        [
            (key.replace("_", " "), record.get(key))
            for key in (
                "capture_id",
                "configuration_hash",
                "evidence_hash",
                "intelligence_hash",
                "snapshot_hash",
                "intelligence_recorded_at",
                "analysis_attempted_at",
            )
        ]
    )
    if reference := record.get("analysis_source"):
        content += facts(
            [
                ("Reanalysis source snapshot", reference["source_snapshot_hash"]),
                (
                    "Original intelligence recorded at",
                    reference.get("source_intelligence_recorded_at"),
                ),
                ("Reanalysis checkpoint time", record.get("intelligence_recorded_at")),
            ]
        )
    content += paragraph(
        "Hashes check consistency with local receipts, not independent authenticity. Someone able to replace both evidence and hashes can replace the record. Raw scanner files remain unchanged. This report is derived; the saved checkpoint is the source of record.",
        "muted",
    )
    content += "</section><footer>VulnAssess · Observations, deterministic priorities and AI interpretation remain separate.</footer></main></body></html>"
    return content


def render(record, *, standalone=False, composition=None, policy=None, decision_focus=None):
    """Fail closed on unsupported historical shapes; never return a partial report."""
    try:
        return _render(
            record,
            standalone=standalone,
            composition=composition,
            policy=policy,
            decision_focus=decision_focus,
        )
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
        raise ConfigError(
            "Saved assessment report structure is invalid; review required"
        ) from error
