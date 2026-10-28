"""Pure decision cards from a verified capture_history.load record.

Sources are JSON pointers into that record. Observation/action IDs are qualified
by a deterministic card UUID; premise_ids reference only that card's observations.
Scanner text is attributed, never promoted to independently verified evidence.
"""

import json
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from vulnassess.cve_discovery import NOTICE
from vulnassess.finding_assurance import is_redis_lua
from vulnassess.network_policy_facts import observation as policy_observation
from vulnassess.network_service_checks import guidance as policy_guidance
from vulnassess.redis_probe import POSITIVE, REQUEST

MAX_CARDS = 8


def _card(record, kind, finding_ids, identity):
    key = json.dumps([record.get("capture_id"), kind, identity], separators=(",", ":"))
    return {
        "id": "d-" + uuid5(NAMESPACE_URL, key).hex,
        "finding_ids": list(finding_ids),
        "title": "",
        "observations": [],
        "conclusion": {"text": "", "premise_ids": [], "label": "inferred"},
        "significance": "",
        "limits": [],
        "alternatives": [],
        "actions": [],
        "changes_conclusion": [],
        "kind": kind,
    }


def _observe(card, text, source):
    identity = f"{card['id']}:o{len(card['observations']) + 1}"
    card["observations"].append({"id": identity, "text": text, "source": source})
    return identity


def _conclude(card, text, premises):
    card["conclusion"].update(text=text, premise_ids=list(premises))


def _action(card, key, task, expected, if_fail, if_pass, reason, premises):
    card["actions"].append(
        {
            "id": f"{card['id']}:{key}",
            "task": task,
            "expected": expected,
            "if_fail": if_fail,
            "if_pass": if_pass,
            "reason": reason,
            "premise_ids": list(premises),
        }
    )


def _matching_proof(record, finding):
    for index, proof in enumerate(record.get("bounded_protocol_proofs", [])):
        if not isinstance(proof, dict):
            continue
        if (
            proof.get("status") == "verified"
            and proof.get("target_ip")
            == finding.get("host_ip")
            == record["result"].get("resolved_ip")
            and type(proof.get("port")) is int
            and type(finding.get("port")) is int
            and 1 <= proof["port"] <= 65535
            and proof["port"] == finding["port"]
            and proof.get("protocol") == finding.get("protocol") == "tcp"
            and isinstance(proof.get("finding_ids"), list)
            and finding["id"] in proof["finding_ids"]
            and proof.get("request") == REQUEST.decode("ascii")
            and proof.get("response") == POSITIVE.decode("ascii")
        ):
            return index
    return None


def _finding_card(record, index, finding):
    redis = is_redis_lua(finding)
    operation = (
        policy_observation(finding)
        if finding.get("host_ip") == record["result"].get("resolved_ip")
        else None
    )
    card = _card(record, "redis-lua" if redis else "scanner-lead", [finding["id"]], finding["id"])
    source = f"/payload/findings/{index}"
    title = finding.get("title") or "Untitled scanner finding"
    card["title"] = "Redis Lua access and package verification" if redis else title
    endpoint = (
        f"{finding.get('host_ip', 'unknown host')} "
        f"{finding.get('protocol') or 'unknown protocol'}/{finding.get('port') or 'unspecified'}"
    )
    lead = _observe(
        card,
        f"Scanner {finding.get('tool') or 'unspecified'} reports at {endpoint}: {title}",
        source,
    )
    premises = [lead]
    if redis:
        _redis(card, record, finding, premises)
    elif operation:
        _service_policy(card, finding, source, premises, operation)
    else:
        from vulnassess.cve_discovery import candidate_facts

        candidate = (
            candidate_facts(finding)
            if finding.get("host_ip") == record["result"].get("resolved_ip")
            else None
        )
        if candidate:
            _cve_candidate(card, finding, source, premises, candidate)
        else:
            _generic(card, finding, source, premises)
    return card


def _cve_candidate(card, finding, source, premises, candidate):
    card["kind"] = "cve-candidate"
    product = candidate["service"].get("product") or candidate["service"].get("name") or "service"
    premises.append(
        _observe(
            card,
            "Retained service identity and NVD criteria: " + finding["evidence"],
            source + "/evidence",
        )
    )
    _conclude(
        card,
        f"Observed {product} version {candidate['service']['version']} matches an NVD product/version applicability branch for {candidate['cve']}. This is a candidate association, not confirmation of exploitability or package patch state.",
        premises,
    )
    card["significance"] = (
        "Prioritise verification using retained CVSS, EPSS and KEV where available; these describe the associated CVE, not proof that this endpoint was exploited."
    )
    card["limits"] = [
        candidate.get("notice") or NOTICE,
        "No exploit, malformed command, sensitive-data read or host compromise was demonstrated.",
    ]
    card["alternatives"] = [
        "A vendor backport, different package build or disabled feature may make the CVE inapplicable or prevent its prerequisites; obtain owner evidence rather than inferring this from a banner."
    ]
    _action(
        card,
        "verify",
        "Verify package provenance, vendor patch status and the advisory's configuration and access prerequisites.",
        "Owner evidence confirms or excludes this CVE's applicability to the installed package.",
        "If applicability remains unresolved, retain candidate status and apply proportionate containment.",
        "If excluded, close this association with supporting evidence; if applicable, schedule the supported vendor fix.",
        "A product/version match cannot establish installed patch state or exploitation.",
        premises,
    )
    _action(
        card,
        "retest",
        "After an approved fix, repeat the same read-only identity check and compare the applicable CVE range.",
        "The observed version is outside this CVE's affected range and intended clients still work.",
        "If the candidate persists, verify effective deployment and vendor backports; a timeout is inconclusive.",
        "Record bounded closure for this CVE only; a reference patch does not resolve every later CVE.",
        "A comparable retest checks the chosen fix without executing an exploit.",
        premises,
    )
    card["changes_conclusion"] = [
        "Verified installed-package and backport evidence.",
        "Advisory-specific feature/access configuration evidence.",
        "A comparable post-fix service identity and client-functionality check.",
    ]


def _service_policy(card, finding, source, premises, operation):
    """Derive only the typed operation whose raw proof passed canonical checks."""
    guidance = policy_guidance(finding)
    if guidance is None:
        _generic(card, finding, source, premises)
        return
    card["kind"] = "endpoint-policy"
    card["title"] = operation["statement"]
    premises.append(
        _observe(card, "Retained protocol proof: " + finding["evidence"], source + "/evidence")
    )
    _conclude(
        card,
        operation["statement"]
        + " At capture time this contradicted the recorded owner policy for this endpoint.",
        premises,
    )
    card["significance"] = guidance["meaning"]
    card["limits"] = [
        operation["limit"],
        guidance["impact"],
        "This retained exchange does not establish current state, public reachability or CVE applicability.",
    ]
    card["alternatives"] = [
        "The configuration may be intentional for training. That does not remove its conflict with the recorded owner policy; any policy exception needs an explicit owner decision."
    ]
    _action(
        card,
        "change",
        guidance["patch"][0],
        guidance["verify"][0],
        "If the prohibited operation still succeeds, retain the finding and review the effective configuration.",
        "If it is rejected and intended clients still work, record closure of this condition within the retest scope.",
        "The retained operation already demonstrates this specific policy conflict; a generic control question adds no proof.",
        premises,
    )
    _action(
        card,
        "retest",
        "Repeat the same bounded protocol check on the same endpoint after the approved change.",
        guidance["verify"][0],
        "An unavailable service or timeout is inconclusive; investigate availability before claiming remediation.",
        "Retain the before/after responses, unchanged endpoint policy and intended-client comparison.",
        "Comparable positive and negative controls distinguish a resolved violation from a broken service.",
        premises,
    )
    card["changes_conclusion"] = [
        "A comparable endpoint-bound retest that no longer reproduces the prohibited operation, with intended-client access preserved.",
        "An explicitly approved owner-policy change, recorded separately from the observed service behavior.",
    ]


def _redis(card, record, finding, premises):
    proof_index = _matching_proof(record, finding)
    if proof_index is not None:
        premises.append(
            _observe(
                card,
                "Verified fixed EVAL completed on a new connection without an AUTH exchange; "
                "table:function identifies package as a table and package.loadlib as a function.",
                f"/bounded_protocol_proofs/{proof_index}",
            )
        )
        text = (
            "Scripting command execution and a visible native loader justify prompt review of "
            "approved-client containment and Redis native controls. Vendor CVE applicability "
            "is a separate package decision. OS command execution remains untested."
        )
    else:
        text = (
            "The scanner-reported Lua condition warrants containment review and owner package "
            "verification if reproduced. Without matching verified proof, fixed EVAL access, "
            "lack of an AUTH exchange and loader availability are not independently established."
        )
    _conclude(card, text, premises)
    card["significance"] = (
        "If unapproved clients can execute scripting commands while a native loader is exposed, "
        "they may have a route beyond intended Redis data operations into the server process. "
        "Containment review need not wait for vendor-specific CVE applicability."
    )
    card["limits"] = [
        "CVE-2022-0543 is a candidate pending owner verification of distribution, installed "
        "package revision and vendor patches.",
        "RCE untested: no native library loading or OS command execution is established.",
        "Connection evidence does not establish global authentication policy, other command "
        "ACLs or public reachability; a vantage tag alone cannot establish internet access.",
        "Retained evidence describes capture time; current controls require verification.",
    ]
    card["alternatives"] = [
        "Access may be intentional for approved clients on an isolated test service; owner "
        "and network evidence must verify that explanation.",
        "A different or vendor-patched package may make the candidate CVE inapplicable; "
        "that alone does not resolve the reported loader condition.",
    ]
    _action(
        card,
        "containment",
        "Review approved-client network containment and Redis bind, protected-mode, AUTH/ACL "
        "and scripting permissions with the owner.",
        "Document intended clients and effective access from approved review locations.",
        "If unintended access persists, agree scoped restrictions and preserve required clients.",
        "If access matches policy, record its scope; still resolve the loader and package questions.",
        "Resolve who can reach and invoke the reported scripting surface.",
        premises,
    )
    _action(
        card,
        "package",
        "Have the owner verify distribution, installed Redis package revision and vendor patch status.",
        "Package evidence supports or excludes CVE-2022-0543 applicability.",
        "If unresolved or affected, retain candidate status or follow verified vendor remediation.",
        "If excluded, close that CVE association; review the loader condition separately.",
        "The scanner condition cannot identify vendor package applicability.",
        [premises[0]],
    )
    _action(
        card,
        "retest",
        "After an agreed fix, authorize a bounded fixed type-inspection retest on the same endpoint.",
        "Comparable endpoint and approved-client evidence shows whether the condition remains.",
        "If reproduced, reopen the relevant control or package decision; do not escalate to exploitation.",
        "If absent, record bounded closure and verify intended-client operation.",
        "Confirm the chosen change addressed its stated condition.",
        premises,
    )
    card["changes_conclusion"] = [
        "A matching verified fixed exchange would strengthen a scanner-only lead.",
        "Owner package and vendor patch evidence would settle the candidate CVE association.",
        "Approved-client reachability and effective Redis policy evidence would change containment urgency.",
        "A comparable authorized post-fix retest would show whether the condition persists.",
    ]


def _generic(card, finding, source, premises):
    evidence = finding.get("evidence")
    if isinstance(evidence, str) and evidence:
        premises.append(
            _observe(card, "Scanner-reported evidence: " + evidence, source + "/evidence")
        )
    _conclude(
        card,
        "This retained scanner lead supports owner verification of the reported condition. "
        "Impact, exploitability and the need for a change depend on confirmation in its actual context.",
        premises,
    )
    card["significance"] = (
        "Use the reported condition to choose a bounded verification decision; "
        "no additional attack path or service relationship is established."
    )
    card["limits"] = [
        "Scanner attribution is not independent confirmation of impact or exploitation.",
        "Any scanner-named CVE remains a candidate until applicability is verified.",
        "Current state and public reachability are not established by this lead or a vantage tag.",
    ]
    card["alternatives"] = [
        "The result may be a false positive or intended service behavior; owner review "
        "and a scoped reproduction can distinguish these possibilities."
    ]
    _action(
        card,
        "verify",
        "Ask the service owner to verify the exact reported condition and applicability.",
        "A documented reproduction or evidence explaining the scanner result.",
        "If unresolved, retain the lead and request the missing evidence.",
        "If confirmed, agree a scoped fix; if disproved, document why the lead is closed.",
        "A scanner lead needs context before choosing a change.",
        premises,
    )
    _action(
        card,
        "retest",
        "After any agreed fix, authorize a bounded retest of this reported condition.",
        "Comparable evidence for the same service and finding.",
        "If the condition remains, return to the owner for review.",
        "If absent, record closure within the retest scope and check intended behavior.",
        "A targeted retest checks the decision without inventing an exploit claim.",
        premises,
    )
    card["changes_conclusion"] = [
        "Owner evidence confirming or disproving the exact scanner observation.",
        "Applicable package/configuration evidence and a comparable authorized post-fix retest.",
    ]


def _no_findings(record):
    card = _card(record, "service-verification", [], "no-findings")
    card["title"] = "Service and management access verification"
    premises = [_observe(card, "No findings are retained in this capture.", "/payload")]
    services = record["result"].get("services")
    service_source = "/result/services"
    for index, host in enumerate(record["payload"].get("hosts", [])):
        if host.get("ip") == record["result"].get("resolved_ip"):
            if isinstance(host.get("services"), list):
                services = host["services"]
                service_source = f"/payload/hosts/{index}/services"
            break
    if isinstance(services, list):
        premises.append(_observe(card, f"Retained service count: {len(services)}.", service_source))
    _conclude(
        card,
        "Absence of retained findings supports service and management-access verification, "
        "not a secure verdict. Coverage and intended access still require owner review.",
        premises,
    )
    card["significance"] = (
        "Visible services and management access need an intended purpose and owner."
    )
    card["limits"] = [
        "Zero retained findings do not demonstrate complete testing or absence of vulnerabilities.",
        "Control presence, current state and public reachability remain unestablished.",
    ]
    card["alternatives"] = [
        "The captured services may be intentionally configured and restricted to approved clients; "
        "that benign explanation requires owner and access evidence."
    ]
    _action(
        card,
        "verify",
        "Have owners verify service purpose, management interfaces and approved-client access.",
        "An owned inventory and documented intended access compared with effective access.",
        "If unexpected access or services appear, agree a scoped containment review.",
        "If matched, record verified scope and remaining coverage gaps.",
        "An empty finding list leaves management-access decisions unresolved.",
        premises,
    )
    _action(
        card,
        "retest",
        "Agree missing coverage and authorize bounded verification after any control change.",
        "Evidence for the agreed services and access paths.",
        "If incomplete or unexpected, retain the gap for owner review.",
        "If satisfied, close only the verified service/access questions.",
        "Verification should address identified gaps and changes.",
        premises,
    )
    card["changes_conclusion"] = [
        "Owner service inventory, effective management-access evidence and explicit scanner coverage.",
        "New findings or comparable authorized verification after a change.",
    ]
    return card


def _coverage(record, omitted):
    card = _card(record, "coverage", [f["id"] for _, f in omitted], "coverage")
    card["title"] = "Remaining findings require individual review"
    premise = _observe(
        card,
        f"{len(omitted)} retained findings have no individual decision card.",
        "/payload/findings",
    )
    _conclude(
        card,
        "The remaining findings require review before claiming complete decision coverage.",
        [premise],
    )
    card["significance"] = "The display limit must not hide unresolved scanner leads."
    card["limits"] = [
        "This aggregate declares coverage; it does not assess the remaining findings."
    ]
    card["alternatives"] = [
        "Some remaining leads may be benign or duplicates; individual review must establish that."
    ]
    _action(
        card,
        "review",
        "Review the listed remaining finding IDs individually with their owners.",
        "Each lead has an evidence-bound decision.",
        "If incomplete, retain the coverage gap.",
        "If complete, record each decision and its supporting evidence.",
        "Unreviewed leads cannot be treated as resolved.",
        [premise],
    )
    _action(
        card,
        "verify",
        "Agree bounded verification for remaining leads that require more evidence.",
        "An approved scope tied to the unresolved finding IDs.",
        "If evidence is unavailable, retain uncertainty.",
        "If obtained, reassess only supported conclusions.",
        "Missing individual decisions require evidence before closure.",
        [premise],
    )
    card["changes_conclusion"] = [
        "Individual owner review and verification of the listed remaining findings."
    ]
    return card


def derive(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Return at most eight cards without I/O, model calls or mutation.

    Findings sort by descending recorded risk, with finding ID breaking ties and
    unscored findings last. Over eight findings, seven receive individual cards and
    the last card names every omitted ID. Every card declares individual-card
    coverage in limits; finding_ids on coverage are unassessed.
    """
    findings = record["payload"].get("findings", [])
    scores = {score["finding_id"]: score["risk"] for score in record["payload"].get("scores", [])}
    ordered = sorted(
        enumerate(findings),
        key=lambda item: (
            item[1]["id"] not in scores,
            -scores.get(item[1]["id"], 0),
            item[1]["id"],
        ),
    )
    selected = ordered[: MAX_CARDS if len(ordered) <= MAX_CARDS else MAX_CARDS - 1]
    cards = [_finding_card(record, index, finding) for index, finding in selected]
    if not cards:
        cards = [_no_findings(record)]
    elif len(selected) < len(ordered):
        cards.append(_coverage(record, ordered[len(selected) :]))
    coverage = (
        f"Decision coverage: {len(selected)} of {len(findings)} retained findings have individual "
        f"cards; {len(findings) - len(selected)} remain without individual assessment. "
        "This is not a statement of scanner completeness."
    )
    for card in cards:
        card["limits"].append(coverage)
    return cards
