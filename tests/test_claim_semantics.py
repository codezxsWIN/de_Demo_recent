"""Offline adversarial tests for the deliberately bounded semantic guard."""

import copy
import json

import pytest

from vulnassess.claim_semantics import verify_semantic_claims
from vulnassess.errors import LLMUnavailable


def test_remediation_is_not_a_benign_alternative_explanation():
    with pytest.raises(LLMUnavailable, match="alternative is an action"):
        verify_semantic_claims(
            [{"path": "investigations.0.alternative", "label": "inferred", "evidence_ids": ["E1"]}],
            [{"id": "E1", "text": "6379/tcp Redis service"}],
            {
                "investigations.0.alternative": "Restrict network access to Redis via firewall rules."
            },
        )


PLAIN = {"id": "E1", "kind": "nmap_service", "text": "80 tcp http nginx; 443 tcp http"}
TUNNEL = {"id": "E2", "kind": "nmap_service", "text": "port 81 tcp http tunnel=ssl"}
UNKNOWN = {"id": "E3", "kind": "context_tls", "text": "none observed; TLS status unknown"}
NEGATIVE = {"id": "E4", "kind": "tls_probe", "text": "port 80 tls_test=negative"}
REDIRECT = {
    "id": "E5",
    "kind": "http_head",
    "text": "port 80 HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.test:8443/",
}
COOCCURRENCE = {"id": "E6", "kind": "nmap_service", "text": "80 tcp nginx; 7001 tcp WebLogic"}


def check(text, evidence=(), *, ids=None, path="summary", label="observed"):
    claim = {
        "path": path,
        "label": label,
        "evidence_ids": ids if ids is not None else [item["id"] for item in evidence],
        "quotes": [{"evidence_id": item["id"], "text": item["text"]} for item in evidence],
        "finding_ids": [],
        "confidence": 0.8,
        "score": None,
        "verification_action": "Check supplied capture" if label == "hypothesis" else None,
    }
    return verify_semantic_claims([claim], list(evidence), {path: text})


def test_verified_fixture_login_bypass_is_not_proxy_topology():
    proof = {
        "id": "E1",
        "kind": "harbordesk_finding",
        "text": json.dumps(
            {
                "id": "HD-03",
                "observed_intentional_weakness": True,
                "evidence": {
                    "normal_wrong_password_status": 401,
                    "injected_fixture_login_status": 200,
                },
            }
        ),
    }
    assert check("A login bypass was reproduced in the local fixture.", [proof]) is None
    assert check("SQL injection bypasses authentication in the local fixture.", [proof]) is None
    for text in (
        "WebLogic bypasses nginx.",
        "The firewall was bypassed.",
        "An object authorization bypass was reproduced.",
    ):
        with pytest.raises(LLMUnavailable, match="bypass topology"):
            check(text, [proof])
    with pytest.raises(LLMUnavailable, match="bypass topology"):
        check("A login bypass was reproduced.", [{**proof, "kind": "nmap_service"}])
    proof["text"] = json.dumps(
        {"id": "HD-03", "observed_intentional_weakness": False, "evidence": {}}
    )
    with pytest.raises(LLMUnavailable, match="bypass topology"):
        check("A login bypass was reproduced.", [proof])


def test_fixture_protocol_proofs_support_only_their_fixed_endpoints():
    ftp = {
        "id": "E1",
        "kind": "harbordesk_finding",
        "text": json.dumps(
            {
                "id": "HD-14",
                "observed_intentional_weakness": True,
                "evidence": {"protocol": "FTP", "tls_negotiated": False},
            }
        ),
    }
    tls = {
        "id": "E2",
        "kind": "harbordesk_finding",
        "text": json.dumps(
            {
                "id": "HD-15",
                "observed_intentional_weakness": True,
                "evidence": {"tls_version": "TLSv1.3", "certificate_expired": True},
            }
        ),
    }
    assert check("FTP on port 2121 uses unencrypted transport.", [ftp]) is None
    assert check("Port 8443 uses TLS.", [tls]) is None
    for sentence, evidence in [
        ("Port 8787 uses unencrypted transport.", ftp),
        ("Port 8787 uses TLS.", tls),
    ]:
        with pytest.raises(LLMUnavailable, match="TLS assertion"):
            check(sentence, [evidence])


@pytest.mark.parametrize(
    "text",
    [
        "TLS=true on port 81.",
        "Port 81 has TLS enabled.",
        "Port 81 uses encrypted transport.",
        "TLS-enabled ports 81 were observed.",
        "81/tcp supports TLS.",
    ],
)
def test_tls_tunnel_supports_only_its_port(text):
    assert check(text, [TUNNEL]) is None


@pytest.mark.parametrize(
    "text",
    [
        "TLS=true on port 443.",
        "Port 443 has TLS enabled.",
        "Ports 81 and 443 have encrypted transport.",
        "Verify whether TLS-enabled ports 81 and 443 redirect.",
        "Verify whether TLS=true on port 443 explains the behavior.",
    ],
)
def test_tls_port_81_cannot_support_443_even_inside_questions(text):
    with pytest.raises(LLMUnavailable, match="TLS.*443"):
        check(text, [PLAIN, TUNNEL, UNKNOWN], label="hypothesis")


@pytest.mark.parametrize(
    "text",
    [
        "TLS=true.",
        "TLS is enabled.",
        "Encrypted transport is available.",
        "TLS=false.",
        "Port 80 has no TLS.",
        "The service lacks TLS.",
        "Transport is unencrypted.",
        "Verify whether TLS=false explains the result.",
    ],
)
def test_no_port_heuristic_or_missing_metadata_can_support_tls(text):
    with pytest.raises(LLMUnavailable, match="TLS"):
        check(text, [PLAIN, UNKNOWN])


@pytest.mark.parametrize(
    "text",
    [
        "Verify whether TLS is configured.",
        "Verify whether TLS is enabled on port 443.",
        "Is TLS enabled on port 443?",
        "TLS status is unknown.",
        "TLS=false is not established.",
        "No TLS configuration evidence was retained.",
        "TLS is enabled remains unverified.",
        "Whether TLS is configured is unknown.",
        "WAF and authentication controls are unknown; TLS was not established by this scan.",
    ],
)
def test_procedural_questions_and_explicit_unknown_wording_are_allowed(text):
    assert check(text, [PLAIN, UNKNOWN], label="unknown") is None


@pytest.mark.parametrize(
    "text",
    [
        "TLS status is unknown; TLS=false.",
        "Verify whether TLS is configured; port 443 has TLS enabled.",
        "Verify whether port 80 redirects, because TLS=false.",
        "TLS is enabled, but redirects remain unknown.",
        "TLS=false, and verify whether port 80 redirects.",
    ],
)
def test_unknown_or_question_clause_does_not_excuse_another_fact(text):
    with pytest.raises(LLMUnavailable, match="TLS"):
        check(text, [PLAIN, UNKNOWN], label="unknown")


@pytest.mark.parametrize(
    "observation",
    [
        "port 81 tunnel=ssl",
        "81/tcp tls=observed",
        "port 81 TLS handshake succeeded",
        "port 81 negotiated TLSv1.3",
    ],
)
def test_explicit_tls_observations(observation):
    assert (
        check(
            "Port 81 has TLS enabled.",
            [
                {"id": "E1", "kind": "tls_inspect", "text": observation},
            ],
        )
        is None
    )


@pytest.mark.parametrize(
    "observation",
    [
        "port 443 https",
        "port 443 tls=true",
        "port 443 TLS handshake failed",
        "port 443 TLS handshake timed out",
        "port 443 tunnel=ssl not observed",
        "Verify whether port 443 tunnel=ssl",
        "port 443 not tunnel=ssl",
    ],
)
def test_guesses_booleans_failed_handshakes_and_proposals_are_not_tls_observations(observation):
    with pytest.raises(LLMUnavailable, match="TLS"):
        check(
            "Port 443 has TLS enabled.",
            [
                {"id": "E1", "kind": "nmap_service", "text": observation},
            ],
        )


def test_retained_tls_boolean_is_not_cited_text_and_quotes_are_not_observations():
    old_capture = {**PLAIN, "tls": True, "port": 443}
    with pytest.raises(LLMUnavailable, match="TLS"):
        verify_semantic_claims(
            [
                {
                    "path": "summary",
                    "label": "observed",
                    "evidence_ids": ["E1"],
                    "quotes": [{"evidence_id": "E1", "text": "port 443 tunnel=ssl"}],
                }
            ],
            [old_capture],
            {"summary": "Port 443 has TLS enabled."},
        )


def test_uncited_tls_observation_is_not_support():
    with pytest.raises(LLMUnavailable, match="TLS"):
        check("Port 81 has TLS enabled.", [PLAIN, TUNNEL], ids=["E1"])


@pytest.mark.parametrize("separator", ["; ", "\n", ", "])
def test_aggregate_record_cannot_lend_tls_to_another_port(separator):
    aggregate = {
        "id": "E1",
        "kind": "context_tls",
        "text": "port 81 tunnel=ssl" + separator + "port 443 http",
    }
    assert check("TLS=true on port 81.", [aggregate]) is None
    with pytest.raises(LLMUnavailable, match="TLS.*443"):
        check("TLS=true on port 443.", [aggregate])


def test_each_asserted_tls_port_needs_its_own_cited_observation():
    second = {"id": "E7", "kind": "tls_inspect", "text": "port 443 TLS handshake completed"}
    assert check("Ports 81 and 443 have TLS enabled.", [TUNNEL, second]) is None
    with pytest.raises(LLMUnavailable, match="443"):
        check("Ports 81 and 443 have TLS enabled.", [TUNNEL, second], ids=["E2"])


def test_explicit_negative_test_and_positive_test_are_not_interchangeable():
    assert check("Port 80 has no TLS.", [NEGATIVE]) is None
    assert check("TLS=false on port 80.", [NEGATIVE]) is None
    with pytest.raises(LLMUnavailable, match="TLS"):
        check("TLS=true on port 80.", [NEGATIVE])
    with pytest.raises(LLMUnavailable, match="negative TLS"):
        check("TLS=false on port 81.", [TUNNEL])
    with pytest.raises(LLMUnavailable, match="443"):
        check("TLS=false on port 443.", [NEGATIVE])


@pytest.mark.parametrize(
    "text",
    [
        "Port 80 redirects.",
        "Port 80 redirects to HTTPS.",
        "Port 80 redirects to https://example.test:8443/.",
    ],
)
def test_genuine_http_redirect_response(text):
    assert check(text, [REDIRECT]) is None


@pytest.mark.parametrize(
    "evidence",
    [
        [PLAIN],
        [TUNNEL],
        [UNKNOWN],
        [{"id": "E1", "kind": "http_head", "text": "port 80 HTTP/1.1 200 OK"}],
        [{"id": "E1", "kind": "http_head", "text": "port 80 HTTP/1.1 304 Not Modified"}],
        [{"id": "E1", "kind": "http_head", "text": "port 80 HTTP/1.1 201 Created; Location: /new"}],
        [
            {
                "id": "E1",
                "kind": "probe_option",
                "text": "port 80 status=301 Location: https://example.test/",
            }
        ],
    ],
)
def test_speculative_redirects_need_response_evidence(evidence):
    with pytest.raises(LLMUnavailable, match="redirect"):
        check("Port 80 redirects to HTTPS.", evidence)


def test_redirect_questions_are_allowed_but_not_neighboring_assertions():
    assert check("Verify whether port 80 redirects to HTTPS.", [PLAIN], label="inferred") is None
    with pytest.raises(LLMUnavailable, match="redirect"):
        check("Verify whether TLS is configured; port 80 redirects.", [TUNNEL])
    with pytest.raises(LLMUnavailable, match="TLS"):
        check("Do TLS-enabled ports 443 redirect?", [PLAIN], label="hypothesis")


def test_redirect_response_is_bound_to_listener_and_destination():
    with pytest.raises(LLMUnavailable, match="redirect.*443"):
        check("Port 443 redirects.", [REDIRECT])
    with pytest.raises(LLMUnavailable, match="redirect.*8443"):
        check("Port 8443 redirects.", [REDIRECT])
    with pytest.raises(LLMUnavailable, match="redirect"):
        check("Port 80 redirects to HTTP.", [REDIRECT])
    with pytest.raises(LLMUnavailable, match="redirect"):
        check("Port 80 redirects to https://other.test/.", [REDIRECT])


@pytest.mark.parametrize(
    "text",
    [
        "nginx is a reverse proxy for WebLogic.",
        "WebLogic is behind nginx.",
        "nginx fronts WebLogic.",
        "WebLogic bypasses nginx.",
        "nginx proxies to WebLogic.",
    ],
)
@pytest.mark.parametrize("label", ["observed", "inferred", "hypothesis", "unknown"])
def test_fingerprint_cooccurrence_does_not_observe_topology(text, label):
    with pytest.raises(LLMUnavailable, match="topology"):
        check(text, [COOCCURRENCE], path="investigations.0.hypothesis", label=label)


@pytest.mark.parametrize(
    "text",
    [
        "Verify whether nginx is a reverse proxy for WebLogic.",
        "Could WebLogic bypass nginx?",
        "nginx may be a reverse proxy for WebLogic.",
        "WebLogic might bypass nginx.",
    ],
)
def test_testable_topology_hypotheses_are_permitted(text):
    assert (
        check(text, [COOCCURRENCE], path="investigations.0.hypothesis", label="hypothesis") is None
    )


def test_unknown_auth_possibility_is_permitted_as_hypothesis():
    assert (
        check(
            "Authentication may be absent; verify whether it is required.",
            [UNKNOWN],
            path="investigations.0.hypothesis",
            label="hypothesis",
        )
        is None
    )


def test_actual_topology_evidence_and_bypass_evidence_are_distinct():
    proxy = {
        "id": "E1",
        "kind": "configuration_observation",
        "text": "nginx reverse_proxy=observed; proxy_pass http://weblogic:7001",
    }
    assert check("nginx is a reverse proxy for WebLogic.", [proxy]) is None
    with pytest.raises(LLMUnavailable, match="bypass"):
        check("WebLogic bypasses nginx.", [proxy])
    bypass = {"id": "E2", "kind": "bypass_test", "text": "WebLogic bypass=observed"}
    assert check("WebLogic bypasses nginx.", [bypass]) is None


@pytest.mark.parametrize(
    "path",
    [
        "recommended_actions.0.action",
        "recommended_actions.12.action",
        "investigations.0.verification",
        "investigations.1.alternative",
        "uncertainties.0",
    ],
)
def test_observed_label_rejected_for_procedural_and_uncertainty_fields(path):
    with pytest.raises(LLMUnavailable, match="observed label.*" + path.replace(".", r"\.")):
        check("Verify whether TLS is configured.", [UNKNOWN], path=path)
    assert (
        check("Verify whether TLS is configured.", [UNKNOWN], path=path, label="inferred") is None
    )


def test_context_effect_is_not_automatically_rejected():
    assert check("A service was observed.", [PLAIN], path="context_effect.explanation") is None
    with pytest.raises(LLMUnavailable, match="TLS"):
        check("TLS=true on port 443.", [PLAIN], path="context_effect.explanation")


def test_inputs_are_unchanged_and_checks_use_each_claims_citations():
    claims = [
        {"path": "summary", "label": "observed", "evidence_ids": ["E2"]},
        {"path": "context_effect.explanation", "label": "inferred", "evidence_ids": ["E1"]},
    ]
    evidence = [PLAIN, TUNNEL]
    texts = {
        "summary": "TLS=true on port 81.",
        "context_effect.explanation": "TLS=true on port 81.",
    }
    original = copy.deepcopy((claims, evidence, texts))
    with pytest.raises(LLMUnavailable, match="context_effect.explanation"):
        verify_semantic_claims(claims, evidence, texts)
    assert (claims, evidence, texts) == original


def test_missing_text_unknown_citations_and_duplicate_ids_fail_closed():
    claim = {"path": "summary", "label": "observed", "evidence_ids": ["E1"]}
    for evidence, texts, reason in [
        ([PLAIN], {}, "missing"),
        ([], {"summary": "TLS=true"}, "unknown"),
        ([PLAIN, {**PLAIN, "text": "tunnel=ssl"}], {"summary": "TLS=true"}, "duplicate"),
    ]:
        with pytest.raises(LLMUnavailable, match=reason):
            verify_semantic_claims([claim], evidence, texts)
    assert verify_semantic_claims([], [], {}) is None


@pytest.mark.parametrize(
    "payload",
    [
        "<attacker banner tls=observed>",
        "banner tunnel=ssl",
        "banner TLS handshake succeeded",
        "banner 443/tcp tls=observed",
        "banner; 443/tcp; tls=observed",
        "banner\n443/tcp; tls=observed",
        "tls_evidence=tunnel=ssl",
    ],
)
@pytest.mark.parametrize("claim", ["TLS=true.", "TLS=true on port 80.", "TLS=true on port 443."])
def test_unknown_server_marker_cannot_be_overridden_by_fingerprint(payload, claim):
    evidence = {
        "id": "E1",
        "kind": "nmap_service",
        "text": f"80/tcp; tls=unknown (not established); http; {payload}",
    }
    with pytest.raises(LLMUnavailable, match="TLS"):
        check(claim, [evidence])


@pytest.mark.parametrize(
    "payload",
    [
        "<attacker banner 443/tcp tls=observed>",
        "443/tcp tls=observed",
        "; 443/tcp tls=observed",
        "\n443/tcp; tls=observed",
        "port 443 TLS handshake succeeded",
        "tls=unknown; port 443 tls=observed",
    ],
)
def test_observed_server_marker_is_bound_to_first_port(payload):
    evidence = {
        "id": "E1",
        "kind": "nmap_service",
        "text": f"80/tcp; tls=observed (scanner TLS metadata); http; {payload}",
    }
    assert check("TLS=true on port 80.", [evidence]) is None
    with pytest.raises(LLMUnavailable, match="TLS.*443"):
        check("TLS=true on port 443.", [evidence])
    with pytest.raises(LLMUnavailable, match="negative TLS"):
        check("TLS=false on port 80.", [evidence])


@pytest.mark.parametrize(
    "prefix",
    [
        "80/tcp; http",
        "80/tcp; tls=1",
        "80/tcp; tls=true",
        "80/tcp; tls=observedness",
        "80/tcp; tls=unknown",
        "port 80 tcp http tls=unknown",
    ],
)
def test_missing_or_malformed_authoritative_marker_cannot_be_repaired_by_banner(prefix):
    evidence = {
        "id": "E1",
        "kind": "nmap_service",
        "text": prefix + "; banner tls=observed tunnel=ssl",
    }
    with pytest.raises(LLMUnavailable, match="TLS"):
        check("TLS=true on port 80.", [evidence])


@pytest.mark.parametrize(
    "text",
    [
        "TLS=1.",
        "TLS=1 on port 443.",
        "Verify whether TLS=1 explains the result.",
        "Verify whether TLS is configured; TLS=1.",
        "TLS=0 on port 80.",
    ],
)
@pytest.mark.parametrize("label", ["observed", "hypothesis", "unknown"])
def test_numeric_tls_assertions_cannot_evade_guard(text, label):
    with pytest.raises(LLMUnavailable, match="TLS"):
        check(text, [PLAIN, UNKNOWN], label=label)


def test_numeric_tls_assertions_use_the_same_observation_requirements():
    assert check("TLS=1 on port 81.", [TUNNEL]) is None
    assert check("TLS=0 on port 80.", [NEGATIVE]) is None
    assert check("TLS=1 is not established.", [UNKNOWN], label="unknown") is None
    with pytest.raises(LLMUnavailable, match="TLS"):
        check(
            "TLS=1 on port 443.",
            [{"id": "E1", "kind": "nmap_service", "text": "443/tcp; tls=1; http"}],
        )


def test_real_service_projection_keeps_first_tls_marker_authoritative():
    from vulnassess.service_context import service_evidence_text

    for tls in (False, True):
        text = service_evidence_text(
            {
                "port": 80,
                "protocol": "tcp",
                "name": "http",
                "tls": tls,
                "banner": "<attacker banner; 443/tcp tls=observed tunnel=ssl>",
            }
        )
        evidence = {"id": "E1", "kind": "nmap_service", "text": text}
        if tls:
            assert check("TLS=true on port 80.", [evidence]) is None
        else:
            with pytest.raises(LLMUnavailable, match="TLS"):
                check("TLS=true on port 80.", [evidence])
        with pytest.raises(LLMUnavailable, match="TLS"):
            check("TLS=true on port 443.", [evidence])
