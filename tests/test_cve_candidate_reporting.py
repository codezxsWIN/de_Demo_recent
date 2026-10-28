"""Candidate status, bounded RESP parsing and read-only lab views."""

import copy
import json

import pytest

from tests.test_claim_semantics import check
from tests.test_cve_discovery import TARGET, nvd_entry, page, service
from vulnassess import cve_discovery, redis_identity
from vulnassess.assessment_derivations import derive
from vulnassess.errors import LLMUnavailable
from vulnassess.finding_assurance import assurance
from vulnassess.schema import Host
from vulnassess.store import Store
from vulnassess.ui import cve_lab
from vulnassess.ui.assessment_report import _finding_guidance


@pytest.mark.parametrize("extra", ["", "x" * 5000])
def test_serialized_candidate_evidence_never_truncates_unicode_or_oversized_criteria(
    tmp_path, extra
):
    from tests.test_cve_discovery import configurations, criterion
    from vulnassess.schema import EVIDENCE_MAX

    observed = service(name="界" * 60, product="界" * 80)
    match = criterion(matchCriteriaId=extra)
    findings, receipt = cve_discovery.discover(
        Host(TARGET, services=(observed,)),
        tmp_path,
        None,
        fetch=lambda *_: page(nvd_entry(configs=configurations(match))),
        sleep=lambda _: None,
    )
    if extra:
        assert findings == []
        assert "serialized evidence budget" in receipt["queries"][0]["decisions"][-1]["reason"]
    else:
        assert len(findings) == 1
        assert len(findings[0].evidence) <= EVIDENCE_MAX
        assert cve_discovery.candidate_facts(findings[0], observed)


EVIDENCE = [
    {
        "id": "E1",
        "kind": "nvd-cpe_finding",
        "text": "Product/version candidate; patch state unverified",
    }
]


def test_discovery_to_targeted_lookup_preserves_nvd_pacing(monkeypatch, tmp_path):
    from vulnassess import live_assessment

    clock, requests = [0], []
    monkeypatch.setattr(
        live_assessment.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds)
    )
    services = tuple(
        service(cpe=f"cpe:2.3:a:vendor:product{i}:7.0.5:*:*:*:*:*:*:*") for i in range(4)
    )

    def fetch(*_):
        requests.append(clock[0])
        return page()

    with Store(tmp_path / "intel-cache.db") as cache:
        _, receipt = cve_discovery.discover(
            Host(TARGET, services=services),
            tmp_path,
            cache,
            fetch=fetch,
            sleep=live_assessment.time.sleep,
        )
        live_assessment._pace_nvd_handoff(cache, ["CVE-2026-12345"], receipt["queries"])
        requests.append(clock[0])
        live_assessment.time.sleep(7)  # sync_cves's spacing between targeted NVD requests
        requests.append(clock[0])
        assert requests == [0, 7, 14, 21, 28, 35]
        for start in requests:
            assert sum(start <= value < start + 30 for value in requests) <= 5
        cache.put_cves(
            [
                {
                    "id": "CVE-2026-12345",
                    "_fetched_at": live_assessment.datetime.now(live_assessment.UTC).isoformat(),
                }
            ]
        )
        live_assessment._pace_nvd_handoff(cache, ["CVE-2026-12345"], True)
        assert clock[0] == 35  # no NVD request means no unnecessary delay
        live_assessment._pace_nvd_handoff(cache, ["CVE-2026-99999"], False)
        assert clock[0] == 35


@pytest.mark.parametrize(
    "text",
    [
        "The Redis host is confirmed vulnerable to CVE-2026-12345.",
        "CVE-2026-12345 is proven on the host.",
        "The Redis service is vulnerable to CVE-2026-12345.",
        "Remote code execution was demonstrated.",
        "The service may be vulnerable to the CVE but compromise is confirmed.",
    ],
)
def test_candidate_does_not_support_confirmed_or_unqualified_vulnerability(text):
    with pytest.raises(LLMUnavailable, match="product-version"):
        check(text, EVIDENCE)


@pytest.mark.parametrize(
    "text",
    [
        "Redis may be vulnerable to the associated CVE; package applicability remains unverified.",
        "The service might be vulnerable to the candidate CVE.",
        "The vulnerability is not confirmed.",
        "Verify whether the package is vulnerable to the associated CVE.",
        "The observed upstream version matches a candidate affected-product range.",
    ],
)
def test_candidate_qualifiers_and_neutral_verification_stay_available(text):
    check(text, EVIDENCE, label="inferred")


def fake_wire(monkeypatch, response, *, fragment=1):
    class Wire:
        def __init__(self):
            self.data = bytearray(response)
            self.sent = []

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def settimeout(self, value):
            assert 0 < value <= 4

        def sendall(self, data):
            self.sent.append(data)

        def recv(self, size):
            data = bytes(self.data[: min(size, fragment)])
            del self.data[: len(data)]
            return data

    wire = Wire()
    monkeypatch.setattr(redis_identity.socket, "create_connection", lambda *_args, **_kwargs: wire)
    return wire


def test_fragmented_info_retains_only_version_and_hash(monkeypatch):
    body = b"# Server\r\nredis_version:7.0.11\r\nos:private-host-metadata\r\n"
    wire = fake_wire(monkeypatch, b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n")
    proof = redis_identity.probe("192.0.2.41", {"port": 16379})
    assert proof["redis_version"] == "7.0.11" and proof["data_keys_read"] is False
    assert "private-host" not in json.dumps(proof)
    assert wire.sent == [b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"]


@pytest.mark.parametrize(
    "reply",
    [
        b"$16385\r\n",
        b"+PONG\r\n",
        b"$10\r\nshort",
        b"$0\r\n\r\n",
        b"A" * 128,
        b"$5\r\nabcdeZZ",
    ],
)
def test_invalid_or_unbounded_redis_identity_is_rejected(monkeypatch, reply):
    fake_wire(monkeypatch, reply)
    with pytest.raises(ValueError):
        redis_identity.probe("192.0.2.41", {"port": 16379})


@pytest.mark.parametrize(
    "body", [b"os:dummy\r\n", b"redis_version:7.0.11\r\nredis_version:7.0.12\r\n"]
)
def test_missing_or_contradictory_redis_version_is_not_guessed(monkeypatch, body):
    fake_wire(monkeypatch, b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n")
    with pytest.raises(ValueError, match="unambiguous"):
        redis_identity.probe("192.0.2.41", {"port": 16379})


def test_denied_info_does_not_supply_an_invented_version(monkeypatch):
    fake_wire(monkeypatch, b"-NOPERM this user cannot run INFO\r\n")
    result = redis_identity.probe("192.0.2.41", {"port": 16379})
    assert result["identity_established"] is False and "redis_version" not in result


def test_identity_has_an_absolute_deadline_even_with_a_live_connection(monkeypatch):
    fake_wire(monkeypatch, b"$100\r\n")
    times = iter([0, 5])
    monkeypatch.setattr(redis_identity.time, "monotonic", lambda: next(times))
    with pytest.raises(TimeoutError):
        redis_identity.probe("192.0.2.41", {"port": 16379})


def test_derived_candidate_guidance_and_empty_view_do_not_claim_exploitation(tmp_path):
    with Store(tmp_path / "intel-cache.db") as cache:
        findings, _ = cve_discovery.discover(
            Host(TARGET, services=(service(),)),
            tmp_path,
            cache,
            fetch=lambda *_: page(nvd_entry()),
            sleep=lambda _: None,
        )
    finding = findings[0].to_json()
    record = {
        "capture_id": "assessment-synthetic-candidate",
        "result": {"resolved_ip": TARGET},
        "payload": {"findings": [finding]},
    }
    before = copy.deepcopy(record)
    card = derive(record)[0]
    assert card["kind"] == "cve-candidate" and "candidate association" in card["conclusion"]["text"]
    assert "conditional" in assurance(finding)["priority"].lower()
    assert "backported" in _finding_guidance(finding)[1]
    assert record == before
    html = cve_lab.render({})
    assert html.count("No verified saved assessment") == 2
    assert "not a current secure release" in html


def test_derive_handles_real_serialized_budget_fallback_without_mutating_capture(tmp_path):
    from tests.test_cve_discovery import CVE, configurations, criterion
    from vulnassess.schema import EVIDENCE_MAX

    observed = service(name="synthetic-cache-service" * 3, product="Independent Cache Server" * 4)
    # Trailing zero components retain the same comparable upper bound while exercising
    # the actual serialized budget fallback with valid version criteria and a UUID.
    match = criterion(
        matchCriteriaId="12345678-1234-1234-1234-123456789abc",
        versionEndExcluding="7.0.9" + ".0" * 500,
    )
    with Store(tmp_path / "intel-cache.db") as cache:
        findings, receipt = cve_discovery.discover(
            Host(TARGET, services=(observed,)),
            tmp_path,
            cache,
            fetch=lambda *_: page(nvd_entry(configs=configurations(match))),
            sleep=lambda _: None,
        )
    assert len(findings) == receipt["findings_created"] == 1
    proof = cve_discovery.candidate_facts(findings[0], observed)
    assert proof is not None and len(findings[0].evidence) <= EVIDENCE_MAX
    assert "product" not in proof["service"] and "name" not in proof["service"]
    assert "notice" not in proof
    record = {
        "capture_id": "assessment-synthetic-bounded-candidate",
        "result": {"resolved_ip": TARGET},
        "payload": {"findings": [findings[0].to_json()]},
    }
    before = copy.deepcopy(record)
    cards = derive(record)
    assert record == before
    assert derive(record) == cards
    assert record == before
    assert len(cards) == 1
    card = cards[0]
    assert card["kind"] == "cve-candidate"
    assert CVE in card["title"] and CVE in card["conclusion"]["text"]
    assert "Observed service version 7.0.5" in card["conclusion"]["text"]
    assert "candidate association" in card["conclusion"]["text"]
    assert cve_discovery.NOTICE in card["limits"]


def test_publisher_metadata_cannot_become_observed_network_controls(tmp_path):
    from tests.test_cve_discovery import configurations, criterion
    from vulnassess import context

    observed = service()
    findings, _ = cve_discovery.discover(
        Host(TARGET, services=(observed,)),
        tmp_path,
        None,
        fetch=lambda *_: page(
            nvd_entry(
                configs=configurations(
                    criterion(matchCriteriaId="F5-BIG-IP-auth-required-rate-limit")
                )
            )
        ),
        sleep=lambda _: None,
    )
    assert findings
    signatures = {
        "waf": [{"regex": "F5", "vendor": "F5 BIG-IP"}],
        "auth_required": [{"regex": "auth-required"}],
        "rate_limiting": [{"regex": "rate-limit"}],
    }
    controls = context.detect_controls(Host(TARGET, services=(observed,)), findings, signatures)
    assert all(control.value is None for control in controls.values())
