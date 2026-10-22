"""Synthetic endpoint evidence boundaries; no scanners or network calls."""

import json
from copy import deepcopy

import pytest

from vulnassess.service_context import endpoint_context, service_evidence_text


def scoped_control(**overrides):
    return {
        "value": True,
        "scope": "endpoint",
        "port": 8080,
        "protocol": "tcp",
        "source": "scanner",
        "evidence": "Synthetic endpoint observation",
        **overrides,
    }


def test_mixed_services_do_not_inherit_host_or_sibling_controls():
    host = {
        "role": {"value": "web_frontend"},
        "controls": {
            key: scoped_control() for key in ("tls", "auth_required", "waf", "rate_limiting")
        },
    }
    plain = {"port": 80, "protocol": "tcp", "name": "http", "tls": False}
    secure = {"port": 8443, "protocol": "tcp", "name": "http", "tls": True}
    assert endpoint_context(secure, host)["controls"]["tls"]["value"] is True
    for service in (plain, secure):
        result = endpoint_context(service, host)
        assert result["port"] == service["port"]
        assert result["protocol"] == "tcp"
        for key in ("auth_required", "waf", "rate_limiting"):
            assert result["controls"][key]["value"] is None
    assert endpoint_context(plain, host)["controls"]["tls"]["value"] is None


@pytest.mark.parametrize(
    "fingerprint",
    [
        {"product": "Oracle WebLogic Server"},
        {"banner": "HTTP Administration Console"},
        {"fingerprint": "management-interface"},
        {"name": "http", "banner": "Admin panel"},
        {"cpe": "cpe:/a:oracle:weblogic_server:12.2.1"},
    ],
)
def test_admin_candidate_preserves_host_web_frontend(fingerprint):
    host = {"role": {"value": "web_frontend", "source": "rule"}}
    result = endpoint_context({"port": 7001, "protocol": "tcp", **fingerprint}, host)
    assert result["role_candidate"] == "management_interface"
    assert result["host_role"] == "web_frontend"
    assert host["role"]["value"] == "web_frontend"


def test_role_candidate_uses_fingerprint_not_host_role_or_port():
    assert endpoint_context({"port": 7001, "protocol": "tcp"})["role_candidate"] == "unknown"
    result = endpoint_context({"port": 49152, "protocol": "tcp", "name": "http"})
    assert result["role_candidate"] == "web_frontend"
    assert result["host_role"] is None
    assert endpoint_context({}, {"role": "web_frontend"})["role_candidate"] == "unknown"


@pytest.mark.parametrize("port", [80, 443, 7002, 8443, 49152])
@pytest.mark.parametrize("tls", [False, None, "true", "false", 0, 1, {}, []])
def test_ports_names_and_truthy_values_do_not_establish_tls(port, tls):
    service = {"port": port, "protocol": "tcp", "name": "https", "tls": tls}
    assert endpoint_context(service)["controls"]["tls"]["value"] is None
    assert "tls=unknown (not established)" in service_evidence_text(service)


def test_explicit_tls_observation_on_unusual_port_has_metadata():
    service = {"port": 49152, "protocol": "tcp", "product": "Example", "tls": True}
    assert "tls=observed (scanner TLS metadata)" in service_evidence_text(service)
    service.update(tls_source="nmap tunnel metadata", tls_evidence="service tunnel=ssl")
    fact = endpoint_context(service)["controls"]["tls"]
    assert fact == {
        "value": True,
        "scope": "endpoint",
        "source": "nmap tunnel metadata",
        "evidence": "service tunnel=ssl",
    }
    text = service_evidence_text(service)
    assert "tls=observed (nmap tunnel metadata)" in text
    assert "tls_evidence=service tunnel=ssl" in text


def test_metadata_alone_cannot_promote_unknown_tls():
    service = {
        "port": 443,
        "protocol": "tcp",
        "tls": False,
        "tls_source": "import",
        "tls_evidence": "unverified metadata",
    }
    assert endpoint_context(service)["controls"]["tls"]["value"] is None
    text = service_evidence_text(service)
    assert "tls=unknown (not established)" in text
    assert "tls_source=import" in text
    assert "tls_evidence=unverified metadata" in text


@pytest.mark.parametrize(
    "tls,marker",
    [
        (True, "tls=observed (scanner TLS metadata)"),
        (False, "tls=unknown (not established)"),
    ],
)
def test_long_banner_keeps_tls_marker_within_first_200_characters(tls, marker):
    service = {
        "port": 8443,
        "protocol": "tcp",
        "name": "http",
        "banner": "Synthetic long banner " * 100,
        "tls": tls,
    }
    text = service_evidence_text(service)
    assert len(text) > 200
    assert text.startswith(f"8443/tcp; {marker}; http;")
    assert marker in text[:200]
    assert service["banner"].strip() in text


@pytest.mark.parametrize(
    "key",
    [
        "auth_required",
        "waf",
        "rate_limiting",
        "network_acl",
        "bind_configuration",
        "service_privileges",
        "command_acl",
    ],
)
@pytest.mark.parametrize("value", [True, False])
def test_explicit_endpoint_control_requires_evidence_and_binding(key, value):
    name = "http" if key in ("waf", "rate_limiting") else "redis"
    service = {
        "port": 8080,
        "protocol": "tcp",
        "name": name,
        "controls": {key: scoped_control(value=value)},
    }
    fact = endpoint_context(service)["controls"][key]
    assert fact["value"] is value
    assert fact["scope"] == "endpoint"
    assert fact["source"] == "scanner"
    assert fact["evidence"] == "Synthetic endpoint observation"


@pytest.mark.parametrize(
    "key",
    [
        "auth_required",
        "waf",
        "rate_limiting",
        "network_acl",
        "bind_configuration",
        "service_privileges",
        "command_acl",
    ],
)
@pytest.mark.parametrize(
    "overrides",
    [
        {"scope": "host"},
        {"scope": "scope"},
        {"scope": None},
        {"port": 8443},
        {"port": None},
        {"port": "8080"},
        {"protocol": "udp"},
        {"protocol": None},
        {"source": ""},
        {"evidence": ""},
        {"evidence": "none observed"},
        {"evidence": "unknown"},
        {"value": None},
        {"value": 1},
    ],
)
def test_unscoped_mismatched_or_missing_control_evidence_is_unknown(key, overrides):
    name = "http" if key in ("waf", "rate_limiting") else "redis"
    service = {
        "port": 8080,
        "protocol": "tcp",
        "name": name,
        "controls": {key: scoped_control(**overrides)},
    }
    assert endpoint_context(service)["controls"][key]["value"] is None


def test_control_evidence_is_not_transferred_to_another_service():
    evidence = {"waf": scoped_control(value="Example WAF")}
    first = endpoint_context({"port": 8080, "protocol": "tcp", "controls": evidence})
    other = endpoint_context({"port": 8443, "protocol": "tcp", "controls": evidence})
    assert first["controls"]["waf"]["value"] == "Example WAF"
    assert other["controls"]["waf"]["value"] is None


@pytest.mark.parametrize("record", [True, False, "present", {"value": True}, None])
def test_bare_service_controls_do_not_establish_endpoint_observations(record):
    service = {
        "port": 8080,
        "protocol": "tcp",
        "tls": False,
        "controls": {key: record for key in ("tls", "auth_required", "waf", "rate_limiting")},
    }
    assert all(fact["value"] is None for fact in endpoint_context(service)["controls"].values())


def test_missing_tls_flag_and_custom_evidence_without_source():
    service = {"port": 443, "protocol": "tcp", "name": "https"}
    assert "tls=unknown (not established)" in service_evidence_text(service)
    service.update(tls=True, tls_evidence="Synthetic handshake metadata")
    text = service_evidence_text(service)
    assert "tls=observed (scanner TLS metadata)" in text
    assert "tls_evidence=Synthetic handshake metadata" in text


@pytest.mark.parametrize("origin", ["host", "scope"])
def test_exposure_retains_host_or_scope_origin_without_claiming_endpoint_reachability(origin):
    host = {
        "exposure": {
            "value": "internet_facing",
            "scope": origin,
            "source": "manual",
            "evidence": "Synthetic scope tag",
        }
    }
    result = endpoint_context({"port": 8080, "protocol": "tcp"}, host)
    assert result["exposure"] == {
        **host["exposure"],
        "origin": origin,
    }
    assert result["exposure"]["scope"] != "endpoint"


def test_plain_host_exposure_and_explicit_origin():
    assert endpoint_context({}, {"exposure": "internal"})["exposure"]["origin"] == "host"
    host = {"exposure": {"value": "internal", "origin": "scope"}}
    assert endpoint_context({}, host)["exposure"]["origin"] == "scope"
    assert endpoint_context({"exposure": "internet_facing"})["exposure"]["value"] is None


def test_evidence_is_address_free_and_preserves_fingerprint():
    service = {
        "ip": "192.0.2.10",
        "hostname": "synthetic.example",
        "port": 8080,
        "protocol": "tcp",
        "name": "http",
        "product": "Oracle WebLogic",
        "version": "12.2.1",
        "tls": False,
        "banner": "Admin console at https://synthetic.example:8080/ 192.0.2.10 [2001:db8::1]",
    }
    text = service_evidence_text(service)
    for fingerprint in ("8080/tcp", "http", "Oracle WebLogic", "12.2.1", "Admin console"):
        assert fingerprint in text
    for address in ("192.0.2.10", "synthetic.example", "2001:db8::1"):
        assert address not in text


def test_empty_inputs_are_json_unknowns_without_invented_protocol_or_controls():
    result = endpoint_context({})
    assert result["port"] is None and result["protocol"] is None
    assert result["exposure"]["origin"] == "unknown"
    assert all(fact["value"] is None for fact in result["controls"].values())
    assert "unknown/unknown" in service_evidence_text({})
    assert json.loads(json.dumps(result)) == result


def test_helpers_do_not_mutate_inputs_or_share_returned_state():
    service = {"port": 8080, "protocol": "tcp", "controls": {"waf": scoped_control()}}
    host = {"role": {"value": "web_frontend"}, "exposure": {"value": "internal"}}
    original = deepcopy((service, host))
    result = endpoint_context(service, host)
    service_evidence_text(service)
    assert (service, host) == original
    result["controls"]["waf"]["value"] = False
    result["exposure"]["value"] = "internet_facing"
    assert endpoint_context(service, host)["controls"]["waf"]["value"] is True
    assert endpoint_context(service, host)["exposure"]["value"] == "internal"
    assert (service, host) == original


def test_redis_with_http_siblings_and_host_waf_has_only_endpoint_checks():
    siblings = [
        {"port": 8080, "protocol": "tcp", "name": "http", "controls": {"waf": scoped_control()}},
        {"port": 8443, "protocol": "tcp", "name": "https", "tls": True},
    ]
    host = {
        "role": {"value": "web_frontend"},
        "controls": {
            "waf": True,
            "auth_required": True,
            "tls": True,
            "network_acl": True,
            "command_acl": True,
        },
        "services": siblings,
    }
    service = {"port": 6379, "protocol": "tcp", "name": "redis"}
    original = deepcopy((service, host))
    result = endpoint_context(service, host)
    assert result["role_candidate"] == "database"
    assert result["host_role"] == "web_frontend"
    assert result["relevant_checks"] == [
        "network_acl",
        "auth_required",
        "bind_configuration",
        "service_privileges",
        "tls",
        "command_acl",
    ]
    for key in result["relevant_checks"]:
        assert result["controls"][key]["value"] is None
        assert result["controls"][key]["scope"] == "endpoint"
        assert result["control_relevance"][key]["value"] is True
    for key in ("waf", "rate_limiting"):
        assert result["controls"][key]["value"] is None
        assert result["controls"][key]["scope"] == "not_applicable"
        assert result["controls"][key]["reason"]
        assert result["control_relevance"][key]["value"] is False
        assert result["control_relevance"][key]["scope"] == "not_applicable"
        assert result["control_relevance"][key]["reason"]
        assert key not in result["relevant_checks"]
    assert endpoint_context(siblings[0], host)["controls"]["waf"]["value"] is True
    assert endpoint_context(siblings[1], host)["controls"]["tls"]["value"] is True
    assert (service, host) == original
    assert service_evidence_text(service) == "6379/tcp; tls=unknown (not established); redis"


@pytest.mark.parametrize("name", ["http", "https"])
def test_http_known_controls_keep_values_and_relevance(name):
    service = {
        "port": 8080,
        "protocol": "tcp",
        "name": name,
        "tls": True,
        "controls": {
            "auth_required": scoped_control(value=False),
            "waf": scoped_control(value="Example WAF"),
            "rate_limiting": scoped_control(),
        },
    }
    result = endpoint_context(service)
    assert result["relevant_checks"] == ["auth_required", "waf", "rate_limiting", "tls"]
    assert {key: fact["value"] for key, fact in result["controls"].items()} == {
        "auth_required": False,
        "waf": "Example WAF",
        "rate_limiting": True,
        "tls": True,
    }
    assert all(fact["value"] is True for fact in result["control_relevance"].values())
    assert all(fact["scope"] == "endpoint" for fact in result["controls"].values())


@pytest.mark.parametrize("name", ["redis", "mysql", "postgresql", "mongodb", "mssql"])
def test_native_database_controls_ignore_explicit_http_control_observations(name):
    service = {
        "port": 8080,
        "protocol": "tcp",
        "name": name,
        "tls": True,
        "controls": {"waf": scoped_control(), "rate_limiting": scoped_control()},
    }
    result = endpoint_context(service)
    assert result["controls"]["waf"]["scope"] == "not_applicable"
    assert result["controls"]["rate_limiting"]["scope"] == "not_applicable"
    assert result["controls"]["tls"]["value"] is True


@pytest.mark.parametrize("protocol", [None, "tcp", "udp", "unknown"])
def test_unknown_application_protocol_does_not_infer_relevance_from_port_or_host(protocol):
    service = {"port": 6379, "protocol": protocol}
    host = {"role": "database", "controls": {"waf": True}}
    result = endpoint_context(service, host)
    assert result["relevant_checks"] == []
    assert set(result["controls"]) == {"auth_required", "waf", "rate_limiting", "tls"}
    assert all(fact["value"] is None for fact in result["controls"].values())
    assert all(fact["scope"] == "endpoint" for fact in result["controls"].values())
    assert all(fact["value"] is None for fact in result["control_relevance"].values())
    assert all(fact["reason"] for fact in result["control_relevance"].values())
    assert result["role_candidate"] == "unknown"
    assert result["host_role"] == "database"


def test_protocol_relevance_is_independent_of_management_role_and_returned_state():
    service = {"port": 6379, "protocol": "tcp", "name": "redis", "banner": "Admin server"}
    result = endpoint_context(service, {"role": "web_frontend"})
    assert result["role_candidate"] == "management_interface"
    assert result["controls"]["waf"]["scope"] == "not_applicable"
    result["control_relevance"]["waf"]["value"] = True
    result["relevant_checks"].clear()
    fresh = endpoint_context(service)
    assert fresh["control_relevance"]["waf"]["value"] is False
    assert "network_acl" in fresh["relevant_checks"]
