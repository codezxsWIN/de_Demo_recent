"""Synthetic proof validation, not live evidence of a successful repair."""

import copy
import json

import pytest

from vulnassess.errors import ConfigError
from vulnassess.service_network_deployment import digest
from vulnassess.service_network_remediation import load_latest, validate
from vulnassess.ui import network_labs


def receipt():
    document = {
        "schema_version": 1,
        "project": "vulnassess-service-networks",
        "status": "passed",
        "verified_at": "2026-10-27T10:04:00+00:00",
        "ftp_authorised_login_after": True,
        "stages": {},
    }
    for index, stage in enumerate(("before", "after", "restored")):
        accepted = stage != "after"
        rows = {}
        for name, ip, port, service in (
            ("office", "127.0.0.2", 2121, "ftp"),
            ("iot", "127.0.0.3", 1883, "mqtt"),
        ):
            proof = {"protocol_confirmed": True, "anonymous_accepted": accepted}
            if service == "ftp":
                proof["response"] = (
                    "230 Login successful" if accepted else "530 Authentication failed"
                )
            else:
                proof.update(
                    connack_hex="0000" if accepted else "0005", message_exchange_confirmed=accepted
                )
            rows[name] = {
                "target": ip,
                "port": port,
                "service": service,
                "observed_at": f"2026-10-27T10:0{index}:00+00:00",
                "container_id": str(index + 1) * 64,
                "image_id": "sha256:" + "a" * 64,
                "policy_sha256": "b" * 64,
                "policy": {
                    "port": port,
                    "transport": "tcp",
                    "service": service,
                    "require_auth": True,
                },
                "proof": proof,
                "violations": ["authentication"] if accepted else [],
            }
        document["stages"][stage] = rows
    document["receipt_hash"] = digest(document)
    return document


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(status="failed"),
        lambda d: d.update(schema_version=True),
        lambda d: d.update(ftp_authorised_login_after=False),
        lambda d: d.update(error="A trial operation failed"),
        lambda d: d["stages"].pop("restored"),
        lambda d: d["stages"]["after"]["office"].update(port=2122),
        lambda d: d["stages"]["after"]["office"]["policy"].update(require_auth=False),
        lambda d: d["stages"]["after"]["office"]["proof"].update(anonymous_accepted=True),
        lambda d: d["stages"]["after"]["office"]["proof"].update(protocol_confirmed=False),
        lambda d: d["stages"]["after"]["office"]["proof"].update(response="421 unavailable"),
        lambda d: d["stages"]["after"]["iot"]["proof"].update(connack_hex="0003"),
        lambda d: d["stages"]["before"]["iot"]["proof"].update(message_exchange_confirmed=False),
        lambda d: d["stages"]["after"]["iot"].update(violations=["authentication"]),
        lambda d: d["stages"]["after"]["iot"].update(policy_sha256="c" * 64),
        lambda d: d["stages"]["after"]["iot"].update(image_id="sha256:" + "c" * 64),
        lambda d: d["stages"]["after"]["iot"].update(container_id="1" * 64),
        lambda d: d["stages"]["after"]["iot"].update(observed_at="2026-10-27T10:05:00+00:00"),
        lambda d: d["stages"]["after"]["iot"].update(observed_at="2026-10-27T10:01:00"),
    ],
)
def test_contradictory_trial_cannot_be_displayed_as_a_fix_even_after_rehash(change):
    document = receipt()
    change(document)
    document["receipt_hash"] = digest(document)
    with pytest.raises(ConfigError):
        validate(document)


def test_saved_trial_is_bounded_hash_checked_and_not_mutated(tmp_path):
    assert load_latest(tmp_path) is None
    document = receipt()
    before = copy.deepcopy(document)
    path = tmp_path / "remediation-verification-synthetic.json"
    path.write_text(json.dumps(document))
    loaded = load_latest(tmp_path)
    assert loaded["filename"] == path.name and document == before
    html = network_labs.render({}, remediation=loaded)
    assert "Same-endpoint remediation experiment" in html
    assert "not a completed authenticated broker" in html
    assert "intentionally insecure baseline was restored" in html
    assert "Download HTML report" not in html  # No invented saved captures.
    document["verified_at"] = "2020-01-01T00:00:00+00:00"
    path.write_text(json.dumps(document))
    with pytest.raises(ConfigError):
        load_latest(tmp_path)


@pytest.mark.parametrize(
    "raw", ["{", '{"a":1,"a":2}', "x" * 65537], ids=["malformed", "duplicate", "oversize"]
)
def test_bad_trial_json_is_rejected(tmp_path, raw):
    (tmp_path / "remediation-verification-synthetic.json").write_text(raw)
    with pytest.raises(ConfigError):
        load_latest(tmp_path)


def test_empty_view_and_failed_trial_do_not_claim_running_services_or_success():
    html = network_labs.render({}, remediation_error="SYNTHETIC corrupt")
    assert html.count("No verified saved assessment") == 2
    assert "latest remediation experiment could not be verified" in html
    assert "Declared wiring" in html and "not live status" not in html
    assert "http://127.0.0.1:8798/office" in html and "http://127.0.0.1:8798/iot" in html


def test_newest_corrupt_or_wrong_host_capture_is_skipped_without_losing_other_lab(
    monkeypatch, tmp_path
):
    listing = {
        "captures": [
            {"target": "127.0.0.2", "capture_id": "bad"},
            {"target": "127.0.0.2", "capture_id": "wrong-host"},
            {"target": "127.0.0.2", "capture_id": "office"},
            {"target": "127.0.0.3", "capture_id": "iot"},
        ],
        "total": 4,
        "page_size": 20,
    }
    monkeypatch.setattr(network_labs.capture_history, "listing", lambda *_: listing)

    def load(_, identity):
        if identity == "bad":
            raise ConfigError("SYNTHETIC corrupt")
        ip = "127.0.0.2" if identity == "office" else "127.0.0.3"
        return {"capture_id": identity, "payload": {"hosts": [{"ip": ip}]}}

    monkeypatch.setattr(network_labs.capture_history, "load", load)
    selected = network_labs.latest_records(tmp_path)
    assert selected["127.0.0.2"]["capture_id"] == "office"
    assert selected["127.0.0.3"]["capture_id"] == "iot"
