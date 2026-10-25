import copy

from tests.test_assessment_report import setup_report
from vulnassess import capture_history
from vulnassess.ui import environment


def test_environment_routes_preserve_verified_capture_and_reject_bad_queries(tmp_path):
    app, directory = setup_report(tmp_path)
    response = app.get(f"/environment?capture={directory.name}")
    assert response.status == 200
    assert b"Environment overview" in response.body
    assert b"not network topology" in response.body
    assert directory.name.encode() in response.body
    assert app.get("/environment?capture=missing").status == 409
    for query in ("capture=", "capture=a&capture=b", "target=192.168.0.0/24"):
        assert app.get(f"/environment?{query}").status == 400
    (directory / "case.json").write_text("{}")
    assert app.get(f"/environment?capture={directory.name}").status == 409


def test_multiple_hosts_do_not_invent_os_or_network_relationships(tmp_path):
    _, directory = setup_report(tmp_path)
    record = capture_history.load(directory.parent, directory.name)
    record = copy.deepcopy(record)
    record["payload"]["hosts"] = [
        {"ip": "192.0.2.1", "services": [{"port": 22, "protocol": "tcp", "name": "ssh"}]},
        {"ip": "192.0.2.2", "os_guess": "SYNTHETIC Linux", "services": []},
    ]
    record["payload"]["findings"] = [
        {"host_ip": "192.0.2.1", "port": 22, "protocol": "tcp", "title": "<script>bad</script>"}
    ]
    before = copy.deepcopy(record)
    document = environment.render(record)
    assert "2 observed hosts · 1 service records · 1 recorded findings" in document
    assert "OS fingerprint / guess: <strong>Not established</strong>" in document
    assert "SYNTHETIC Linux" in document
    assert "&lt;script&gt;bad&lt;/script&gt;" in document
    assert "<script>bad</script>" not in document
    assert "No such connections are invented" in document
    assert "not separate network machines" in document
    assert record == before


def test_device_evidence_is_not_fabricated(tmp_path):
    _, directory = setup_report(tmp_path, device=True)
    record = capture_history.load(directory.parent, directory.name)
    document = environment.render(record)
    assert "Recorded device protection checks" in document
    assert "No authenticated local device checks" not in document
