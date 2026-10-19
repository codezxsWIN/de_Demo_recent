"""Synthetic report-state compatibility, never independent context/accuracy evidence.

Declared-human labels simulate the wire contract. All input observations, reviewer
identifiers and evaluation outcomes in this module are unit-test constructions.
"""

import io
import json
import re
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace

import pytest

from tests.test_assessment_snapshot import ROOT, SETTINGS, prepared_store
from vulnassess import assessment_snapshot, audit, cohort, context_eval
from vulnassess.cli import main
from vulnassess.errors import ConfigError
from vulnassess.schema import Feature


def synthetic_write(tmp_path, payload):
    core = {key: value for key, value in payload.items() if key != "evaluation_hash"}
    path = tmp_path / "synthetic_context_report.json"
    path.write_text(json.dumps({**core, "evaluation_hash": audit._digest(core)}))
    return path


def synthetic_result(profiles, labels):
    result = {**context_eval.evaluate_context(profiles, labels), "run_id": "snapshot"}
    assert result["evidence_status"] == "VERIFIED"
    return result


def synthetic_state(store):
    return {
        "profiles": [item.to_json() for item in store.profiles("snapshot")],
        "scores": [item.to_json() for item in store.scores("snapshot")],
        "hosts": [item.to_json() for item in store.hosts("snapshot")],
        "findings": [item.to_json() for item in store.findings("snapshot")],
    }


@pytest.fixture
def synthetic_assessment(tmp_path):
    with prepared_store(str(tmp_path)) as store:
        profiles = store.profiles("snapshot")
        for profile in profiles:
            # Simulate an earlier, rule-only observed profile state. This is not
            # a claim about the real inference provenance of any captured host.
            profile.exposure = Feature(
                profile.exposure.value, 0.9, "rule", "SYNTHETIC direct exposure observation"
            )
            store.upsert_profile("snapshot", profile)
        # These cases isolate the context-evaluation attachment contract, even
        # after profiles deliberately change. Use the supported legacy score
        # shape with no retained input binding; keep the nonempty score queue
        # and every numeric/identity field. Current fully bound score/profile
        # disagreement is tested separately in test_synthetic_snapshot_score_binding.
        scores = store.scores("snapshot")
        assert scores
        for score in scores:
            legacy_score = replace(score, inputs={})
            original = score.to_json()
            retained = legacy_score.to_json()
            original.pop("inputs")
            retained.pop("inputs")
            assert retained == original
            store.upsert_score("snapshot", legacy_score)
        labels = [
            context_eval.ContextTruth(
                profile.host_ip,
                f"SYNTHETIC group-{index}",
                str(profile.role.value),
                str(profile.exposure.value),
                label_source="human",
                reviewer="SYNTHETIC simulated reviewer",
                provenance="SYNTHETIC contract input, not actual independent truth",
            )
            for index, profile in enumerate(profiles)
        ]
        payload = synthetic_result(profiles, labels)
        path = synthetic_write(tmp_path, payload)
        yield store, profiles, labels, payload, path


def synthetic_report(store, path, **paths):
    return audit.collect_report_audit(
        SETTINGS, store, "snapshot", artifact_paths={"context": path}, **paths
    )


@pytest.mark.parametrize("field", ["role", "exposure"])
@pytest.mark.parametrize("source", ["manual", "model", "llm", "legacy_metadata"])
@pytest.mark.parametrize("frozen", [False, True])
def test_synthetic_old_evaluation_cannot_hide_changed_profile_provenance(
    tmp_path, synthetic_assessment, field, source, frozen
):
    store, profiles, _, _, path = synthetic_assessment
    old_bytes = path.read_bytes()
    profile = profiles[0]
    changed = replace(
        getattr(profile, field),
        source="rule" if source == "legacy_metadata" else source,
        evidence="scope.yaml lab_targets[SYNTHETIC].tags.vantage=external"
        if source == "legacy_metadata"
        else "SYNTHETIC changed provenance",
    )
    setattr(profile, field, changed)
    store.upsert_profile("snapshot", profile)
    before = synthetic_state(store)
    paths = {}
    if frozen:
        snapshot = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
        paths["snapshot_path"] = assessment_snapshot.save_snapshot(
            snapshot, tmp_path / "synthetic_current_snapshot.json"
        )
        manifest, evidence = cohort.freeze_cohort(
            snapshot,
            [finding["id"] for finding in snapshot["findings"]],
            cohort_id="synthetic-current-cohort",
            created_on="2026-10-17",
            evidence_status="NOT RUN",
        )
        directory = tmp_path / "synthetic_current_cohort"
        cohort.save_cohort(manifest, evidence, directory)
        paths.update(
            cohort_manifest_path=directory / "manifest.json",
            cohort_evidence_path=directory / "evidence.json",
        )
    # The old bytes are still a structurally coherent artifact for this run.
    assert audit.load_artifact("context", path, "snapshot").evidence_status == "VERIFIED"
    with pytest.raises(ConfigError, match="context artifact.*current"):
        synthetic_report(store, path, **paths)
    assert path.read_bytes() == old_bytes
    assert synthetic_state(store) == before


@pytest.mark.parametrize("field", ["role", "exposure"])
def test_synthetic_prediction_marginals_must_match_current_profiles(synthetic_assessment, field):
    store, profiles, _, _, path = synthetic_assessment
    profile = profiles[0]
    value = (
        ("database" if profile.role.value != "database" else "workstation")
        if field == "role"
        else ("internal" if profile.exposure.value == "internet_facing" else "internet_facing")
    )
    setattr(profile, field, replace(getattr(profile, field), value=value))
    store.upsert_profile("snapshot", profile)
    with pytest.raises(ConfigError, match="context artifact.*current"):
        synthetic_report(store, path)


@pytest.mark.parametrize("mode", ["missing", "additional", "unknown_exclusion", "no_subset"])
def test_synthetic_evaluated_subset_must_be_reconcilable(tmp_path, synthetic_assessment, mode):
    store, profiles, _, payload, path = synthetic_assessment
    if mode == "missing":
        store.connection.execute(
            "DELETE FROM context_profiles WHERE run_id=? AND host_ip=?",
            ("snapshot", profiles[0].host_ip),
        )
        store.connection.commit()
    elif mode == "additional":
        extra = replace(profiles[0], host_ip="192.0.2.99")
        store.upsert_profile("snapshot", extra)
    elif mode == "unknown_exclusion":
        payload["unlabelled_profile_hosts"] = ["192.0.2.99"]
        path = synthetic_write(tmp_path, payload)
    else:
        del payload["unlabelled_profile_hosts"]
        path = synthetic_write(tmp_path, payload)
    assert audit.load_artifact("context", path, "snapshot").evidence_status == "VERIFIED"
    with pytest.raises(ConfigError, match="context artifact.*current"):
        synthetic_report(store, path)


def test_synthetic_unchanged_subset_preserves_unused_manual_inputs_and_raw_artifact(
    tmp_path, synthetic_assessment
):
    store, profiles, labels, _, _ = synthetic_assessment
    profiles[-1].role = replace(profiles[-1].role, source="manual")
    store.upsert_profile("snapshot", profiles[-1])
    profiles[0].manual["environment"] = Feature("test", 1, "manual", "SYNTHETIC unused tag")
    store.upsert_profile("snapshot", profiles[0])
    payload = synthetic_result(profiles, labels[:-1])
    path = synthetic_write(tmp_path, payload)
    before = synthetic_state(store)
    result = synthetic_report(store, path)
    assert (
        result["artifacts"]["context"]["evaluation_hash"]
        == audit.load_artifact("context", path, "snapshot").artifact_hash
    )
    assert any("historical" in value.lower() for value in result["limitations"])
    row = next(row for row in result["rows"] if row["component"] == "context")
    assert row["evidence_status"] == "NOT RUN"
    assert result["artifacts"]["context"]["evidence_status"] == "VERIFIED"
    assert "compatible" in row["summary"]
    assert "unbound" in row["summary"]
    assert synthetic_state(store) == before


@pytest.mark.parametrize("source", ["manual", "model", "llm", "legacy_metadata"])
def test_synthetic_control_metrics_cannot_require_untrusted_current_inputs(
    tmp_path, synthetic_assessment, source
):
    store, profiles, labels, _, _ = synthetic_assessment
    for profile, label in zip(profiles, labels, strict=True):
        profile.controls["waf"] = Feature(True, 0.9, "rule", "SYNTHETIC WAF observation")
        label.controls["waf"] = True
        store.upsert_profile("snapshot", profile)
    payload = synthetic_result(profiles, labels)
    path = synthetic_write(tmp_path, payload)
    profiles[0].controls["waf"] = Feature(
        True,
        0.9,
        "rule" if source == "legacy_metadata" else source,
        "scope.yaml lab_targets[SYNTHETIC].tags.waf=true"
        if source == "legacy_metadata"
        else "SYNTHETIC changed WAF source",
    )
    store.upsert_profile("snapshot", profiles[0])
    with pytest.raises(ConfigError, match="context artifact.*current"):
        synthetic_report(store, path)


def test_synthetic_partial_control_truth_does_not_include_unused_manual_control(
    tmp_path, synthetic_assessment
):
    store, profiles, labels, _, _ = synthetic_assessment
    labels[0].controls["waf"] = True
    profiles[0].controls["waf"] = Feature(True, 0.9, "rule", "SYNTHETIC WAF observation")
    profiles[1].controls["waf"] = Feature(True, 0.9, "manual", "SYNTHETIC unused control")
    for profile in profiles:
        store.upsert_profile("snapshot", profile)
    payload = synthetic_result(profiles, labels)
    result = synthetic_report(store, synthetic_write(tmp_path, payload))
    assert result["artifacts"]["context"]["controls"]["waf"]["examples"] == 1
    assert any("historical" in value.lower() for value in result["limitations"])


@pytest.mark.parametrize("provided", [False, True])
def test_synthetic_existing_snapshot_binding_can_be_checked_with_or_without_report_option(
    tmp_path, synthetic_assessment, provided
):
    store, _, _, payload, _ = synthetic_assessment
    snapshot = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
    payload["snapshot_hash"] = snapshot["snapshot_hash"]
    path = synthetic_write(tmp_path, payload)
    paths = {}
    if provided:
        paths["snapshot_path"] = assessment_snapshot.save_snapshot(
            snapshot, tmp_path / "synthetic_matching_snapshot.json"
        )
    before = synthetic_state(store)
    result = synthetic_report(store, path, **paths)
    row = next(row for row in result["rows"] if row["component"] == "context")
    assert row["evidence_status"] == "VERIFIED"
    assert "snapshot-bound" in row["summary"]
    assert synthetic_state(store) == before


@pytest.mark.parametrize("provided", [False, True])
def test_synthetic_changed_evidence_cannot_keep_old_snapshot_binding(
    tmp_path, synthetic_assessment, provided
):
    store, profiles, _, payload, _ = synthetic_assessment
    old = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
    payload["snapshot_hash"] = old["snapshot_hash"]
    profiles[0].role = replace(profiles[0].role, evidence="SYNTHETIC different input quote")
    store.upsert_profile("snapshot", profiles[0])
    paths = {}
    if provided:
        paths["snapshot_path"] = assessment_snapshot.save_snapshot(
            assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot"),
            tmp_path / "synthetic_new_snapshot.json",
        )
    with pytest.raises(ConfigError, match="context artifact.*snapshot"):
        synthetic_report(store, synthetic_write(tmp_path, payload), **paths)


def test_synthetic_profile_drift_between_snapshot_check_and_binding_is_rejected(
    tmp_path, synthetic_assessment, monkeypatch
):
    store, _, _, payload, _ = synthetic_assessment
    snapshot = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
    payload["snapshot_hash"] = snapshot["snapshot_hash"]
    frozen = assessment_snapshot.save_snapshot(snapshot, tmp_path / "synthetic_race_snapshot.json")
    original = store.profiles
    calls = 0

    def changed_after_initial_check(run_id):
        nonlocal calls
        calls += 1
        current = original(run_id)
        if calls > 1:
            current[0].role = replace(current[0].role, evidence="SYNTHETIC later evidence")
        return current

    monkeypatch.setattr(store, "profiles", changed_after_initial_check)
    with pytest.raises(ConfigError, match="context artifact.*current"):
        synthetic_report(store, synthetic_write(tmp_path, payload), snapshot_path=frozen)


def test_synthetic_same_marginals_do_not_prove_historical_host_identity(synthetic_assessment):
    store, profiles, _, _, path = synthetic_assessment
    first, second = profiles[:2]
    first.role, second.role = second.role, first.role
    store.upsert_profile("snapshot", first)
    store.upsert_profile("snapshot", second)
    result = synthetic_report(store, path)
    row = next(row for row in result["rows"] if row["component"] == "context")
    assert row["evidence_status"] == "NOT RUN"
    assert "unbound" in row["summary"]
    assert any("historical" in value.lower() for value in result["limitations"])


def test_synthetic_orphan_profile_cannot_substitute_for_an_observed_host(synthetic_assessment):
    store, profiles, _, _, path = synthetic_assessment
    replaced = profiles[0]
    store.connection.execute(
        "DELETE FROM context_profiles WHERE run_id=? AND host_ip=?",
        ("snapshot", replaced.host_ip),
    )
    store.connection.commit()
    store.upsert_profile("snapshot", replace(replaced, host_ip="192.0.2.99"))
    with pytest.raises(ConfigError, match="context artifact.*current"):
        synthetic_report(store, path)


def test_synthetic_legacy_not_run_stays_unknown_without_current_binding(
    tmp_path, synthetic_assessment
):
    store, _, _, _, _ = synthetic_assessment
    payload = {
        "run_id": "snapshot",
        "evidence_status": "NOT RUN",
        "rule_role": {},
        "exposure": {},
        "h1": {},
    }
    result = synthetic_report(store, synthetic_write(tmp_path, payload))
    row = next(row for row in result["rows"] if row["component"] == "context")
    assert row["evidence_status"] == "NOT RUN"
    assert "accuracy=None" in row["summary"]
    assert "compatible" not in row["summary"]


def test_synthetic_cli_rejection_does_not_replace_existing_report(tmp_path, synthetic_assessment):
    store, profiles, _, _, path = synthetic_assessment
    profiles[0].role = replace(profiles[0].role, source="manual")
    store.upsert_profile("snapshot", profiles[0])
    before = synthetic_state(store)
    report = tmp_path / "synthetic_existing_report.html"
    report.write_text("SYNTHETIC retained report, not new evidence")
    error, output = io.StringIO(), io.StringIO()
    with redirect_stderr(error), redirect_stdout(output):
        code = main(
            [
                "--config",
                str(ROOT / "config"),
                "--db",
                str(tmp_path / "assessment.db"),
                "report",
                "--run-id",
                "snapshot",
                "--out",
                str(report),
                "--context-artifact",
                str(path),
                "--json",
            ]
        )
    assert code == 2
    assert "context artifact" in error.getvalue()
    assert "Traceback" not in error.getvalue()
    assert output.getvalue() == ""
    assert report.read_text() == "SYNTHETIC retained report, not new evidence"
    assert synthetic_state(store) == before


@pytest.mark.parametrize("identifier", [1, True])
def test_synthetic_artifact_run_identifier_cannot_be_coerced(
    tmp_path, synthetic_assessment, identifier
):
    _, _, _, payload, _ = synthetic_assessment
    payload["run_id"] = identifier
    with pytest.raises(ConfigError, match="run_id.*string"):
        audit.load_artifact("context", synthetic_write(tmp_path, payload), str(identifier))


def test_synthetic_unbound_limitation_is_visible_in_actual_html_report(
    tmp_path, synthetic_assessment
):
    store, _, _, _, path = synthetic_assessment
    before = synthetic_state(store)
    output = tmp_path / "synthetic_unbound_report.html"
    with redirect_stdout(io.StringIO()):
        code = main(
            [
                "--config",
                str(ROOT / "config"),
                "--db",
                str(tmp_path / "assessment.db"),
                "report",
                "--run-id",
                "snapshot",
                "--out",
                str(output),
                "--context-artifact",
                str(path),
                "--json",
            ]
        )
    assert code == 0
    rendered = output.read_text(encoding="utf-8")
    row = re.search(r"<tr>\s*<td>context</td>(.*?)</tr>", rendered, re.S)
    assert row is not None
    assert "<b>NOT RUN</b>" in row[1]
    assert "compatible" in row[1]
    assert "historical input identity unbound" in row[1]
    assert "historical per-host inputs are unbound" in rendered
    assert synthetic_state(store) == before


@pytest.mark.parametrize("field", ["role", "exposure"])
@pytest.mark.parametrize("value", [None, True, [], "invented"])
def test_synthetic_current_profile_labels_cannot_bypass_report_validation(
    synthetic_assessment, field, value
):
    store, profiles, _, _, path = synthetic_assessment
    profile = profiles[0]
    setattr(profile, field, replace(getattr(profile, field), value=value))
    store.upsert_profile("snapshot", profile)
    with pytest.raises(ConfigError, match="context artifact.*current"):
        synthetic_report(store, path)


@pytest.mark.parametrize("reader", ["profiles", "hosts"])
@pytest.mark.parametrize("error", [ValueError, TypeError, AttributeError])
def test_synthetic_corrupt_stored_inputs_are_controlled_errors(
    synthetic_assessment, monkeypatch, reader, error
):
    store, _, _, _, path = synthetic_assessment

    def malformed(run_id):
        raise error("SYNTHETIC malformed stored input")

    monkeypatch.setattr(store, reader, malformed)
    with pytest.raises(ConfigError, match="context artifact.*current"):
        synthetic_report(store, path)


@pytest.mark.parametrize("identifier", ["", False, 0])
def test_synthetic_current_host_identifier_is_not_coerced(
    synthetic_assessment, monkeypatch, identifier
):
    store, profiles, _, _, path = synthetic_assessment
    altered = [replace(profiles[0], host_ip=identifier), *profiles[1:]]
    monkeypatch.setattr(store, "profiles", lambda run_id: altered)
    with pytest.raises(ConfigError, match="context artifact.*current"):
        synthetic_report(store, path)


def test_synthetic_duplicate_current_profile_cannot_disappear_from_subset(
    synthetic_assessment, monkeypatch
):
    store, profiles, _, _, path = synthetic_assessment
    monkeypatch.setattr(store, "profiles", lambda run_id: [*profiles, profiles[0]])
    with pytest.raises(ConfigError, match="context artifact.*current"):
        synthetic_report(store, path)


@pytest.mark.parametrize(
    "replacement",
    [
        Feature(False, 0.9, "rule", "SYNTHETIC negative control observation"),
        Feature(None, 0, "rule", "none observed"),
        Feature(False, 0.5, "rule", "none observed"),
    ],
)
def test_synthetic_changed_control_observations_cannot_reuse_old_marginals(
    tmp_path, synthetic_assessment, replacement
):
    store, profiles, labels, _, _ = synthetic_assessment
    for profile, label in zip(profiles, labels, strict=True):
        profile.controls["waf"] = Feature(True, 0.9, "rule", "SYNTHETIC WAF signal")
        label.controls["waf"] = True
        store.upsert_profile("snapshot", profile)
    payload = synthetic_result(profiles, labels)
    profiles[0].controls["waf"] = replacement
    store.upsert_profile("snapshot", profiles[0])
    with pytest.raises(ConfigError, match="context artifact.*current"):
        synthetic_report(store, synthetic_write(tmp_path, payload))


def test_synthetic_feasible_control_subset_still_cannot_prove_original_host_mapping(
    tmp_path, synthetic_assessment
):
    store, profiles, labels, _, _ = synthetic_assessment
    profiles[0].controls["waf"] = Feature(True, 0.9, "rule", "SYNTHETIC WAF signal")
    labels[0].controls["waf"] = True
    payload = synthetic_result(profiles, labels)
    profiles[0].controls["waf"] = replace(profiles[0].controls["waf"], source="manual")
    profiles[1].controls["waf"] = Feature(True, 0.9, "rule", "SYNTHETIC alternative signal")
    for profile in profiles:
        store.upsert_profile("snapshot", profile)
    result = synthetic_report(store, synthetic_write(tmp_path, payload))
    row = next(row for row in result["rows"] if row["component"] == "context")
    assert row["evidence_status"] == "NOT RUN"
    assert "unbound" in row["summary"]


@pytest.mark.parametrize("name", ["SYNTHETIC\ntarget", "SYNTHETIC\rtarget", "SYNTHETIC\r\ntarget"])
def test_legacy_multiline_metadata_cannot_attach_as_snapshot_bound_verified(
    tmp_path, synthetic_assessment, name
):
    store, profiles, _, payload, _ = synthetic_assessment
    profiles[0].exposure = replace(
        profiles[0].exposure,
        source="rule",
        evidence=f"scope.yaml lab_targets[{name}].tags.vantage=external",
    )
    store.upsert_profile("snapshot", profiles[0])
    snapshot = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
    payload["snapshot_hash"] = snapshot["snapshot_hash"]
    path = synthetic_write(tmp_path, payload)
    frozen = assessment_snapshot.save_snapshot(
        snapshot, tmp_path / "synthetic_multiline_snapshot.json"
    )
    before = synthetic_state(store)
    with pytest.raises(ConfigError, match="context artifact.*current"):
        synthetic_report(store, path, snapshot_path=frozen)
    assert synthetic_state(store) == before


@pytest.mark.parametrize(
    "artifact_model,snapshot_model",
    [
        ("a" * 16, "b" * 16),
        (None, "b" * 16),
        ("a" * 16, None),
    ],
)
@pytest.mark.parametrize("bound", [False, True])
def test_report_snapshot_cannot_replace_contradictory_artifact_model_identity(
    tmp_path, synthetic_assessment, artifact_model, snapshot_model, bound
):
    store, _, _, payload, _ = synthetic_assessment
    snapshot = assessment_snapshot.build_snapshot(
        SETTINGS, store, "snapshot", model_hash=snapshot_model
    )
    payload["model_hash"] = artifact_model
    if bound:
        payload["snapshot_hash"] = snapshot["snapshot_hash"]
    path = synthetic_write(tmp_path, payload)
    frozen = assessment_snapshot.save_snapshot(snapshot, tmp_path / "synthetic_model_snapshot.json")
    before = synthetic_state(store)
    original = path.read_bytes()
    with pytest.raises(ConfigError, match="context artifact.*model"):
        synthetic_report(store, path, snapshot_path=frozen)
    assert path.read_bytes() == original
    assert synthetic_state(store) == before


@pytest.mark.parametrize("provided", [False, True])
@pytest.mark.parametrize("model", [None, "a" * 16])
def test_matching_model_declarations_preserve_snapshot_bound_verification(
    tmp_path, synthetic_assessment, provided, model
):
    store, _, _, payload, _ = synthetic_assessment
    snapshot = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot", model_hash=model)
    payload["model_hash"] = model
    payload["snapshot_hash"] = snapshot["snapshot_hash"]
    path = synthetic_write(tmp_path, payload)
    paths = {}
    if provided:
        paths["snapshot_path"] = assessment_snapshot.save_snapshot(
            snapshot, tmp_path / "synthetic_consistent_model.json"
        )
    result = synthetic_report(store, path, **paths)
    row = next(row for row in result["rows"] if row["component"] == "context")
    assert row["evidence_status"] == "VERIFIED"
    assert "snapshot-bound" in row["summary"]


@pytest.mark.parametrize("model", ["", False, 1, 1.0, [], {}])
def test_model_identity_in_context_artifact_requires_its_declared_type(
    tmp_path, synthetic_assessment, model
):
    _, _, _, payload, _ = synthetic_assessment
    payload["model_hash"] = model
    with pytest.raises(ConfigError, match="model_hash"):
        audit.load_artifact("context", synthetic_write(tmp_path, payload), "snapshot")


@pytest.mark.parametrize("kind", ["multiline_metadata", "model_identity"])
def test_review_rejection_preserves_existing_html_and_canonical_data(
    tmp_path, synthetic_assessment, kind
):
    store, profiles, _, payload, _ = synthetic_assessment
    if kind == "multiline_metadata":
        profiles[0].exposure = replace(
            profiles[0].exposure,
            evidence="scope.yaml lab_targets[SYNTHETIC\ntarget].tags.vantage=external",
        )
        store.upsert_profile("snapshot", profiles[0])
    else:
        payload["model_hash"] = "a" * 16
    snapshot = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
    payload["snapshot_hash"] = snapshot["snapshot_hash"]
    path = synthetic_write(tmp_path, payload)
    frozen = assessment_snapshot.save_snapshot(
        snapshot, tmp_path / "synthetic_rejection_snapshot.json"
    )
    report = tmp_path / "synthetic_retained_report.html"
    report.write_text("SYNTHETIC existing report", encoding="utf-8")
    before = synthetic_state(store)
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(
            [
                "--config",
                str(ROOT / "config"),
                "--db",
                str(tmp_path / "assessment.db"),
                "report",
                "--run-id",
                "snapshot",
                "--out",
                str(report),
                "--context-artifact",
                str(path),
                "--snapshot",
                str(frozen),
                "--json",
            ]
        )
    assert code == 2
    assert stdout.getvalue() == ""
    assert "context artifact" in stderr.getvalue()
    assert "Traceback" not in stderr.getvalue()
    assert report.read_text(encoding="utf-8") == "SYNTHETIC existing report"
    assert synthetic_state(store) == before
