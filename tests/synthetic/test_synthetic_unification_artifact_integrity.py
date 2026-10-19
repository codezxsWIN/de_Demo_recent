"""Synthetic internal-consistency claims, never scanner or expert evidence."""

import io
import json
from collections.abc import Iterator
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from vulnassess import assessment_snapshot, audit, pipeline, role_model, unify
from vulnassess.cli import main
from vulnassess.errors import ConfigError
from vulnassess.schema import Finding, Host, Provenance
from vulnassess.settings import Settings
from vulnassess.store import Store


def synthetic_group_id(sources: list[str]) -> str:
    return sha256(
        ("vulnassess-unified-v1|" + "|".join(sorted(set(sources)))).encode("utf-8")
    ).hexdigest()


def synthetic_group(sources: list[str]) -> dict[str, Any]:
    return {
        "id": synthetic_group_id(sources),
        "host_ip": "192.0.2.10",
        "port": 80,
        "protocol": "tcp",
        "url": None,
        "source_finding_ids": sources,
        "tools": ["nmap"],
        "cve_ids": [],
        "method": "synthetic_group_reason",
        "confidence": 0.75,
        "justification": "SYNTHETIC loader input, no matching policy claim",
        "evidence": ["SYNTHETIC pure-logic input"],
    }


@pytest.fixture
def synthetic_artifact() -> dict[str, Any]:
    # VERIFIED is a simulated claim under test, not an assertion of authenticity.
    return {
        "run_id": "synthetic_unification_integrity",
        "snapshot_hash": "a" * 64,
        "evidence_status": "VERIFIED",
        "data_kind": "assessment_diagnostic",
        "mode": "preview_only",
        "raw_count": 3,
        "unified_count": 2,
        "duplicate_reduction": 1,
        "downstream_ranking_changed": False,
        "groups": [
            synthetic_group(["synthetic_a", "synthetic_b"]),
            synthetic_group(["synthetic_c"]),
        ],
        "candidates": [
            {
                "left_finding_id": "synthetic_a",
                "right_finding_id": "synthetic_c",
                "method": "synthetic_conservative_review_reason",
                "confidence": 0.5,
                "justification": "SYNTHETIC review candidate",
            }
        ],
    }


def synthetic_write(tmp_path: Path, payload: dict[str, Any]) -> Path:
    core = {key: value for key, value in payload.items() if key != "preview_hash"}
    path = tmp_path / "synthetic_unification_integrity.json"
    path.write_text(json.dumps({**core, "preview_hash": audit._digest(core)}), encoding="utf-8")
    return path


def synthetic_load(tmp_path: Path, payload: dict[str, Any]) -> audit.AuditArtifact:
    return audit.load_artifact(
        "unification", synthetic_write(tmp_path, payload), "synthetic_unification_integrity"
    )


def synthetic_set(payload: dict[str, Any], field: str, value: Any) -> None:
    parent: Any = payload
    parts = field.split(".")
    for part in parts[:-1]:
        parent = parent[int(part)] if isinstance(parent, list) else parent[part]
    parent[parts[-1]] = value


@pytest.mark.parametrize("status", audit.EVIDENCE_STATUSES)
@pytest.mark.parametrize(
    "field,value",
    [
        ("raw_count", True),
        ("raw_count", -1),
        ("raw_count", 3.0),
        ("raw_count", "3"),
        ("raw_count", None),
        ("raw_count", 2),
        ("raw_count", 4),
        ("unified_count", False),
        ("unified_count", 2.0),
        ("unified_count", "2"),
        ("unified_count", None),
        ("unified_count", -1),
        ("unified_count", 0),
        ("unified_count", 1),
        ("unified_count", 4),
        ("duplicate_reduction", True),
        ("duplicate_reduction", 1.0),
        ("duplicate_reduction", "1"),
        ("duplicate_reduction", None),
        ("duplicate_reduction", -1),
        ("duplicate_reduction", 0),
        ("duplicate_reduction", 3),
        ("downstream_ranking_changed", True),
        ("downstream_ranking_changed", 0),
        ("downstream_ranking_changed", "false"),
        ("downstream_ranking_changed", None),
        ("groups", {}),
        ("groups", "synthetic_groups"),
        ("groups", None),
        ("groups", [None]),
        ("groups.0.source_finding_ids", "synthetic_a"),
        ("groups.0.source_finding_ids", None),
        ("groups.0.source_finding_ids", []),
        ("groups.0.source_finding_ids", ["synthetic_a", "synthetic_a"]),
        ("groups.0.source_finding_ids", ["synthetic_a", 1]),
        ("groups.0.source_finding_ids", ["synthetic_a", True]),
        ("groups.0.source_finding_ids", ["synthetic_a", " "]),
        ("groups.0.source_finding_ids", ["synthetic_a", "synthetic_unknown"]),
        ("groups.0.id", "f" * 64),
        ("groups.0.id", 1),
        ("groups.0.id", None),
        ("groups.0.id", ""),
        ("candidates", {}),
        ("candidates", "synthetic_candidates"),
        ("candidates", None),
        ("candidates", [None]),
        ("candidates.0.left_finding_id", "synthetic_unknown"),
        ("candidates.0.right_finding_id", "synthetic_unknown"),
        ("candidates.0.left_finding_id", "synthetic_c"),
        ("candidates.0.left_finding_id", True),
        ("candidates.0.right_finding_id", None),
        ("candidates.0.left_finding_id", " "),
        ("candidates.0.method", False),
        ("candidates.0.method", " "),
        ("candidates.0.confidence", True),
        ("candidates.0.confidence", "0.5"),
        ("candidates.0.confidence", -0.1),
        ("candidates.0.confidence", 1.1),
    ],
)
def test_synthetic_rehashed_contradictions_fail_closed(
    tmp_path: Path, synthetic_artifact: dict[str, Any], status: str, field: str, value: Any
) -> None:
    synthetic_artifact["evidence_status"] = status
    synthetic_set(synthetic_artifact, field, value)
    with pytest.raises(ConfigError, match="invalid unification audit artifact"):
        synthetic_load(tmp_path, synthetic_artifact)


@pytest.mark.parametrize("status", audit.EVIDENCE_STATUSES)
@pytest.mark.parametrize("case", ["source_overlap", "group_id", "candidate", "reverse_candidate"])
def test_synthetic_duplicate_references_fail_closed(
    tmp_path: Path, synthetic_artifact: dict[str, Any], status: str, case: str
) -> None:
    synthetic_artifact["evidence_status"] = status
    if case == "source_overlap":
        synthetic_artifact["groups"][1] = synthetic_group(["synthetic_b"])
    elif case == "group_id":
        synthetic_artifact["groups"][1]["id"] = synthetic_artifact["groups"][0]["id"]
    else:
        candidate = deepcopy(synthetic_artifact["candidates"][0])
        if case == "reverse_candidate":
            candidate["left_finding_id"], candidate["right_finding_id"] = (
                candidate["right_finding_id"],
                candidate["left_finding_id"],
            )
            candidate["method"] = "synthetic_other_review_reason"
        synthetic_artifact["candidates"].append(candidate)
    with pytest.raises(ConfigError, match="invalid unification audit artifact"):
        synthetic_load(tmp_path, synthetic_artifact)


@pytest.mark.parametrize(
    "field",
    [
        "unified_count",
        "duplicate_reduction",
        "downstream_ranking_changed",
        "groups.0.source_finding_ids",
        "groups.0.id",
        "candidates.0.left_finding_id",
        "candidates.0.right_finding_id",
    ],
)
def test_synthetic_verified_requires_aggregate_support(
    tmp_path: Path, synthetic_artifact: dict[str, Any], field: str
) -> None:
    parent: Any = synthetic_artifact
    parts = field.split(".")
    for part in parts[:-1]:
        parent = parent[int(part)] if isinstance(parent, list) else parent[part]
    del parent[parts[-1]]
    with pytest.raises(ConfigError, match="invalid unification audit artifact"):
        synthetic_load(tmp_path, synthetic_artifact)


@pytest.mark.parametrize("status", audit.EVIDENCE_STATUSES)
@pytest.mark.parametrize(
    "method",
    [
        "shared_cve_unresolved_instance",
        "shared_cve_overlap_candidate",
        "synthetic future review reason: punctuation / spaces allowed",
    ],
)
def test_synthetic_consistent_claim_round_trips_without_authenticating_it(
    tmp_path: Path, synthetic_artifact: dict[str, Any], status: str, method: str
) -> None:
    synthetic_artifact["evidence_status"] = status
    synthetic_artifact["groups"][0]["source_finding_ids"].reverse()
    # A review link within one group is legal; the loader does not re-run matching policy.
    synthetic_artifact["candidates"][0]["right_finding_id"] = "synthetic_b"
    synthetic_artifact["candidates"][0]["method"] = method
    original = deepcopy(synthetic_artifact)
    loaded = synthetic_load(tmp_path, synthetic_artifact)
    assert loaded.evidence_status == status
    assert loaded.row()["evidence_status"] == status
    assert {
        key: value for key, value in loaded.payload.items() if key != "preview_hash"
    } == original
    assert synthetic_artifact == original
    assert "3 raw -> 2 groups" in loaded.summary


@pytest.mark.parametrize("size", [0, 1, 3])
def test_synthetic_current_producer_outputs_are_usable(tmp_path: Path, size: int) -> None:
    findings = [
        Finding.make(
            host_ip="192.0.2.10",
            port=80,
            protocol="tcp",
            tool="nmap",
            tool_native_id=f"synthetic_{index}",
            title=f"SYNTHETIC pure-logic finding {index}",
            description="SYNTHETIC loader input",
            evidence="SYNTHETIC input, never scanner evidence",
            cve_ids=(),
            cwe_ids=(),
            first_seen="2026-10-18T00:00:00Z",
            last_seen="2026-10-18T00:00:00Z",
            provenance=Provenance(
                "nmap", "tests/synthetic/synthetic_unification_input.json", index, "synthetic"
            ),
        )
        for index in range(size)
    ]
    payload = {
        "run_id": "synthetic_unification_integrity",
        "evidence_status": "VERIFIED",
        "mode": "preview_only",
        "downstream_ranking_changed": False,
        **unify.unify_findings(findings).to_json(),
    }
    loaded = synthetic_load(tmp_path, payload)
    assert loaded.payload["raw_count"] == size
    assert loaded.payload["unified_count"] == size
    assert loaded.payload["duplicate_reduction"] == 0


@pytest.mark.parametrize("status", ["NOT RUN", "MISSING", "TESTED WITH MOCKS"])
@pytest.mark.parametrize("groups", [[], [{}], [{"source_finding_ids": ["synthetic_a"]}]])
def test_synthetic_sparse_legacy_facts_stay_unknown(
    tmp_path: Path, status: str, groups: list[dict[str, Any]]
) -> None:
    payload = {
        "run_id": "synthetic_unification_integrity",
        "evidence_status": status,
        "raw_count": len(groups),
        "groups": groups,
        "candidates": [],
    }
    loaded = synthetic_load(tmp_path, payload)
    assert loaded.evidence_status == status
    assert loaded.payload == {**payload, "preview_hash": audit._digest(payload)}
    for field in ("unified_count", "duplicate_reduction", "downstream_ranking_changed"):
        assert field not in loaded.payload
    assert "None groups" in loaded.summary
    assert "ranking changed=None" in loaded.summary


@pytest.mark.parametrize(
    "raw_count,groups,reduction,candidates",
    [
        (1, [], None, []),
        (0, [{}], None, []),
        (1, [{}, {}], None, []),
        (2, [synthetic_group(["synthetic_a", "synthetic_b"]), {}], None, []),
        (2, [{}, {}], 1, []),
        (2, [{}], 3, []),
        (1, [{}], None, [{"left_finding_id": "synthetic_a", "right_finding_id": "synthetic_b"}]),
        (1, [synthetic_group(["synthetic_a"])], None, [{"left_finding_id": "synthetic_unknown"}]),
    ],
)
def test_synthetic_partial_legacy_contradictions_are_rejected(
    tmp_path: Path,
    raw_count: int,
    groups: list[dict[str, Any]],
    reduction: int | None,
    candidates: list[dict[str, Any]],
) -> None:
    payload = {
        "run_id": "synthetic_unification_integrity",
        "evidence_status": "NOT RUN",
        "raw_count": raw_count,
        "groups": groups,
        "candidates": candidates,
    }
    if reduction is not None:
        payload["duplicate_reduction"] = reduction
    with pytest.raises(ConfigError, match="invalid unification audit artifact"):
        synthetic_load(tmp_path, payload)


def test_synthetic_partial_candidate_membership_stays_unknown(tmp_path: Path) -> None:
    payload = {
        "run_id": "synthetic_unification_integrity",
        "evidence_status": "NOT RUN",
        "raw_count": 2,
        "groups": [{}],
        "candidates": [{"left_finding_id": "synthetic_a", "right_finding_id": "synthetic_b"}],
    }
    loaded = synthetic_load(tmp_path, payload)
    assert loaded.payload["groups"] == [{}]
    assert loaded.evidence_status == "NOT RUN"


@pytest.fixture
def synthetic_report_bundle(
    tmp_path: Path,
) -> Iterator[tuple[Settings, Store, dict[str, Any], Path]]:
    settings = Settings(Path(__file__).resolve().parents[2] / "config")
    run_id = "synthetic_unification_integrity"
    with Store(tmp_path / "synthetic_assessment.db") as store:
        store.start_run(run_id, settings.config_hash())
        store.upsert_host(run_id, Host("192.0.2.10"))
        store.upsert_findings(
            run_id,
            [
                Finding.make(
                    host_ip="192.0.2.10",
                    port=80,
                    protocol="tcp",
                    url=f"http://192.0.2.10/synthetic_{index}",
                    tool="nmap",
                    tool_native_id=f"synthetic_{index}",
                    title="SYNTHETIC title for review-only correlation",
                    description="SYNTHETIC report binding input",
                    evidence=f"SYNTHETIC pure-logic observation {index}",
                    provenance=Provenance(
                        "nmap", "tests/synthetic/synthetic_binding.json", index, run_id
                    ),
                )
                for index in range(2)
            ],
        )
        snapshot = assessment_snapshot.build_snapshot(settings, store, run_id)
        snapshot_path = assessment_snapshot.save_snapshot(
            snapshot, tmp_path / "synthetic_report_snapshot.json"
        )
        payload = {
            "run_id": run_id,
            "snapshot_hash": snapshot["snapshot_hash"],
            "evidence_status": "VERIFIED",  # Simulated claim only.
            "mode": "preview_only",
            "downstream_ranking_changed": False,
            **unify.unify_run(store, run_id).to_json(),
        }
        assert len(payload["candidates"]) == 1
        yield settings, store, payload, snapshot_path


def synthetic_report(
    settings: Settings, store: Store, path: Path, snapshot_path: Path | None, **kwargs: Any
) -> dict[str, Any]:
    return audit.collect_report_audit(
        settings,
        store,
        "synthetic_unification_integrity",
        snapshot_path=snapshot_path,
        artifact_paths={"unification": path},
        **kwargs,
    )


def synthetic_database_state(store: Store) -> tuple[int, list[str]]:
    return store.connection.total_changes, list(store.connection.iterdump())


@pytest.mark.parametrize("frozen", [False, True])
@pytest.mark.parametrize(
    "change",
    [
        "invented_source",
        "invented_grouping",
        "omitted_source",
        "group_evidence",
        "group_host",
        "group_method",
        "candidate_method",
        "candidate_confidence",
        "omitted_candidate",
    ],
)
def test_synthetic_report_checks_current_sources_and_recomputed_preview(
    tmp_path: Path, synthetic_report_bundle: tuple, frozen: bool, change: str
) -> None:
    settings, store, payload, snapshot_path = synthetic_report_bundle
    if change == "invented_source":
        original_id = payload["groups"][0]["source_finding_ids"][0]
        payload["groups"][0]["source_finding_ids"] = ["synthetic_invented_source"]
        payload["groups"][0]["id"] = synthetic_group_id(["synthetic_invented_source"])
        for key in ("left_finding_id", "right_finding_id"):
            if payload["candidates"][0][key] == original_id:
                payload["candidates"][0][key] = "synthetic_invented_source"
    elif change == "invented_grouping":
        sources = [source for group in payload["groups"] for source in group["source_finding_ids"]]
        payload["groups"] = [synthetic_group(sources)]
        payload["unified_count"] = 1
        payload["duplicate_reduction"] = 1
        payload["candidates"] = []
    elif change == "omitted_source":
        payload["groups"] = payload["groups"][:1]
        payload["raw_count"] = payload["unified_count"] = 1
        payload["candidates"] = []
    elif change == "group_evidence":
        payload["groups"][0]["evidence"] = ["SYNTHETIC invented observation"]
    elif change == "group_host":
        payload["groups"][0]["host_ip"] = "192.0.2.99"
    elif change == "group_method":
        payload["groups"][0]["method"] = "synthetic unsupported grouping reason"
    elif change == "candidate_method":
        payload["candidates"][0]["method"] = "synthetic different review reason"
    elif change == "candidate_confidence":
        payload["candidates"][0]["confidence"] = 0.25
    else:
        payload["candidates"] = []
    path = synthetic_write(tmp_path, payload)
    original_bytes, before = path.read_bytes(), synthetic_database_state(store)
    # Coherent bytes and a copied *real current* snapshot hash are insufficient.
    assert synthetic_load(tmp_path, payload).evidence_status == "VERIFIED"
    with pytest.raises(ConfigError, match="unification artifact.*current"):
        synthetic_report(settings, store, path, snapshot_path if frozen else None)
    assert path.read_bytes() == original_bytes
    assert synthetic_database_state(store) == before


@pytest.mark.parametrize("frozen", [False, True])
def test_synthetic_report_accepts_exact_current_preview_without_mutation(
    tmp_path: Path, synthetic_report_bundle: tuple, frozen: bool
) -> None:
    settings, store, payload, snapshot_path = synthetic_report_bundle
    path = synthetic_write(tmp_path, payload)
    original_bytes, before = path.read_bytes(), synthetic_database_state(store)
    result = synthetic_report(settings, store, path, snapshot_path if frozen else None)
    assert result["unification"] == synthetic_load(tmp_path, payload).payload
    assert set(
        source
        for group in result["unification"]["groups"]
        for source in group["source_finding_ids"]
    ) == {finding.id for finding in store.findings(payload["run_id"])}
    row = next(row for row in result["rows"] if row["component"] == "unification")
    assert row["evidence_status"] == "VERIFIED"
    assert path.read_bytes() == original_bytes
    assert synthetic_database_state(store) == before


@pytest.mark.parametrize("frozen", [False, True])
@pytest.mark.parametrize("binding", ["missing_snapshot", "stale_snapshot", "model_hash", "run_id"])
def test_synthetic_report_requires_applicable_snapshot_model_and_run_bindings(
    tmp_path: Path, synthetic_report_bundle: tuple, frozen: bool, binding: str
) -> None:
    settings, store, payload, snapshot_path = synthetic_report_bundle
    if binding == "missing_snapshot":
        del payload["snapshot_hash"]
    elif binding == "stale_snapshot":
        payload["snapshot_hash"] = "f" * 64
    elif binding == "model_hash":
        payload["model_hash"] = "synthetic_other_model"
    else:
        payload["run_id"] = "synthetic_other_run"
    path = synthetic_write(tmp_path, payload)
    original_bytes, before = path.read_bytes(), synthetic_database_state(store)
    with pytest.raises(ConfigError, match="unification.*(snapshot|model_hash|run)"):
        synthetic_report(settings, store, path, snapshot_path if frozen else None)
    assert path.read_bytes() == original_bytes
    assert synthetic_database_state(store) == before


@pytest.mark.parametrize("matching", [False, True])
@pytest.mark.parametrize("frozen", [False, True])
def test_synthetic_report_checks_selected_model_when_binding_preview(
    tmp_path: Path, synthetic_report_bundle: tuple, matching: bool, frozen: bool
) -> None:
    settings, store, payload, _ = synthetic_report_bundle
    model_path = Path(__file__).resolve().parents[2] / "models" / "synthetic-role-model.json"
    model_hash = role_model.load_model(model_path).model_hash
    snapshot = assessment_snapshot.build_snapshot(
        settings,
        store,
        payload["run_id"],
        model_hash=model_hash if matching else "synthetic_other_model",
    )
    snapshot_path = assessment_snapshot.save_snapshot(
        snapshot, tmp_path / "synthetic_model_snapshot.json"
    )
    payload["snapshot_hash"] = snapshot["snapshot_hash"]
    payload["model_hash"] = snapshot["model_hash"]
    path = synthetic_write(tmp_path, payload)
    original_bytes, before = path.read_bytes(), synthetic_database_state(store)
    if matching:
        result = synthetic_report(
            settings, store, path, snapshot_path if frozen else None, model_path=model_path
        )
        assert result["unification"]["model_hash"] == model_hash
    else:
        with pytest.raises(ConfigError, match="unification.*model_hash"):
            synthetic_report(
                settings, store, path, snapshot_path if frozen else None, model_path=model_path
            )
    assert path.read_bytes() == original_bytes
    assert synthetic_database_state(store) == before


@pytest.mark.parametrize("frozen", [False, True])
def test_synthetic_report_keeps_sparse_legacy_attachment_unknown(
    tmp_path: Path, synthetic_report_bundle: tuple, frozen: bool
) -> None:
    settings, store, payload, snapshot_path = synthetic_report_bundle
    for field in (
        "unified_count",
        "duplicate_reduction",
        "downstream_ranking_changed",
        "snapshot_hash",
    ):
        del payload[field]
    payload["evidence_status"] = "NOT RUN"
    payload["groups"] = [{}, {}]
    payload["candidates"] = []
    path = synthetic_write(tmp_path, payload)
    original_bytes, before = path.read_bytes(), synthetic_database_state(store)
    result = synthetic_report(settings, store, path, snapshot_path if frozen else None)
    assert result["unification"] == synthetic_load(tmp_path, payload).payload
    row = next(row for row in result["rows"] if row["component"] == "unification")
    assert row["evidence_status"] == "NOT RUN"
    assert "None groups" in row["summary"]
    assert any(
        "unification" in text.lower() and "unknown" in text.lower()
        for text in result["limitations"]
    )
    assert path.read_bytes() == original_bytes
    assert synthetic_database_state(store) == before


def test_synthetic_cli_rejects_false_preview_before_html_writing(
    tmp_path: Path, synthetic_report_bundle: tuple, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, store, payload, snapshot_path = synthetic_report_bundle
    payload["groups"][0]["evidence"] = ["SYNTHETIC forged observation"]
    path = synthetic_write(tmp_path, payload)
    output_path = tmp_path / "synthetic_preserved_report.html"
    output_path.write_text("SYNTHETIC prior report", encoding="utf-8")
    original_bytes, before = path.read_bytes(), synthetic_database_state(store)
    writer = Mock(return_value=output_path)
    monkeypatch.setattr(pipeline, "do_report", writer)
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors:
        code = main(
            [
                "--config",
                str(settings.config_dir),
                "--db",
                str(store.path),
                "report",
                "--run-id",
                payload["run_id"],
                "--snapshot",
                str(snapshot_path),
                "--unification-artifact",
                str(path),
                "--out",
                str(output_path),
            ]
        )
    assert code == 2
    assert "unification artifact" in errors.getvalue()
    writer.assert_not_called()
    assert output_path.read_text(encoding="utf-8") == "SYNTHETIC prior report"
    assert path.read_bytes() == original_bytes
    assert synthetic_database_state(store) == before


@pytest.mark.parametrize("field", ["raw_count", "unified_count", "duplicate_reduction"])
def test_synthetic_booleans_are_not_counts_even_when_numerically_equal(
    tmp_path: Path, field: str
) -> None:
    payload = {
        "run_id": "synthetic_unification_integrity",
        "evidence_status": "VERIFIED",
        "raw_count": 1,
        "unified_count": 1,
        "duplicate_reduction": 0,
        "downstream_ranking_changed": False,
        "groups": [synthetic_group(["synthetic_a"])],
        "candidates": [],
    }
    payload[field] = bool(payload[field])
    with pytest.raises(ConfigError, match="nonnegative integer"):
        synthetic_load(tmp_path, payload)


@pytest.mark.parametrize("frozen", [False, True])
def test_synthetic_empty_current_preview_can_be_reported(tmp_path: Path, frozen: bool) -> None:
    settings = Settings(Path(__file__).resolve().parents[2] / "config")
    run_id = "synthetic_unification_integrity"
    with Store(tmp_path / "synthetic_empty.db") as store:
        store.start_run(run_id, settings.config_hash())
        snapshot = assessment_snapshot.build_snapshot(settings, store, run_id)
        snapshot_path = assessment_snapshot.save_snapshot(
            snapshot, tmp_path / "synthetic_empty_snapshot.json"
        )
        payload = {
            "run_id": run_id,
            "evidence_status": "VERIFIED",  # Simulated claim, no scanner execution.
            "snapshot_hash": snapshot["snapshot_hash"],
            "downstream_ranking_changed": False,
            **unify.unify_run(store, run_id).to_json(),
        }
        path = synthetic_write(tmp_path, payload)
        before = synthetic_database_state(store)
        result = synthetic_report(settings, store, path, snapshot_path if frozen else None)
        assert result["unification"]["groups"] == []
        assert result["unification"]["candidates"] == []
        assert result["unification"]["duplicate_reduction"] == 0
        assert synthetic_database_state(store) == before


def test_synthetic_actual_producer_model_binding_needs_no_new_artifact_field(
    tmp_path: Path, synthetic_report_bundle: tuple
) -> None:
    settings, store, payload, _ = synthetic_report_bundle
    model_path = Path(__file__).resolve().parents[2] / "models" / "synthetic-role-model.json"
    snapshot = assessment_snapshot.build_snapshot(
        settings, store, payload["run_id"], model_hash=role_model.load_model(model_path).model_hash
    )
    snapshot_path = assessment_snapshot.save_snapshot(
        snapshot, tmp_path / "synthetic_producer_model_snapshot.json"
    )
    payload["snapshot_hash"] = snapshot["snapshot_hash"]
    assert "model_hash" not in payload  # This is the current producer's artifact shape.
    path = synthetic_write(tmp_path, payload)
    before = synthetic_database_state(store)
    result = synthetic_report(settings, store, path, snapshot_path, model_path=model_path)
    assert "model_hash" not in result["unification"]
    assert synthetic_database_state(store) == before


def test_synthetic_later_assessment_drift_cannot_reuse_initial_snapshot_check(
    tmp_path: Path, synthetic_report_bundle: tuple, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, store, payload, snapshot_path = synthetic_report_bundle
    path = synthetic_write(tmp_path, payload)
    original_bytes = path.read_bytes()
    original = assessment_snapshot.build_snapshot
    calls = 0

    def drift_after_initial_validation(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        captured = original(*args, **kwargs)
        if calls == 1:
            store.upsert_host(
                payload["run_id"], Host("192.0.2.10", hostname="SYNTHETIC later host")
            )
        return captured

    monkeypatch.setattr(assessment_snapshot, "build_snapshot", drift_after_initial_validation)
    with pytest.raises(ConfigError, match="unification.*snapshot"):
        synthetic_report(settings, store, path, snapshot_path)
    assert path.read_bytes() == original_bytes


@pytest.mark.parametrize("model", [False, 1, "", [], {}])
def test_synthetic_optional_artifact_model_identity_cannot_have_the_wrong_type(
    tmp_path: Path, synthetic_artifact: dict[str, Any], model: Any
) -> None:
    synthetic_artifact["model_hash"] = model
    with pytest.raises(ConfigError, match="unification.*model_hash"):
        synthetic_load(tmp_path, synthetic_artifact)
