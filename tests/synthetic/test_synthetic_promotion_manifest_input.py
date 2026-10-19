"""Synthetic manifest boundaries; declarations are not genuine model approvals."""

import json
from datetime import date
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from vulnassess import audit
from vulnassess import model_governance as governance
from vulnassess.errors import ConfigError
from vulnassess.role_model import PREPROCESSING_VERSION, RoleModel


@pytest.fixture
def manifest() -> governance.PromotionManifest:
    return governance.PromotionManifest(
        model_hash="synthetic-model-not-approved",
        preprocessing_version=PREPROCESSING_VERSION,
        test_dataset_hash="a" * 64,
        test_evidence_status="TESTED WITH MOCKS",
        label_source="synthetic",
        groups_disjoint=True,
        manual_tags_used=False,
        test_groups=4,
        metrics={"role_accuracy": 0.9, "coverage": 1, "expected_calibration_error": 0.05},
        thresholds={
            "minimum_role_accuracy": 0.85,
            "minimum_coverage": 0.8,
            "maximum_ece": 0.1,
            "prediction_confidence": 0.55,
            "prediction_margin": 0.1,
        },
        reviewer="synthetic-only \u03b4",
        approval_id="synthetic-declaration-not-approval",
        mentor_approval_id="synthetic-declaration-not-approval",
        issued_on="2026-10-01",
        expires_on="2026-10-31",
    )


@pytest.mark.parametrize("as_string", [False, True], ids=["path", "string"])
@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig"])
@pytest.mark.parametrize("pretty", [False, True], ids=["compact-ascii", "pretty-unicode"])
def test_manifest_round_trip_preserves_declarations(
    tmp_path: Path,
    manifest: governance.PromotionManifest,
    as_string: bool,
    encoding: str,
    pretty: bool,
) -> None:
    payload = manifest.to_json()
    path = tmp_path / "synthetic_promotion_manifest.json"
    path.write_text(
        json.dumps(payload, ensure_ascii=not pretty, indent=2 if pretty else None),
        encoding=encoding,
    )

    loaded = governance.load_manifest(str(path) if as_string else path)

    assert loaded == manifest
    assert loaded.to_json() == payload
    assert loaded.test_evidence_status == "TESTED WITH MOCKS"
    assert loaded.label_source == "synthetic"


@pytest.mark.parametrize(
    "key,earlier",
    [
        ("test_evidence_status", '"NOT RUN"'),
        ("label_source", '"different-synthetic-source"'),
        ("groups_disjoint", "false"),
        ("manual_tags_used", "true"),
        ("approval_id", '"different-synthetic-declaration"'),
        ("model_hash", '"different-synthetic-model"'),
        ("schema_version", "0"),
    ],
)
def test_duplicate_manifest_declarations_fail_closed(
    tmp_path: Path, manifest: governance.PromotionManifest, key: str, earlier: str
) -> None:
    path = tmp_path / "synthetic_duplicate_manifest.json"
    content = json.dumps(manifest.to_json())
    path.write_text('{"' + key + '":' + earlier + "," + content[1:], encoding="utf-8")

    with pytest.raises(ConfigError, match="duplicate key") as caught:
        governance.load_manifest(path)

    assert str(path) in str(caught.value)


@pytest.mark.parametrize("section", ["metrics", "thresholds"])
@pytest.mark.parametrize("escaped", [False, True], ids=["literal-key", "escaped-key"])
def test_nested_duplicate_numbers_fail_closed(
    tmp_path: Path, manifest: governance.PromotionManifest, section: str, escaped: bool
) -> None:
    path = tmp_path / "synthetic_duplicate_metrics.json"
    content = json.dumps(manifest.to_json())
    key = "role_accuracy" if section == "metrics" else "prediction_confidence"
    duplicate = r"\u0072ole_accuracy" if section == "metrics" else r"\u0070rediction_confidence"
    if not escaped:
        duplicate = key
    content = content.replace(f'"{section}": {{', f'"{section}": {{"{duplicate}": 0.01,', 1)
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigError, match="duplicate key") as caught:
        governance.load_manifest(path)

    assert str(path) in str(caught.value)


@pytest.mark.parametrize("section", ["metrics", "thresholds"])
@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity", "1e1000"])
def test_nonfinite_manifest_values_are_controlled_errors(
    tmp_path: Path, manifest: governance.PromotionManifest, section: str, number: str
) -> None:
    path = tmp_path / "synthetic_nonfinite_manifest.json"
    payload = manifest.to_json()
    payload[section] = {"synthetic_nonfinite": "replace-number"}
    path.write_text(json.dumps(payload).replace('"replace-number"', number), encoding="utf-8")

    with pytest.raises(ConfigError) as caught:
        governance.load_manifest(path)

    assert "promotion manifest" in str(caught.value)
    assert str(path) in str(caught.value)


@pytest.mark.parametrize("content", [b"\xff", b'{"reviewer":"\xc3("}', b"\xff\xfe{\x00}"])
def test_invalid_manifest_encoding_is_a_controlled_error(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "synthetic_invalid_encoding.json"
    path.write_bytes(content)

    with pytest.raises(ConfigError, match="invalid role-model promotion manifest") as caught:
        governance.load_manifest(path)

    assert str(path) in str(caught.value)


@pytest.mark.parametrize(
    "content,message",
    [
        (
            "[" * (audit.MAX_ARTIFACT_DEPTH + 1) + "0" + "]" * (audit.MAX_ARTIFACT_DEPTH + 1),
            "depth",
        ),
        ("[" + ",".join(["0"] * audit.MAX_ARTIFACT_NODES) + "]", "JSON nodes"),
        ("[" * 10_000 + "0" + "]" * 10_000, "recursion"),
    ],
    ids=["depth-budget", "node-budget", "decoder-recursion"],
)
def test_excessive_manifest_structure_fails_before_schema_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: str, message: str
) -> None:
    path = tmp_path / "synthetic_excessive_structure.json"
    path.write_text('{"metrics":' + content + "}", encoding="utf-8")
    constructor = Mock(side_effect=AssertionError("manifest construction must not be reached"))
    monkeypatch.setattr(governance, "PromotionManifest", constructor)

    with pytest.raises(ConfigError, match=message) as caught:
        governance.load_manifest(path)

    assert str(path) in str(caught.value)
    constructor.assert_not_called()


def test_oversized_manifest_is_rejected_before_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "synthetic_oversized_manifest.json"
    with path.open("wb") as stream:
        stream.seek(audit.MAX_ARTIFACT_BYTES)
        stream.write(b" ")
    forbidden = Mock(side_effect=AssertionError("oversized manifest must not be read"))
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)

    with pytest.raises(ConfigError, match=f"exceeds {audit.MAX_ARTIFACT_BYTES} bytes") as caught:
        governance.load_manifest(path)

    assert str(path) in str(caught.value)
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "raw_path",
    [
        "//synthetic.invalid/share/synthetic_manifest.json",
        r"\\synthetic.invalid\share\synthetic_manifest.json",
        r"\\?\UNC\synthetic.invalid\share\synthetic_manifest.json",
    ],
    ids=["forward-unc", "backward-unc", "extended-unc"],
)
def test_network_share_manifest_is_rejected_before_filesystem_access(
    monkeypatch: pytest.MonkeyPatch, raw_path: str
) -> None:
    forbidden = Mock(side_effect=AssertionError("network-share filesystem access is forbidden"))
    with monkeypatch.context() as boundary:
        for operation in ("is_file", "stat", "open", "read_bytes", "read_text"):
            boundary.setattr(Path, operation, forbidden)

        with pytest.raises(ConfigError, match="network-share") as caught:
            governance.load_manifest(raw_path)

    assert str(Path(raw_path)) in str(caught.value)
    forbidden.assert_not_called()


def test_unreadable_manifest_is_controlled_at_the_filesystem_boundary(
    tmp_path: Path, manifest: governance.PromotionManifest, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "synthetic_unreadable_manifest.json"
    path.write_text(json.dumps(manifest.to_json()), encoding="utf-8")
    monkeypatch.setattr(Path, "open", Mock(side_effect=PermissionError("synthetic denied")))

    with pytest.raises(ConfigError, match="invalid role-model promotion manifest") as caught:
        governance.load_manifest(path)

    assert str(path) in str(caught.value)


@pytest.mark.parametrize("directory", [False, True], ids=["missing-file", "directory"])
def test_missing_manifest_names_the_path(tmp_path: Path, directory: bool) -> None:
    path = tmp_path if directory else tmp_path / "synthetic_missing_manifest.json"

    with pytest.raises(ConfigError, match="MISSING: role-model promotion manifest") as caught:
        governance.load_manifest(path)

    assert str(path) in str(caught.value)


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"synthetic_unknown": True}, "unknown key"),
        ({"schema_version": True}, "schema_version"),
        ({"groups_disjoint": "true"}, "groups_disjoint"),
        ({"test_groups": 4.0}, "test_groups"),
        ({"issued_on": "synthetic-invalid"}, "ISO dates"),
    ],
)
def test_manifest_field_validation_is_preserved(
    tmp_path: Path, manifest: governance.PromotionManifest, changes: dict[str, Any], message: str
) -> None:
    path = tmp_path / "synthetic_invalid_fields.json"
    path.write_text(json.dumps({**manifest.to_json(), **changes}), encoding="utf-8")

    with pytest.raises(ConfigError, match=message) as caught:
        governance.load_manifest(path)

    assert str(path) in str(caught.value)


@pytest.mark.parametrize("content", ["null", "[]", "{}", "{invalid}"])
def test_malformed_or_incomplete_manifest_is_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "synthetic_incomplete_manifest.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigError) as caught:
        governance.load_manifest(path)

    assert str(path) in str(caught.value)


def test_loading_a_synthetic_declaration_does_not_establish_promotion(
    tmp_path: Path, manifest: governance.PromotionManifest, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "synthetic_unapproved_manifest.json"
    path.write_text(json.dumps(manifest.to_json()), encoding="utf-8")
    model = Mock(spec=RoleModel)
    model.model_hash = manifest.model_hash
    model.training = {"dataset_hash": "b" * 64, "preprocessing_version": PREPROCESSING_VERSION}
    prediction = Mock(side_effect=AssertionError("manifest loading must not invoke inference"))
    monkeypatch.setattr(RoleModel, "predict", prediction)

    loaded = governance.load_manifest(path)

    with pytest.raises(ConfigError, match="not VERIFIED.*not human-supplied"):
        governance.validate_promotion(model, loaded, as_of=date(2026, 10, 18))
    assert loaded == manifest
    prediction.assert_not_called()
    model.predict.assert_not_called()
