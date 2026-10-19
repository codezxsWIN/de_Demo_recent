"""Strict loading of hash-bound artifacts shown in audit reports."""

import json
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from math import isfinite
from pathlib import Path
from typing import Any, Mapping

from vulnassess.context_eval import (
    ABSTAIN,
    CONTROL_KEYS,
    EXPOSURES,
    MISSING,
    ROLES,
    _control_label,
    _feature_provenance,
)
from vulnassess.errors import ConfigError

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_DEPTH = 128
MAX_ARTIFACT_NODES = 200_000
EVIDENCE_STATUSES = ("VERIFIED", "TESTED WITH MOCKS", "NOT RUN", "MISSING")
ARTIFACT_SPECS = {
    "scan": ("summary_hash", "run_id", ("executed", "notice")),
    "context": ("evaluation_hash", "run_id", ("rule_role", "exposure", "h1")),
    "ranking": ("evaluation_hash", "run_id", ("methods", "h2", "h3")),
    "ablation": ("experiment_hash", "run_id", ("scenarios", "comparisons", "orders")),
    "stability": ("stability_hash", "run_id", ("deterministic", "score_hashes")),
    "unification": ("preview_hash", "run_id", ("groups", "candidates", "raw_count")),
    "rescan": ("comparison_hash", "after", ("outcomes", "counts", "interpretation")),
}


def _canonical(payload: Any) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _digest(payload: Any) -> str:
    return sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError(f"non-finite number {value}")


def _guard_structure(payload: Any) -> None:
    stack = [(payload, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_ARTIFACT_NODES:
            raise ValueError(f"artifact exceeds {MAX_ARTIFACT_NODES} JSON nodes")
        if depth > MAX_ARTIFACT_DEPTH:
            raise ValueError(f"artifact exceeds JSON depth {MAX_ARTIFACT_DEPTH}")
        if isinstance(value, float) and not isfinite(value):
            raise ValueError(f"non-finite number {value}")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)


def load_json_payload(
    path: str | Path,
    label: str,
    *,
    max_bytes: int = MAX_ARTIFACT_BYTES,
) -> Any:
    path = Path(path)
    rendered = str(path)
    if rendered.startswith("\\\\") or rendered.startswith("//"):
        raise ConfigError(f"{label}: network-share artifact paths are forbidden: {path}")
    if not path.is_file():
        raise ConfigError(f"MISSING: {label} {path}")
    try:
        size = path.stat().st_size
        if size > max_bytes:
            raise ConfigError(f"{label} {path} exceeds {max_bytes} bytes")
        with path.open("rb") as stream:
            content = stream.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise ConfigError(f"{label} {path} exceeds {max_bytes} bytes")
        payload = json.loads(
            content.decode("utf-8-sig"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
        _guard_structure(payload)
    except ConfigError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise ConfigError(f"invalid {label} {path}: {error}") from error
    return payload


@dataclass(frozen=True)
class AuditArtifact:
    kind: str
    path: str
    artifact_hash: str
    evidence_status: str
    summary: str
    payload: dict[str, Any]

    def row(self) -> dict[str, str]:
        return {
            "component": self.kind,
            "evidence_status": self.evidence_status,
            "artifact_hash": self.artifact_hash,
            "summary": self.summary,
            "path": self.path,
        }


def _summary(kind: str, payload: Mapping[str, Any]) -> str:
    if kind == "scan":
        if not payload["executed"]:
            missing = ", ".join(payload.get("missing", [])) or "none reported"
            return f"planned only; missing binaries: {missing}"
        return (
            f"success={payload.get('successful_tools', 0)}, "
            f"failed={payload.get('failed_tools', 0)}, "
            f"skipped={payload.get('skipped_tools', 0)}"
        )
    if kind == "context":
        return (
            f"role accuracy={payload['rule_role'].get('accuracy')}, "
            f"exposure accuracy={payload['exposure'].get('accuracy')}, "
            f"H1 eligible={payload['h1'].get('eligible')}"
        )
    if kind == "ranking":
        ours = payload["methods"].get("ours", payload["methods"].get("full", {}))
        return (
            f"mean tau-b={ours.get('tau_b_mean')}, NDCG@10={ours.get('ndcg_at_10_mean')}, "
            f"H2 eligible={payload['h2'].get('eligible')}, "
            f"H3 eligible={payload['h3'].get('eligible')}"
        )
    if kind == "ablation":
        return (
            f"{len(payload['scenarios'])} scenarios; "
            f"inactive={len(payload.get('inactive_scenarios', []))}"
        )
    if kind == "stability":
        return (
            f"deterministic={payload['deterministic']}; "
            f"{payload.get('unique_score_hashes')} unique hashes across "
            f"{payload.get('repeats')} repeats; input={payload.get('input_evidence_status')}"
        )
    if kind == "unification":
        return (
            f"{payload['raw_count']} raw -> {payload.get('unified_count')} groups; "
            f"{len(payload['candidates'])} review candidates; ranking changed="
            f"{payload.get('downstream_ranking_changed')}"
        )
    counts = payload["counts"]
    return (
        f"still_open={counts.get('still_open')}, fixed_candidate={counts.get('fixed_candidate')}, "
        f"not_observable={counts.get('not_observable')}, "
        f"regression_candidate={counts.get('regression_candidate')}"
    )


def _context_metrics(
    metrics: Any,
    name: str,
    *,
    complete: bool,
    hosts: int | None,
    missing_profiles: int | None = None,
) -> None:
    """Check supplied classification facts without filling absent legacy metrics."""
    if not isinstance(metrics, dict):
        raise ValueError(f"{name} must be an object")
    rates = (
        "accuracy",
        "coverage",
        "abstention_rate",
        "missing_rate",
        "selective_accuracy",
        "macro_f1",
    )
    if complete:
        missing = {"examples", *rates, "confusion_matrix", "per_class"} - metrics.keys()
        if missing:
            raise ValueError(f"{name} missing metric {sorted(missing)[0]}")
    examples = metrics.get("examples")
    if "examples" in metrics:
        if type(examples) is not int or examples < 0:
            raise ValueError(f"{name}.examples must be a nonnegative integer")
        if hosts is not None and (
            examples > hosts if name.startswith("controls.") else examples != hosts
        ):
            raise ValueError(f"{name}.examples disagrees with truth_hosts")
    for key in rates:
        if key not in metrics:
            continue
        value = metrics[key]
        if value is not None and (type(value) not in (int, float) or not 0 <= value <= 1):
            raise ValueError(f"{name}.{key} must be a number in [0, 1] or null")
        if examples == 0 and value is not None:
            raise ValueError(f"{name}.{key} is undefined with zero examples")
        if examples is not None and examples > 0 and key in rates[:4] and value is None:
            raise ValueError(f"{name}.{key} requires a value with positive examples")
    accuracy, coverage = metrics.get("accuracy"), metrics.get("coverage")
    missing_rate, abstention = metrics.get("missing_rate"), metrics.get("abstention_rate")
    tolerance = 0.000002  # Classification output is rounded to six decimal places.
    if accuracy is not None and coverage is not None and accuracy > coverage + tolerance:
        raise ValueError(f"{name}.accuracy exceeds coverage")
    if coverage is not None:
        for key in ("missing_rate", "abstention_rate"):
            if metrics.get(key) is not None and coverage + metrics[key] > 1 + tolerance:
                raise ValueError(f"{name}.coverage contradicts {key}")
        if (
            missing_rate is not None
            and abstention is not None
            and coverage + missing_rate + abstention < 1 - tolerance
        ):
            raise ValueError(f"{name}.coverage leaves unaccounted examples")
    if missing_profiles is not None and examples and missing_rate is not None:
        if abs(missing_rate - missing_profiles / examples) > tolerance:
            raise ValueError(f"{name}.missing_rate disagrees with missing_profile_hosts")
    if "selective_accuracy" in metrics and coverage is not None:
        selective = metrics["selective_accuracy"]
        if coverage == 0 and selective is not None:
            raise ValueError(f"{name}.selective_accuracy is undefined without coverage")
        if coverage > 0 and accuracy is not None:
            # Compare products to avoid amplifying the rounding error at low coverage.
            if selective is None or abs(accuracy - coverage * selective) > tolerance:
                raise ValueError(f"{name}.selective_accuracy contradicts accuracy and coverage")

    matrix = metrics.get("confusion_matrix")
    class_metrics: dict[str, dict[str, float]] = {}
    if "confusion_matrix" in metrics:
        classes = (
            ("false", "true")
            if name.startswith("controls.")
            else EXPOSURES
            if name == "exposure"
            else ROLES
        )
        if not isinstance(matrix, dict) or any(
            label not in classes
            or not isinstance(row, dict)
            or set(row) - {*classes, ABSTAIN, MISSING}
            or any(type(count) is not int or count < 0 for count in row.values())
            for label, row in matrix.items()
        ):
            raise ValueError(
                f"{name}.confusion_matrix requires supported labels and nonnegative integer counts"
            )
        total = sum(sum(row.values()) for row in matrix.values())
        if examples is not None and total != examples:
            raise ValueError(f"{name}.confusion_matrix disagrees with examples")
        if total:
            missing_count = sum(row.get("__missing__", 0) for row in matrix.values())
            abstain_count = sum(row.get("__abstain__", 0) for row in matrix.values())
            derived = {
                "accuracy": sum(row.get(label, 0) for label, row in matrix.items()) / total,
                "coverage": (total - missing_count - abstain_count) / total,
                "missing_rate": missing_count / total,
            }
            for key, expected in derived.items():
                if metrics.get(key) is not None and abs(metrics[key] - expected) > tolerance:
                    raise ValueError(f"{name}.{key} contradicts confusion_matrix")
            # A missing prediction may also have its abstention flag set.
            if abstention is not None and not (
                abstain_count / total - tolerance
                <= abstention
                <= (abstain_count + missing_count) / total + tolerance
            ):
                raise ValueError(f"{name}.abstention_rate contradicts confusion_matrix")
        predicted_counts: dict[str, int] = {}
        for row in matrix.values():
            for column, count in row.items():
                predicted_counts[column] = predicted_counts.get(column, 0) + count
        supported_f1: list[float] = []
        for label, row in matrix.items():
            support = sum(row.values())
            true_positive = row.get(label, 0)
            predicted = predicted_counts.get(label, 0)
            precision = true_positive / predicted if predicted else 0.0
            recall = true_positive / support if support else 0.0
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
            class_metrics[label] = {"precision": precision, "recall": recall, "f1": f1}
            if support:
                supported_f1.append(f1)
        if "macro_f1" in metrics:
            expected_f1 = sum(supported_f1) / len(supported_f1) if supported_f1 else None
            actual_f1 = metrics["macro_f1"]
            if (actual_f1 is None) != (expected_f1 is None) or (
                actual_f1 is not None
                and expected_f1 is not None
                and abs(actual_f1 - expected_f1) > tolerance
            ):
                raise ValueError(f"{name}.macro_f1 contradicts confusion_matrix")
    per_class = metrics.get("per_class")
    if "per_class" in metrics:
        if not isinstance(per_class, dict):
            raise ValueError(f"{name}.per_class must be an object")
        if matrix is not None and per_class.keys() != matrix.keys():
            raise ValueError(f"{name}.per_class labels contradict confusion_matrix")
        for label, values in per_class.items():
            if not isinstance(values, dict):
                raise ValueError(f"{name}.per_class.{label} must be an object")
            if "support" in values:
                support = values["support"]
                if type(support) is not int or support < 0:
                    raise ValueError(
                        f"{name}.per_class.{label}.support must be nonnegative integer"
                    )
                if examples is not None and support > examples:
                    raise ValueError(f"{name}.per_class.{label}.support exceeds examples")
                if matrix is not None and support != sum(matrix.get(label, {}).values()):
                    raise ValueError(
                        f"{name}.per_class.{label}.support contradicts confusion_matrix"
                    )
            for key in ("precision", "recall", "f1"):
                if key in values and (
                    type(values[key]) not in (int, float) or not 0 <= values[key] <= 1
                ):
                    raise ValueError(f"{name}.per_class.{label}.{key} must be in [0, 1]")
                if (
                    key in values
                    and matrix is not None
                    and (
                        label not in class_metrics
                        or abs(values[key] - class_metrics[label][key]) > tolerance
                    )
                ):
                    raise ValueError(f"{name}.per_class.{label}.{key} contradicts confusion_matrix")


def _validate_context_artifact(payload: Mapping[str, Any]) -> None:
    """Validate internal claims only; a hash does not authenticate human reviewers."""
    model_hash = payload.get("model_hash")
    if model_hash is not None and (not isinstance(model_hash, str) or not model_hash.strip()):
        raise ValueError("model_hash must be a nonblank string or null")
    verified = payload["evidence_status"] == "VERIFIED"
    if "status" in payload and payload["status"] != payload["evidence_status"]:
        raise ValueError("status contradicts evidence_status")
    if verified:
        required = {
            "status",
            "data_kind",
            "manual_tags_used",
            "truth_hosts",
            "truth_groups",
            "missing_profile_hosts",
        }
        missing = required - payload.keys()
        if missing:
            raise ValueError(f"VERIFIED context missing {sorted(missing)[0]}")
    if "manual_tags_used" in payload and type(payload["manual_tags_used"]) is not bool:
        raise ValueError("manual_tags_used must be a boolean")
    if "data_kind" in payload and (
        not isinstance(payload["data_kind"], str) or not payload["data_kind"].strip()
    ):
        raise ValueError("data_kind must be a nonempty string")
    for key in ("truth_hosts", "truth_groups"):
        if key in payload and (type(payload[key]) is not int or payload[key] <= 0):
            raise ValueError(f"{key} must be a positive integer")
    hosts, groups = payload.get("truth_hosts"), payload.get("truth_groups")
    if hosts is not None and groups is not None and groups > hosts:
        raise ValueError("truth_groups exceeds truth_hosts")
    for key in ("missing_profile_hosts", "unlabelled_profile_hosts"):
        if key not in payload:
            continue
        values = payload[key]
        if (
            not isinstance(values, list)
            or any(not isinstance(value, str) or not value.strip() for value in values)
            or len(set(values)) != len(values)
        ):
            raise ValueError(f"{key} must be a list of unique nonempty host identifiers")
    missing_profiles = payload.get("missing_profile_hosts")
    if missing_profiles is not None:
        if hosts is not None and len(missing_profiles) > hosts:
            raise ValueError("missing_profile_hosts exceeds truth_hosts")
        if set(missing_profiles) & set(payload.get("unlabelled_profile_hosts", [])):
            raise ValueError("missing and unlabelled profile hosts overlap")

    h1 = payload["h1"]
    if not isinstance(h1, dict):
        raise ValueError("h1 must be an object")
    if "eligible" in h1 and type(h1["eligible"]) is not bool:
        raise ValueError("h1.eligible must be a boolean")
    eligible = h1.get("eligible")
    if eligible is True and not verified:
        raise ValueError("H1 eligibility requires VERIFIED evaluation evidence")
    if verified or eligible is True:
        if (
            ("data_kind" in payload and payload["data_kind"] != "human")
            or payload.get("manual_tags_used") is True
            or missing_profiles
        ):
            raise ValueError(
                "H1 eligibility contradicts provenance, manual tags or missing profiles"
            )
    if verified and eligible is not True:
        raise ValueError("VERIFIED context requires h1.eligible=true")
    for metric, passed, target, threshold in (
        ("rule_role", "role_pass", "role_target", 0.85),
        ("exposure", "exposure_pass", "exposure_target", 0.95),
    ):
        if verified and ({passed, target} - h1.keys()):
            raise ValueError(f"VERIFIED context requires h1.{passed} and h1.{target}")
        if target in h1 and (type(h1[target]) not in (int, float) or h1[target] != threshold):
            raise ValueError(f"h1.{target} must equal the fixed target {threshold}")
        _context_metrics(
            payload[metric],
            metric,
            complete=verified,
            hosts=hosts,
            missing_profiles=None if missing_profiles is None else len(missing_profiles),
        )
        accuracy = payload[metric].get("accuracy")
        if eligible is True and payload[metric].get("missing_rate", 0) not in (None, 0):
            raise ValueError(f"h1.eligible contradicts {metric}.missing_rate")
        if passed not in h1:
            continue
        result = h1[passed]
        if result is not None and type(result) is not bool:
            raise ValueError(f"h1.{passed} must be boolean or null")
        if result is not None and (
            eligible is not True or accuracy is None or result != (accuracy >= threshold)
        ):
            raise ValueError(f"h1.{passed} contradicts eligibility or {metric}.accuracy")
        if result is None and (verified or (eligible is True and accuracy is not None)):
            raise ValueError(f"eligible context with accuracy requires h1.{passed}")
    if payload.get("model_role") is not None:
        _context_metrics(payload["model_role"], "model_role", complete=verified, hosts=hosts)
    counts = {
        payload[key]["examples"]
        for key in ("rule_role", "exposure", "model_role")
        if isinstance(payload.get(key), dict) and "examples" in payload[key]
    }
    if len(counts) > 1:
        raise ValueError("role and exposure examples disagree")
    if "controls" in payload:
        if not isinstance(payload["controls"], dict):
            raise ValueError("controls must be an object")
        for key, metrics in payload["controls"].items():
            if key not in CONTROL_KEYS:
                raise ValueError(f"unsupported context control {key!r}")
            _context_metrics(metrics, f"controls.{key}", complete=verified, hosts=hosts)


def _validate_unification_artifact(payload: Mapping[str, Any]) -> None:
    """Check internal preview facts, without authenticating sources or inventing legacy facts."""
    model_hash = payload.get("model_hash")
    if model_hash is not None and (not isinstance(model_hash, str) or not model_hash.strip()):
        raise ValueError("model_hash must be a nonblank string or null")
    verified = payload["evidence_status"] == "VERIFIED"
    if verified:
        missing = {
            "unified_count",
            "duplicate_reduction",
            "downstream_ranking_changed",
        } - payload.keys()
        if missing:
            raise ValueError(f"VERIFIED unification missing {sorted(missing)[0]}")
    for key in ("raw_count", "unified_count", "duplicate_reduction"):
        if key in payload and (type(payload[key]) is not int or payload[key] < 0):
            raise ValueError(f"{key} must be a nonnegative integer")
    if "downstream_ranking_changed" in payload:
        if type(payload["downstream_ranking_changed"]) is not bool:
            raise ValueError("downstream_ranking_changed must be a boolean")
        if payload["downstream_ranking_changed"]:
            raise ValueError("unification preview cannot establish downstream_ranking_changed=true")

    groups, candidates = payload["groups"], payload["candidates"]
    for name, records in (("groups", groups), ("candidates", candidates)):
        if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
            raise ValueError(f"{name} must be a list of objects")
        for row in records:
            # Reasons remain free text: validating artifacts must not define matching policy.
            for key in ("method", "justification"):
                if key in row and (not isinstance(row[key], str) or not row[key].strip()):
                    raise ValueError(f"{name}.{key} must be a nonblank string")
            if "confidence" in row and (
                type(row["confidence"]) not in (int, float) or not 0 <= row["confidence"] <= 1
            ):
                raise ValueError(f"{name}.confidence must be a number in [0, 1]")

    raw_count = payload["raw_count"]
    if payload.get("unified_count", len(groups)) != len(groups):
        raise ValueError("unified_count disagrees with groups")
    if len(groups) > raw_count:
        raise ValueError("groups exceeds raw_count")
    if "duplicate_reduction" in payload and (
        payload["duplicate_reduction"] != raw_count - len(groups)
    ):
        raise ValueError("duplicate_reduction disagrees with raw_count and groups")

    covered: set[str] = set()
    group_ids: set[str] = set()
    unknown_groups = 0
    for group in groups:
        if verified and ({"id", "source_finding_ids"} - group.keys()):
            raise ValueError("VERIFIED unification groups require id and source_finding_ids")
        if "id" in group:
            group_id = group["id"]
            if (
                not isinstance(group_id, str)
                or len(group_id) != 64
                or any(character not in "0123456789abcdef" for character in group_id)
            ):
                raise ValueError("groups.id must be a lowercase SHA-256 digest")
            if group_id in group_ids:
                raise ValueError("duplicate groups.id")
            group_ids.add(group_id)
        if "source_finding_ids" not in group:
            unknown_groups += 1
            continue
        sources = group["source_finding_ids"]
        if (
            not isinstance(sources, list)
            or not sources
            or any(not isinstance(source, str) or not source.strip() for source in sources)
        ):
            raise ValueError("source_finding_ids must be a nonempty list of nonblank identifiers")
        source_ids = set(sources)
        if len(source_ids) != len(sources) or covered & source_ids:
            raise ValueError("duplicate source_finding_ids within or across groups")
        covered.update(source_ids)
        if "id" in group:
            joined = "|".join(sorted(source_ids))
            expected = sha256(f"vulnassess-unified-v1|{joined}".encode("utf-8")).hexdigest()
            if group["id"] != expected:
                raise ValueError("groups.id disagrees with source_finding_ids")
    if len(covered) + unknown_groups > raw_count or (
        unknown_groups == 0 and len(covered) != raw_count
    ):
        raise ValueError("source_finding_ids coverage disagrees with raw_count")

    pairs: set[tuple[str, str]] = set()
    referenced = set(covered)
    for candidate in candidates:
        endpoints: list[str] = []
        for key in ("left_finding_id", "right_finding_id"):
            if key not in candidate:
                if verified:
                    raise ValueError(f"VERIFIED unification candidates require {key}")
                continue
            endpoint = candidate[key]
            if not isinstance(endpoint, str) or not endpoint.strip():
                raise ValueError(f"candidates.{key} must be a nonblank identifier")
            if unknown_groups == 0 and endpoint not in covered:
                raise ValueError(f"candidates.{key} references an unknown source_finding_id")
            endpoints.append(endpoint)
            referenced.add(endpoint)
        if len(endpoints) == 2:
            if endpoints[0] == endpoints[1]:
                raise ValueError("candidate endpoints must refer to distinct source_finding_ids")
            pair = tuple(sorted(endpoints))
            pair_key = (pair[0], pair[1])
            if pair_key in pairs:
                raise ValueError("duplicate candidate endpoints")
            pairs.add(pair_key)
    if len(referenced) > raw_count or (candidates and raw_count < 2):
        raise ValueError("candidate endpoints exceed raw_count")


def load_artifact(kind: str, path: str | Path, run_id: str) -> AuditArtifact:
    if kind not in ARTIFACT_SPECS:
        raise ConfigError(
            f"unknown audit artifact kind {kind!r}; expected one of {tuple(ARTIFACT_SPECS)}"
        )
    path = Path(path)
    payload = load_json_payload(path, f"{kind} audit artifact")
    if not isinstance(payload, dict):
        raise ConfigError(f"invalid {kind} audit artifact {path}: expected an object")
    hash_field, run_field, required = ARTIFACT_SPECS[kind]
    missing = sorted({hash_field, run_field, "evidence_status", *required} - set(payload))
    if missing:
        raise ConfigError(f"invalid {kind} audit artifact {path}: missing key {missing[0]!r}")
    if not isinstance(payload[run_field], str) or not payload[run_field].strip():
        raise ConfigError(
            f"invalid {kind} audit artifact {path}: {run_field} must be a non-empty string"
        )
    if payload[run_field] != run_id:
        raise ConfigError(
            f"{kind} audit artifact belongs to run {payload[run_field]!r}, not {run_id!r}"
        )
    evidence_status = str(payload["evidence_status"])
    if evidence_status not in EVIDENCE_STATUSES:
        raise ConfigError(
            f"invalid {kind} audit artifact {path}: unsupported evidence_status {evidence_status!r}"
        )
    claimed = payload[hash_field]
    core = {key: value for key, value in payload.items() if key != hash_field}
    computed = _digest(core)
    if claimed != computed:
        raise ConfigError(
            f"{kind} audit artifact hash mismatch: artifact says {claimed!r}, computed {computed!r}"
        )
    if kind == "context":
        try:
            _validate_context_artifact(payload)
        except ValueError as error:
            raise ConfigError(f"invalid context audit artifact {path}: {error}") from error
    if kind == "unification":
        try:
            _validate_unification_artifact(payload)
        except ValueError as error:
            raise ConfigError(f"invalid unification audit artifact {path}: {error}") from error
    if kind == "stability":
        hashes = payload["score_hashes"]
        repeats, unique = payload.get("repeats"), payload.get("unique_score_hashes")
        if (
            type(payload["deterministic"]) is not bool
            or type(repeats) is not int
            or repeats < 2
            or type(unique) is not int
            or not isinstance(hashes, list)
            or len(hashes) != repeats
            or any(
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in hashes
            )
            or unique != len(set(hashes))
            or payload["deterministic"] != (unique == 1)
        ):
            raise ConfigError(
                f"invalid stability audit artifact {path}: inconsistent repeat evidence"
            )
        if evidence_status == "VERIFIED" and not payload["deterministic"]:
            raise ConfigError(
                f"stability verification failed in {path}; it cannot claim VERIFIED success"
            )
    try:
        summary = _summary(kind, payload)
    except (KeyError, TypeError, AttributeError) as error:
        raise ConfigError(f"invalid {kind} audit artifact {path}: {error}") from error
    return AuditArtifact(
        kind=kind,
        path=str(path),
        artifact_hash=str(claimed),
        evidence_status=evidence_status,
        summary=summary,
        payload=payload,
    )


def _missing_row(component: str, requirement: str) -> dict[str, str]:
    return {
        "component": component,
        "evidence_status": "MISSING",
        "artifact_hash": "",
        "summary": f"MISSING: {requirement}",
        "path": "",
    }


def _metric_columns(metrics: Mapping[str, Any]) -> Counter[str]:
    result: Counter[str] = Counter()
    for row in metrics["confusion_matrix"].values():
        result.update(row)
    return +result


def _context_report_binding(
    settings: Any,
    store: Any,
    run_id: str,
    artifact: AuditArtifact,
    snapshot: Mapping[str, Any] | None,
) -> bool:
    """Check compatibility before publication; counts are not historical identity.

    Truth-to-host mappings are absent from these legacy artifacts. Exact matching
    of role/exposure marginals and feasible clean control subsets is therefore a
    necessary compatibility check, not reconstruction of the original evaluation.
    """
    prefix = f"VERIFIED context artifact {artifact.path} incompatible with current assessment"
    payload = artifact.payload
    if snapshot is not None and payload.get("model_hash") != snapshot.get("model_hash"):
        raise ConfigError(f"{prefix}: context artifact model_hash contradicts report snapshot")
    excluded = payload.get("unlabelled_profile_hosts")
    if not isinstance(excluded, list):
        raise ConfigError(f"{prefix}: evaluated subset is not recorded")
    try:
        profiles = store.profiles(run_id)
        observed_hosts = {host.ip for host in store.hosts(run_id)}
    except (ValueError, TypeError, AttributeError) as error:
        raise ConfigError(f"{prefix}: malformed stored inputs") from error
    if any(not isinstance(item.host_ip, str) or not item.host_ip for item in profiles):
        raise ConfigError(f"{prefix}: malformed current host identifiers")
    current = {item.host_ip: item for item in profiles}
    if len(current) != len(profiles) or not set(excluded) <= current.keys():
        raise ConfigError(f"{prefix}: unlabelled subset no longer matches")
    selected = {key: profile for key, profile in current.items() if key not in excluded}
    if len(selected) != payload["truth_hosts"] or set(selected) - observed_hosts:
        raise ConfigError(f"{prefix}: labelled host subset no longer matches")
    roles: Counter[str] = Counter()
    exposure: Counter[str] = Counter()
    for host, profile in selected.items():
        _, issues = _feature_provenance(
            host, [("role", profile.role), ("exposure", profile.exposure)]
        )
        if issues:
            raise ConfigError(f"{prefix}: {'; '.join(issues)}")
        if profile.role.value not in ROLES or profile.exposure.value not in EXPOSURES:
            raise ConfigError(f"{prefix}: unsupported prediction label")
        roles[ABSTAIN if profile.role.value == "unknown" else profile.role.value] += 1
        exposure[profile.exposure.value] += 1
    if roles != _metric_columns(payload["rule_role"]) or exposure != _metric_columns(
        payload["exposure"]
    ):
        raise ConfigError(f"{prefix}: recorded prediction counts no longer match")
    for key, metrics in payload.get("controls", {}).items():
        if not metrics["examples"]:
            continue
        available: Counter[str] = Counter()
        for host, profile in selected.items():
            feature = profile.controls.get(key)
            if feature is not None and _feature_provenance(host, [(key, feature)])[1]:
                continue
            available[_control_label(feature) or MISSING] += 1
        if _metric_columns(metrics) - available:
            raise ConfigError(f"{prefix}: {key} predictions cannot use a clean current subset")
    binding = payload.get("snapshot_hash")
    if binding is None:
        return False
    from vulnassess import assessment_snapshot

    try:
        current_snapshot = assessment_snapshot.build_snapshot(
            settings,
            store,
            run_id,
            model_hash=payload.get("model_hash"),
        )
        same_profiles = _canonical([profile.to_json() for profile in profiles]) == _canonical(
            current_snapshot["profiles"]
        )
    except (ValueError, TypeError, AttributeError) as error:
        raise ConfigError(f"{prefix}: malformed snapshot inputs") from error
    if (
        binding != current_snapshot["snapshot_hash"]
        or not same_profiles
        or (snapshot is not None and snapshot["snapshot_hash"] != current_snapshot["snapshot_hash"])
    ):
        raise ConfigError(f"{prefix}: context artifact snapshot binding no longer matches")
    return True


def collect_report_audit(
    settings,
    store,
    run_id: str,
    *,
    snapshot_path: str | Path | None = None,
    cohort_manifest_path: str | Path | None = None,
    cohort_evidence_path: str | Path | None = None,
    artifact_paths: Mapping[str, str | Path | None] | None = None,
    model_path: str | Path | None = None,
) -> dict[str, Any]:
    """Validate report attachments and compute read-only diagnostics."""
    from vulnassess import assessment_snapshot, cohort, role_model, unify
    from vulnassess.errors import IntelUnavailable

    if store.run_info(run_id) is None:
        raise ConfigError(f"MISSING: run {run_id!r}")
    rows: list[dict[str, str]] = []
    limitations: list[str] = []
    artifacts: dict[str, dict[str, Any]] = {}
    report_model = None
    snapshot = None
    assessment_status = "MISSING"
    if snapshot_path is None:
        rows.append(_missing_row("assessment snapshot", "report --snapshot PATH"))
        rows.append(
            {
                "component": "score arithmetic",
                "evidence_status": "NOT RUN",
                "artifact_hash": "",
                "summary": "No frozen assessment supplied; score arithmetic not replayed",
                "path": "report --snapshot PATH",
            }
        )
        limitations.append(
            "The report is not bound to a frozen assessment snapshot; current global feed and "
            "enrichment state may differ from the original run."
        )
    else:
        snapshot = assessment_snapshot.load_snapshot(snapshot_path)
        actual_run = str(snapshot["run"].get("run_id"))
        if actual_run != run_id:
            raise ConfigError(f"assessment snapshot belongs to run {actual_run!r}, not {run_id!r}")
        assessment_status = str(snapshot.get("evidence_status"))
        if assessment_status not in EVIDENCE_STATUSES:
            raise ConfigError(
                f"assessment snapshot has unsupported evidence_status {assessment_status!r}"
            )
        live = assessment_snapshot.build_snapshot(
            settings, store, run_id, model_hash=snapshot.get("model_hash")
        )
        if live["snapshot_hash"] != snapshot["snapshot_hash"]:
            raise ConfigError(
                "live report state no longer matches the supplied assessment snapshot"
            )
        rows.append(
            {
                "component": "assessment snapshot",
                "evidence_status": assessment_status,
                "artifact_hash": str(snapshot["snapshot_hash"]),
                "summary": (
                    f"content hash and live state match; {len(snapshot['hosts'])} hosts, "
                    f"{len(snapshot['findings'])} raw findings"
                ),
                "path": str(snapshot_path),
            }
        )
        arithmetic = assessment_snapshot._score_arithmetic_summary(snapshot)
        total = arithmetic["total"]
        replayed = arithmetic["replayed"]
        arithmetic_status = "NOT RUN"
        if total > 0 and replayed == total:
            arithmetic_status = "VERIFIED"
            arithmetic_summary = (
                f"{replayed}/{total} scores replayed against retained current policy/weights; "
                "reproduction is not capture authentication or proof method is correct"
            )
        elif total == 0:
            arithmetic_summary = (
                "No numeric scores in frozen assessment; score arithmetic not replayed"
            )
        else:
            arithmetic_summary = (
                f"{replayed}/{total} scores replayed against retained current policy/weights; "
                f"{arithmetic['cvss_checked']} CVSS scores checked; score arithmetic remains unverified"
            )
        rows.append(
            {
                "component": "score arithmetic",
                "evidence_status": arithmetic_status,
                "artifact_hash": str(snapshot["snapshot_hash"]),
                "summary": arithmetic_summary,
                "path": str(snapshot_path),
            }
        )
        limitations.extend(arithmetic["unknown"])

    if (cohort_manifest_path is None) != (cohort_evidence_path is None):
        raise ConfigError("report needs --cohort-manifest and --cohort-evidence together")
    cohort_manifest = None
    if cohort_manifest_path is None:
        rows.append(
            _missing_row("expert cohort", "report --cohort-manifest PATH --cohort-evidence PATH")
        )
    else:
        cohort_manifest = cohort.load_manifest(cohort_manifest_path)
        if cohort_manifest.run_id != run_id:
            raise ConfigError(
                f"cohort manifest belongs to run {cohort_manifest.run_id!r}, not {run_id!r}"
            )
        assert cohort_evidence_path is not None  # the pairing check above excludes None
        cohort.load_evidence(cohort_evidence_path, cohort_manifest)
        if snapshot is not None:
            cohort.validate_snapshot_against_manifest(snapshot, cohort_manifest)
        rows.append(
            {
                "component": "expert cohort",
                "evidence_status": cohort_manifest.evidence_status,
                "artifact_hash": cohort_manifest.manifest_hash,
                "summary": (
                    f"{len(cohort_manifest.finding_ids)} {cohort_manifest.finding_mode} findings; "
                    f"cohort_id={cohort_manifest.cohort_id}"
                ),
                "path": str(cohort_manifest_path),
            }
        )

    requested_artifacts = artifact_paths or {}
    report_kinds = ("scan", "context", "ranking", "ablation", "stability", "rescan")
    for kind in report_kinds:
        path = requested_artifacts.get(kind)
        if path is None:
            rows.append(_missing_row(kind, f"report --{kind}-artifact PATH"))
            continue
        artifact = load_artifact(kind, path, run_id)
        artifact_snapshot = artifact.payload.get("snapshot_hash")
        if snapshot is not None and artifact_snapshot not in (None, snapshot["snapshot_hash"]):
            raise ConfigError(f"{kind} artifact does not match the report assessment snapshot")
        if cohort_manifest is not None:
            artifact_cohort = artifact.payload.get("cohort_hash")
            if kind == "ablation":
                artifact_cohort = artifact.payload.get("research_binding", {}).get("cohort_hash")
            if artifact_cohort not in (None, cohort_manifest.manifest_hash):
                raise ConfigError(f"{kind} artifact does not match the report cohort")
        row = artifact.row()
        if kind == "context" and artifact.evidence_status == "VERIFIED":
            bound = _context_report_binding(settings, store, run_id, artifact, snapshot)
            row["summary"] += "; current profile inputs compatible; " + (
                "snapshot-bound" if bound else "historical input identity unbound"
            )
            if not bound:
                row["evidence_status"] = "NOT RUN"
                limitations.append(
                    "The context artifact retains its declared VERIFIED evaluation, but its "
                    "historical per-host inputs are unbound to this assessment. Current prediction "
                    "counts and clean-source subsets are compatible, not proof of historical identity; "
                    "the report's context binding remains NOT RUN."
                )
        artifacts[kind] = artifact.payload
        rows.append(row)

    unification_path = requested_artifacts.get("unification")
    if unification_path is not None:
        unification_artifact = load_artifact("unification", unification_path, run_id)
        unification_payload = unification_artifact.payload
        verified = unification_artifact.evidence_status == "VERIFIED"
        binding = unification_payload.get("snapshot_hash")
        if (
            snapshot is not None
            and binding != snapshot["snapshot_hash"]
            and (verified or binding is not None)
        ):
            raise ConfigError("unification artifact does not match the report assessment snapshot")
        if verified:
            prefix = (
                f"VERIFIED unification artifact {unification_path} "
                "incompatible with current assessment"
            )
            model_hash = (
                snapshot.get("model_hash")
                if snapshot is not None
                else unification_payload.get("model_hash")
            )
            if model_hash is not None and (
                not isinstance(model_hash, str) or not model_hash.strip()
            ):
                raise ConfigError(f"{prefix}: model_hash must be a nonblank string or null")
            if "model_hash" in unification_payload and (
                unification_payload["model_hash"] != model_hash
            ):
                raise ConfigError(f"{prefix}: model_hash contradicts report snapshot")
            if model_path is not None:
                report_model = role_model.load_model(model_path)
                if snapshot is None and "model_hash" not in unification_payload:
                    model_hash = report_model.model_hash
                elif model_hash != report_model.model_hash:
                    raise ConfigError(f"{prefix}: model_hash contradicts selected report model")
            current_snapshot = assessment_snapshot.build_snapshot(
                settings, store, run_id, model_hash=model_hash
            )
            if binding != current_snapshot["snapshot_hash"] or (
                snapshot is not None
                and snapshot["snapshot_hash"] != current_snapshot["snapshot_hash"]
            ):
                raise ConfigError(f"{prefix}: snapshot binding no longer matches")
            # Recompute from these exact captured inputs, not a second series of
            # live reads that could describe another state than this binding.
            from vulnassess.schema import Enrichment, Finding

            try:
                current_preview = unify.unify_findings(
                    [Finding.from_json(item) for item in current_snapshot["findings"]],
                    {
                        finding_id: [Enrichment.from_json(item) for item in entries]
                        for finding_id, entries in current_snapshot["enrichments"].items()
                    },
                ).to_json()
            except (KeyError, ValueError, TypeError, AttributeError) as error:
                raise ConfigError(f"{prefix}: malformed snapshot preview inputs") from error
            declared_preview = {key: unification_payload.get(key) for key in current_preview}
            if _canonical(declared_preview) != _canonical(current_preview):
                raise ConfigError(f"{prefix}: declared preview disagrees with current unification")
        else:
            limitations.append(
                "The unification attachment retains its declared evidence status; agreement "
                "with the current preview remains unknown. Missing legacy facts were not inferred."
            )
        rows.append(unification_artifact.row())
    else:
        unification_result = unify.unify_run(store, run_id).to_json()
        unification_payload = {
            "run_id": run_id,
            "mode": "live_read_only_preview",
            "downstream_ranking_changed": False,
            **unification_result,
        }
        rows.append(
            {
                "component": "unification",
                "evidence_status": assessment_status,
                "artifact_hash": _digest(unification_payload),
                "summary": _summary("unification", unification_payload),
                "path": "",
            }
        )
    artifacts["unification"] = unification_payload

    try:
        intelligence = store.intelligence_trace(run_id)
        if intelligence is None:
            raise IntelUnavailable(
                "No run-bound intelligence trace was retained; current-cache recomputation is not historical evidence"
            )
    except IntelUnavailable as error:
        intelligence = {"trace_counts": {}, "unmatched": []}
        rows.append(_missing_row("intelligence trace", str(error)))
    else:
        rows.append(
            {
                "component": "intelligence trace",
                "evidence_status": assessment_status,
                "artifact_hash": _digest(intelligence),
                "summary": (
                    f"matched={intelligence['matched']}/{intelligence['findings']}; "
                    f"unmatched={intelligence['unmatched_count']}"
                ),
                "path": "",
            }
        )

    model_cases: list[dict[str, Any]] = []
    if model_path is None:
        rows.append(_missing_row("shadow role model", "report --model PATH"))
    else:
        model = report_model if report_model is not None else role_model.load_model(model_path)
        profiles = {profile.host_ip: profile for profile in store.profiles(run_id)}
        for host in store.hosts(run_id):
            prediction = model.predict(host)
            profile = profiles.get(host.ip)
            rule_label = None if profile is None else str(profile.role.value)
            model_cases.append(
                {
                    "host_ip": host.ip,
                    "rule": rule_label,
                    "model": prediction.label,
                    "confidence": prediction.confidence,
                    "margin": prediction.margin,
                    "abstained": prediction.abstained,
                    "feature_coverage": prediction.feature_coverage,
                    "out_of_vocabulary": list(prediction.out_of_vocabulary),
                    "model_hash": prediction.model_hash,
                    "evidence": prediction.evidence,
                }
            )
        rows.append(
            {
                "component": "shadow role model",
                "evidence_status": "NOT RUN",
                "artifact_hash": model.model_hash,
                "summary": (
                    f"{len(model_cases)} shadow predictions; independent validation not supplied; "
                    "canonical context unchanged"
                ),
                "path": str(model_path),
            }
        )

    return {
        "assessment_evidence_status": assessment_status,
        "snapshot_hash": None if snapshot is None else snapshot["snapshot_hash"],
        "cohort_hash": (None if cohort_manifest is None else cohort_manifest.manifest_hash),
        "rows": rows,
        "intelligence": intelligence,
        "unification": unification_payload,
        "model_cases": model_cases,
        "artifacts": artifacts,
        "limitations": limitations,
    }
