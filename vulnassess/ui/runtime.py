"""Legacy inference helpers retained but not imported or exposed by the UI server."""

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

from vulnassess.errors import ConfigError
from vulnassess.role_model import RoleModel, extract_features, load_model
from vulnassess.schema import Host
from vulnassess.ui.reader import ReadOnlyStore, local_path


def metadata(model: RoleModel) -> dict[str, Any]:
    return {
        "model_hash": model.model_hash,
        "algorithm": model.training.get("algorithm"),
        "classes": list(model.classes),
        "confidence_threshold": model.confidence_threshold,
        "margin_threshold": model.margin_threshold,
        "minimum_feature_coverage": model.minimum_feature_coverage,
        "label_sources": model.training.get("label_sources", {}),
        "score_influence": "none; shadow predictions only",
    }


def model_status(path: Path) -> dict[str, Any]:
    return {"status": "ready", "model": metadata(load_model(local_path(path)))}


def run_model(database: Path, artifact: Path, run_id: str) -> dict[str, Any]:
    started_at = datetime.now(UTC).isoformat()
    started = perf_counter()
    model = load_model(local_path(artifact))
    with ReadOnlyStore(database) as store:
        payload = store.run(run_id)
    if not payload["hosts"]:
        raise ConfigError(f"MISSING: stored hosts for model inference in run {run_id!r}")
    if len(payload["hosts"]) > 1024:
        raise ConfigError("UI model inference is limited to 1024 stored hosts per request")
    encoded_inputs = json.dumps(payload["hosts"], sort_keys=True, separators=(",", ":"))
    hosts = []
    for stored_host in payload["hosts"]:
        host = Host.from_json(stored_host)
        values, evidence = extract_features(host)
        prediction = model.predict(host)
        hosts.append(
            {
                "host_ip": host.ip,
                "input": stored_host,
                "features": [
                    {"name": name, "value": value, "evidence": evidence[name]}
                    for name, value in sorted(values.items())
                ],
                "prediction": prediction.to_json(),
            }
        )
    return {
        "status": "completed",
        "source": "live_local_inference",
        "execution_id": str(uuid4()),
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat(),
        "elapsed_ms": round((perf_counter() - started) * 1000, 3),
        "input_sha256": sha256(encoded_inputs.encode("utf-8")).hexdigest(),
        "model": metadata(model),
        "hosts": hosts,
        "canonical_scores_changed": False,
    }
