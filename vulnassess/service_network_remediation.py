"""Dated same-endpoint remediation proof, distinct from complete security clearance."""

import json
import re
from datetime import datetime

from vulnassess.errors import ConfigError
from vulnassess.network_service_checks import violations
from vulnassess.service_network_deployment import digest


def validate(document):
    try:
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or document["project"] != "vulnassess-service-networks"
            or document["status"] != "passed"
            or document["receipt_hash"] != digest(document)
            or document.get("error")
            or document.get("restoration_error")
            or document["ftp_authorised_login_after"] is not True
        ):
            raise ValueError("Trial status or integrity failed")
        verified = datetime.fromisoformat(document["verified_at"])
        if verified.tzinfo is None or set(document["stages"]) != {"before", "after", "restored"}:
            raise ValueError("All trial stages and timezone-aware times are required")
        for name, ip, port, protocol in (
            ("office", "127.0.0.2", 2121, "ftp"),
            ("iot", "127.0.0.3", 1883, "mqtt"),
        ):
            policies, images, hashes, times = [], [], [], []
            identities = []
            for stage in ("before", "after", "restored"):
                row = document["stages"][stage][name]
                if (row["target"], row["port"], row["service"]) != (ip, port, protocol):
                    raise ValueError("Endpoint changed")
                if row["policy"].get("require_auth") is not True or (
                    row["policy"]["port"],
                    row["policy"]["service"],
                    row["policy"]["transport"],
                ) != (port, protocol, "tcp"):
                    raise ValueError("Policy does not match endpoint")
                for field in ("container_id", "policy_sha256"):
                    if not re.fullmatch(r"[a-f0-9]{64}", row[field]):
                        raise ValueError("Missing source identity")
                if not re.fullmatch(r"sha256:[a-f0-9]{64}", row["image_id"]):
                    raise ValueError("Missing image identity")
                proof = row["proof"]
                accepted = stage != "after"
                if (
                    proof.get("protocol_confirmed") is not True
                    or proof.get("anonymous_accepted") is not accepted
                ):
                    raise ValueError("Explicit protocol acceptance/rejection is required")
                if protocol == "ftp" and not str(proof.get("response", "")).startswith(
                    "230" if accepted else "530"
                ):
                    raise ValueError("FTP response does not support the access decision")
                if protocol == "mqtt" and (
                    proof.get("connack_hex") not in ({"0000"} if accepted else {"0004", "0005"})
                    or (accepted and proof.get("message_exchange_confirmed") is not True)
                ):
                    raise ValueError("MQTT acknowledgement or nonce exchange is missing")
                observed = [item[0] for item in violations(row["policy"], proof)]
                if row["violations"] != observed or observed != (
                    ["authentication"] if accepted else []
                ):
                    raise ValueError("Detector outcome does not match proof")
                timestamp = datetime.fromisoformat(row["observed_at"])
                if timestamp.tzinfo is None:
                    raise ValueError("Missing observation timezone")
                times.append(timestamp)
                identities.append(row["container_id"])
                policies.append(row["policy"])
                hashes.append(row["policy_sha256"])
                images.append(row["image_id"])
            if (
                not times[0] <= times[1] <= times[2] <= verified
                or not policies[0] == policies[1] == policies[2]
                or len(set(hashes)) != 1
                or len(set(images)) != 1
                or len(set(identities)) != 3
            ):
                raise ValueError(
                    "Chronology, configuration, image or restart identity is inconsistent"
                )
        return document
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as error:
        raise ConfigError(
            "Same-endpoint remediation receipt is incomplete or contradicts its proof"
        ) from error


def load_latest(root):
    paths = sorted(
        root.glob("remediation-verification-*.json"),
        key=lambda p: p.stat().st_mtime_ns,
        reverse=True,
    )
    if not paths:
        return None
    path = paths[0]
    if root.is_symlink() or path.is_symlink() or not path.is_file():
        raise ConfigError("Remediation receipt must be a local regular file")
    try:

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate receipt key")
                result[key] = value
            return result

        with path.open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("Receipt exceeds the read budget")
        document = validate(json.loads(raw, object_pairs_hook=unique))
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        raise ConfigError("Remediation receipt could not be verified") from error
    return {**document, "filename": path.name}
