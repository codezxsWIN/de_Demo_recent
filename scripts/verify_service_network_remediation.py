"""Change two owned lab listeners, repeat their checks, and restore the baseline.

Only FTP 127.0.0.2:2121 and MQTT 127.0.0.3:1883 are tested. The MQTT change
is temporary deny-all containment, not a completed authenticated broker rollout.
Run after building the service-network image; no HarborDesk resources are used.
"""

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from tempfile import mkstemp

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.verify_service_network_containers import COMPOSE, PROJECT, executable  # noqa: E402
from vulnassess import network_service_checks as checks  # noqa: E402
from vulnassess import network_service_policy  # noqa: E402
from vulnassess.service_network_deployment import digest  # noqa: E402
from vulnassess.settings import Settings  # noqa: E402


def main():
    docker = executable()
    environment = dict(os.environ)
    environment["PATH"] = str(docker.parent) + os.pathsep + environment.get("PATH", "")
    settings = Settings(ROOT / "config")
    endpoints = {}
    for name, ip, port in (("office", "127.0.0.2", 2121), ("iot", "127.0.0.3", 1883)):
        policy = network_service_policy.load(settings.config_dir, settings.scope, ip)
        if policy is None or settings.scope.is_canary(ip):
            raise RuntimeError("Both exact lab targets must remain authorised")
        entry = next(item for item in policy["endpoints"] if item["port"] == port)
        if entry.get("require_auth") is not True:
            raise RuntimeError("The comparison requires an unchanged authentication policy")
        endpoints[name] = (ip, entry, policy["policy_sha256"])

    def run(*args):
        process = subprocess.run(
            [str(docker), *args],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
        )
        if process.returncode:
            raise RuntimeError(f"Fixed lab Docker operation failed: {process.stderr[-400:]}")
        return process.stdout.strip()

    def inspect(name):
        identity = run("compose", "-f", str(COMPOSE), "ps", "-q", name)
        value = json.loads(run("inspect", identity))[0]
        if value["Config"]["Labels"].get("com.docker.compose.project") != PROJECT:
            raise RuntimeError("Refusing an unrelated container")
        ready = json.loads(run("exec", identity, "cat", "/runtime/ready.json"))
        return value, ready

    for name in endpoints:
        _, ready = inspect(name)
        if ready.get("access_profile", "baseline") != "baseline":
            raise RuntimeError(
                "Start from the baseline profile; no existing trial will be overwritten"
            )

    def observe(profile):
        result = {}
        for name, (ip, entry, policy_hash) in endpoints.items():
            container, ready = inspect(name)
            if ready.get("access_profile", "baseline") != profile:
                raise RuntimeError("The running backend does not match the requested trial profile")
            proof = checks.TRANSPORTS[entry["service"]](ip, entry)
            result[name] = {
                "target": ip,
                "port": entry["port"],
                "service": entry["service"],
                "observed_at": datetime.now(UTC).isoformat(),
                "container_id": container["Id"],
                "image_id": container["Image"],
                "policy_sha256": policy_hash,
                "policy": entry,
                "proof": proof,
                "violations": [row[0] for row in checks.violations(entry, proof)],
            }
        return result

    output = ROOT / "data/service-networks"
    output.mkdir(parents=True, exist_ok=True)
    descriptor, override_name = mkstemp(prefix="access-profile-", suffix=".json", dir=output)
    override = Path(override_name)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(
            {
                "services": {
                    name: {"environment": {"VULNASSESS_LAB_ACCESS_PROFILE": "restricted"}}
                    for name in endpoints
                }
            },
            stream,
        )
    document = {"schema_version": 1, "project": PROJECT, "status": "failed", "stages": {}}
    changed = False
    try:
        print("BEFORE: checking the original FTP and MQTT listeners", flush=True)
        document["stages"]["before"] = observe("baseline")
        changed = True  # Restoration is required even if Compose changes only one service.
        print("CHANGE: named-user FTP; temporary deny-all MQTT containment", flush=True)
        run(
            "compose",
            "-f",
            str(COMPOSE),
            "-f",
            str(override),
            "up",
            "-d",
            "--no-deps",
            "--wait",
            "office",
            "iot",
        )
        document["stages"]["after"] = observe("restricted")
        # The protected FTP password stays inside the backend; retain only the outcome.
        document["ftp_authorised_login_after"] = (
            run(
                "compose",
                "-f",
                str(COMPOSE),
                "exec",
                "-T",
                "office",
                "python",
                "-c",
                "import json,ftplib; rows=json.load(open('/runtime/control/access.json')); "
                "r=next(x for x in rows if x['port']==2122); f=ftplib.FTP(); "
                "f.connect('127.0.0.1',2121,timeout=4); reply=f.login(r['username'],r['password']); "
                "f.quit(); print(json.dumps(reply.startswith('230')))",
            )
            == "true"
        )
    except Exception as error:
        document["error"] = str(error)[:500]
    finally:
        if changed:
            print("RESTORE: returning both owned backends to the baseline", flush=True)
            try:
                run(
                    "compose",
                    "-f",
                    str(COMPOSE),
                    "up",
                    "-d",
                    "--no-deps",
                    "--wait",
                    "office",
                    "iot",
                )
                document["stages"]["restored"] = observe("baseline")
            except Exception as error:
                document["restoration_error"] = str(error)[:500]
        override.unlink(missing_ok=True)
    document["verified_at"] = datetime.now(UTC).isoformat()
    document["receipt_hash"] = digest(document)
    from vulnassess.service_network_remediation import validate

    try:
        document["status"] = "passed"
        document["receipt_hash"] = digest(document)
        validate(document)
    except Exception as error:
        document["status"] = "failed"
        document["validation_error"] = str(error)[:500]
        document["receipt_hash"] = digest(document)
    descriptor, receipt = mkstemp(prefix="remediation-verification-", suffix=".json", dir=output)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2)
    print(f"{document['status'].upper()}: {receipt}", flush=True)
    return int(document["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
