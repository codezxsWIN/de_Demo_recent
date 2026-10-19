"""Bounded, read-only protection checks for the machine running VulnAssess."""

import hashlib
import json
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from uuid import uuid4

SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$result = @{}
try { Get-NetFirewallProfile | ForEach-Object { if ($null -ne $_.Enabled) { $result[$_.Name] = [bool]$_.Enabled } } } catch {}
try { $result['ActiveProfiles'] = @(Get-NetConnectionProfile | ForEach-Object { if ($_.NetworkCategory -eq 'DomainAuthenticated') { 'Domain' } else { $_.NetworkCategory.ToString() } } | Select-Object -Unique) } catch {}
try { $mp = Get-MpComputerStatus; if ($null -ne $mp.RealTimeProtectionEnabled) { $result['Defender'] = [bool]$mp.RealTimeProtectionEnabled } } catch {}
try { $v = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections; if ($null -ne $v) { $result['RemoteDesktop'] = ($v -eq 0) } } catch {}
try { $v = (Get-SmbServerConfiguration).EnableSMB1Protocol; if ($null -ne $v) { $result['SMB1'] = [bool]$v } } catch {}
try { $result['SecureBoot'] = [bool](Confirm-SecureBootUEFI) } catch {}
try { $v = (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus; if ($null -ne $v) { $result['Encryption'] = ($v -eq 'On') } } catch {}
try { $result['RebootPending'] = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') } catch {}
try { $result['Antivirus'] = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -First 8 -ExpandProperty displayName) } catch {}
try { $result['Listeners'] = @(Get-NetTCPConnection -State Listen | Select-Object -First 64 | ForEach-Object { $name = 'unknown'; try { $name = (Get-Process -Id $_.OwningProcess).ProcessName } catch {}; @{port=$_.LocalPort; address=$_.LocalAddress; app=$name} }) } catch {}
try { $result['LastUpdate'] = (Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn.ToString('yyyy-MM-dd') } catch {}
$result | ConvertTo-Json -Compress -Depth 4
"""
# Flush a complete snapshot after each fixed query. A slow final query must not
# erase completed observations when the process reaches its deadline.
SCRIPT = "\n".join(
    line + "\n$result | ConvertTo-Json -Compress -Depth 4" if line.startswith("try {") else line
    for line in SCRIPT.splitlines()
)

CHECKS = {
    "RemoteDesktop": (
        "Remote Desktop",
        "If you do not use remote access, review Settings → System → Remote Desktop. Enabled does not prove external reachability.",
    ),
    "SMB1": (
        "Legacy SMB1 file sharing",
        "SMB1 is an older sharing protocol. If enabled, review dependencies with your administrator before disabling it.",
    ),
    "SecureBoot": (
        "Secure Boot",
        "Check System Information → Secure Boot State. Do not change firmware settings without recovery information.",
    ),
    "Encryption": (
        "System-drive encryption protection",
        "Review Settings → Privacy & security → Device encryption and keep the recovery key somewhere safe.",
    ),
    "RebootPending": (
        "Windows Update restart pending",
        "Save your work and check Settings → Windows Update. A pending restart may be needed to finish an update.",
    ),
    "Domain": (
        "Work-network firewall",
        "Windows Security → Firewall & network protection. Review the domain profile with your administrator.",
    ),
    "Private": (
        "Private-network firewall",
        "Windows Security → Firewall & network protection → Private network. Review whether the firewall should be enabled.",
    ),
    "Public": (
        "Public-network firewall",
        "Windows Security → Firewall & network protection → Public network. Keep the firewall enabled on untrusted Wi-Fi.",
    ),
    "Defender": (
        "Microsoft Defender real-time protection",
        "Open Windows Security → Virus & threat protection. Check which antivirus provider is active before changing settings; another antivirus may replace Defender.",
    ),
}


def collect(only: str | None = None) -> dict:
    """No elevation, mutations, caller-controlled commands, or personal file access."""
    values = {}
    if only is not None and only not in CHECKS:
        raise ValueError("Unknown device check")
    script = SCRIPT
    if only is not None:
        marker = (
            "Get-NetFirewallProfile"
            if only in {"Domain", "Private", "Public"}
            else f"$result['{only}']"
        )
        script = (
            "$ErrorActionPreference = 'Stop'\n$result = @{}\n"
            + "\n".join(line for line in SCRIPT.splitlines() if marker in line)
            + "\n$result | ConvertTo-Json -Compress"
        )
    windows = platform.system() == "Windows"
    binary = shutil.which("powershell.exe") if windows else None
    if binary:
        output = ""
        try:
            result = subprocess.run(
                [binary, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if result.returncode == 0:
                output = result.stdout
        except subprocess.TimeoutExpired as error:
            output = error.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
        except (OSError, ValueError):
            pass
        if len(output) <= 32768:
            for line in reversed(output.splitlines()):
                try:
                    decoded = json.loads(line)
                except ValueError:
                    continue
                if isinstance(decoded, dict):
                    values = decoded
                    break
    checks = []
    for key, (title, action) in CHECKS.items():
        if only is not None and key != only:
            continue
        value = values.get(key)
        state = "enabled" if value is True else "disabled" if value is False else "unknown"
        checks.append(
            {
                "id": key,
                "title": title,
                "state": state,
                "observation": f"{title}: {state}.",
                "precaution": action,
                "attention": "verify"
                if state == "unknown"
                else "review"
                if (
                    value is True
                    if key in {"RemoteDesktop", "SMB1", "RebootPending"}
                    else value is False
                )
                else "observed",
            }
        )

    def clean(value):
        return "".join(char for char in str(value) if char.isprintable())[:80]

    providers = values.get("Antivirus")
    listeners = values.get("Listeners")
    network = []
    if isinstance(listeners, list):
        import ipaddress

        for item in listeners[:64]:
            if (
                not isinstance(item, dict)
                or type(item.get("port")) is not int
                or not 1 <= item["port"] <= 65535
            ):
                continue
            try:
                address = ipaddress.ip_address(item.get("address", ""))
            except ValueError:
                continue
            network.append(
                {
                    "port": item["port"],
                    "application": clean(item.get("app", "unknown")),
                    "binding": "this device only"
                    if address.is_loopback
                    else "network interface; reachability unverified",
                }
            )
    report = {
        "active_profiles": sorted(
            {
                name
                for name in values.get("ActiveProfiles", [])
                if isinstance(name, str) and name in {"Domain", "Private", "Public"}
            }
        )
        if isinstance(values.get("ActiveProfiles"), list)
        else [],
        "antivirus_providers": [clean(name) for name in providers[:8] if isinstance(name, str)]
        if isinstance(providers, list)
        else [],
        "listeners": network,
        "last_recorded_update": clean(values.get("LastUpdate", "unknown")),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "boundary": "This checks the computer running VulnAssess, not a remote browser device. Loopback services do not prove internet exposure. Firewall profiles may be inactive; disabled Defender does not prove there is no other antivirus.",
        "limitations": "Light service detection and read-only Windows protection status only. Malware, installed-software patch completeness, router settings, backups and internet reachability were not checked. Unavailable or unsupported checks remain unknown.",
    }
    report["action_queue"] = prioritize(report)
    return report


def prioritize(report: dict) -> list[dict]:
    """Deterministic verification order; never vulnerability scores or exposure claims."""
    checks = {row["id"]: row for row in report["checks"]}
    active = report.get("active_profiles", [])
    network_listeners = [
        row for row in report.get("listeners", []) if row["binding"] != "this device only"
    ]
    actions = []
    for profile in active:
        if checks.get(profile, {}).get("state") == "disabled":
            actions.append(
                {
                    "title": "Review the firewall on your active network",
                    "reason": f"The {profile} network profile is active and its firewall is disabled. Reachability still depends on other controls.",
                    "action": checks[profile]["precaution"],
                    "basis": [profile, "active_profiles"],
                    "kind": "observed configuration gap",
                }
            )
            if network_listeners:
                actions[-1]["basis"].append("listeners")
                actions[-1]["reason"] += (
                    " Applications also listen on network interfaces; internet reachability is not established. Review the listed applications and intended access together."
                )
                actions[-1]["supporting_observations"] = [
                    f"{row['application']} · TCP {row['port']} · {row['binding']}"
                    for row in network_listeners[:5]
                ]
    for check in report["checks"]:
        if check["id"] in {"Domain", "Private", "Public"}:
            continue
        if check.get("attention") == "review":
            actions.append(
                {
                    "title": check["title"],
                    "reason": check["observation"],
                    "action": check["precaution"],
                    "basis": [check["id"]],
                    "kind": "review setting",
                }
            )
    remote = checks.get("RemoteDesktop", {}).get("state") == "enabled"
    if remote and any(
        row["port"] == 3389 and row["binding"] != "this device only"
        for row in report.get("listeners", [])
    ):
        actions.append(
            {
                "title": "Confirm who needs remote access",
                "reason": "Remote Desktop is enabled and TCP 3389 has a non-loopback listener. This does not prove internet access or identify the listener as Remote Desktop.",
                "action": "Review Settings → System → Remote Desktop and authorized users. Disabling access can interrupt remote support.",
                "basis": ["RemoteDesktop", "listeners"],
                "kind": "correlated verification",
            }
        )
    if not active:
        actions.append(
            {
                "title": "Verify your active network profile",
                "reason": "The active network profile was not established, so firewall relevance cannot be confirmed.",
                "action": "Open Windows Security → Firewall & network protection and check the active network.",
                "basis": ["active_profiles"],
                "kind": "not verified",
            }
        )
    for check in report["checks"]:
        if check["state"] == "unknown":
            actions.append(
                {
                    "title": check["title"],
                    "reason": "The read-only check could not establish this setting.",
                    "action": check["precaution"],
                    "basis": [check["id"]],
                    "kind": "not verified",
                }
            )
    return actions


def compare(previous: dict | None, current: dict) -> dict:
    """Compare like-for-like settings, without calling a changed setting a fixed threat."""
    if previous is None:
        return {"status": "baseline", "changes": []}
    before = {row["id"]: row["state"] for row in previous.get("checks", [])}
    changes = [
        {"check": row["title"], "before": before[row["id"]], "after": row["state"]}
        for row in current["checks"]
        if row["id"] in before and before[row["id"]] != row["state"]
    ]
    return {"status": "compared", "previous_at": previous.get("checked_at"), "changes": changes}


def save_recheck(root, report):
    """Append a local observation; return ten matching records from the latest 100.

    Hashes detect accidental edits, not an attacker able to replace both record and hash.
    Existing legacy records without a hash are retained but excluded from comparisons.
    """

    def digest(value):
        return hashlib.sha256(
            json.dumps(value, sort_keys=True, ensure_ascii=True).encode()
        ).hexdigest()

    check_id = report["checks"][0]["id"]
    root.mkdir(parents=True, exist_ok=True)
    identity = uuid4().hex
    with (root / f"{identity}.json").open("x", encoding="utf-8") as output:
        json.dump({"target": "127.0.0.1", "observation": report, "sha256": digest(report)}, output)
    history = []
    candidates = sorted(
        root.glob("*.json"), key=lambda path: path.stat().st_mtime_ns, reverse=True
    )[:100]
    for path in candidates:
        try:
            if path.stat().st_size > 65536:
                continue
            record = json.loads(path.read_text(encoding="utf-8"))
            observation = record["observation"]
            if record["target"] != "127.0.0.1" or digest(observation) != record["sha256"]:
                continue
            check = observation["checks"][0]
            timestamp = observation["checked_at"]
            if (
                len(observation["checks"]) != 1
                or check["id"] != check_id
                or check["state"] not in {"enabled", "disabled", "unknown"}
                or not isinstance(timestamp, str)
                or len(timestamp) > 40
            ):
                continue
            datetime.fromisoformat(timestamp)
            history.append({"id": path.stem, "checked_at": timestamp, "state": check["state"]})
        except (OSError, ValueError, KeyError, TypeError, IndexError):
            continue

    def observation_time(row):
        timestamp = datetime.fromisoformat(row["checked_at"])
        return timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp

    # File timestamps may tie or change when copied; order verified observations.
    history.sort(key=lambda row: (observation_time(row), row["id"]), reverse=True)
    return {**report, "recheck_id": identity, "history": history[:10]}


def previous_capture(root):
    """Use only hash-verified local protection evidence; never imported network cases."""
    import hashlib

    candidates = sorted(
        root.glob("assessment-*/device-check.json"), key=lambda p: p.stat().st_mtime, reverse=True
    )[:100]
    for path in candidates:
        try:
            if path.stat().st_size > 65536:
                continue
            raw = path.read_bytes()
            manifest = json.loads(path.with_name("manifest.json").read_text(encoding="utf-8"))
            if (
                manifest.get("resolved_ip") != "127.0.0.1"
                or manifest.get("files", {}).get(path.name) != hashlib.sha256(raw).hexdigest()
            ):
                continue
            result = json.loads(raw)
            if (
                isinstance(result, dict)
                and isinstance(result.get("checks"), list)
                and all(
                    isinstance(row, dict)
                    and row.get("id") in CHECKS
                    and row.get("state") in {"enabled", "disabled", "unknown"}
                    for row in result["checks"]
                )
            ):
                return result
        except (OSError, ValueError, TypeError):
            continue
    return None
