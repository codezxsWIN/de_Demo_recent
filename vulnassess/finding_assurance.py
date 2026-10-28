"""Bounded report facts; no inference of package identity or exploitability."""

from vulnassess.redis_probe import POSITIVE, REQUEST


def is_redis_lua(finding):
    return finding.get("tool") == "redis-check" and "CVE-2022-0543" in finding.get("cve_ids", [])


def assurance(finding):
    if finding.get("tool") == "nvd-cpe":
        from vulnassess.cve_discovery import candidate_facts

        facts = candidate_facts(finding)
        if facts:
            return {
                "condition": "Observed product/version matches an NVD applicability branch",
                "cve": "Candidate association — package and patch applicability unconfirmed",
                "package": "Package revision, vendor backports and required configuration not established",
                "exploitability": "Not tested — no exploit, command execution or compromise demonstrated",
                "priority": "Conditional CVE triage; not proof of confirmed vulnerability or exploitation",
            }
    if not is_redis_lua(finding):
        return None
    return {
        "condition": "Scanner-observed Lua sandbox condition",
        "cve": "Candidate association — vendor-package applicability unconfirmed",
        "package": "Distribution, package revision and vendor patch status not established",
        "exploitability": "Not tested — no library loading or OS command execution",
        "priority": "Conditional triage priority for the associated CVE, not proof of CVE applicability",
    }


def bounded_redis_proof(raw, target_ip, findings, sha256):
    """Expose only the fixed request and exact positive response, never arbitrary text."""
    if not isinstance(raw, dict) or raw.get("target_ip") != target_ip:
        return {"status": "unavailable", "reason": "Probe target does not match this capture"}
    port = raw.get("port")
    bound = [
        f["id"]
        for f in findings
        if isinstance(f.get("id"), str)
        and (
            is_redis_lua(f)
            and f.get("host_ip") == target_ip
            and f.get("port") == port
            and f.get("protocol") == "tcp"
        )
    ]
    if (
        type(port) is not int
        or not 1 <= port <= 65535
        or not bound
        or raw.get("check") != "lua-package-type-v1"
        or raw.get("request") != REQUEST.decode("ascii")
        or raw.get("response") != POSITIVE.decode("ascii")
    ):
        return {
            "status": "unavailable",
            "reason": "No exact, finding-bound positive probe; arbitrary response text withheld",
        }
    return {
        "status": "verified",
        "target_ip": target_ip,
        "finding_ids": bound,
        "port": port,
        "protocol": "tcp",
        "request": REQUEST.decode("ascii"),
        "response": POSITIVE.decode("ascii"),
        "sha256": sha256,
        "establishes": "The fixed EVAL command completed on a new connection without an AUTH exchange and returned table:function.",
        "limitations": "This establishes access to this command from this vantage at that time, not global authentication policy, all command ACLs, package identity, or remote code execution.",
    }
