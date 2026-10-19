"""Nmap XML -> hosts + findings. Produced by: nmap -sV -O [--script vulners] -oX out.xml <target>."""

import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

from vulnassess import protocols
from vulnassess.errors import AdapterError
from vulnassess.readers._input import read_capture, reject_xml_declarations, validate_tree
from vulnassess.schema import Finding, Host, Provenance, Service

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


def _iso(epoch: str | None, fallback: str) -> str:
    if not epoch:
        return fallback
    try:
        return datetime.fromtimestamp(int(epoch), UTC).isoformat()
    except (ValueError, OverflowError, OSError):
        return fallback


def _service(port_node: ET.Element) -> Service:
    port = int(port_node.get("portid", "0"))
    protocol = port_node.get("protocol", "tcp")
    service_node = port_node.find("service")
    name = product = version = extrainfo = None
    cpe = None
    if service_node is not None:
        name = service_node.get("name")
        product = service_node.get("product")
        version = service_node.get("version")
        extrainfo = service_node.get("extrainfo")
        cpe_node = service_node.find("cpe")
        if cpe_node is not None and cpe_node.text:
            cpe = cpe_node.text.strip()
    tunnel = service_node.get("tunnel") if service_node is not None else None
    banner = " ".join(
        part for part in [f"{port}/{protocol}", name, product, version, extrainfo] if part
    )
    return Service(
        port=port,
        protocol=protocol,
        name=name,
        product=product,
        version=version,
        cpe=cpe,
        banner=banner,
        tls=(tunnel == "ssl")
        or (
            service_node is not None
            and service_node.get("method") != "table"
            and protocols.tls_service_name(name)
        ),
    )


def _cve_line(output: str, cve: str) -> str:
    for line in output.splitlines():
        if cve in line:
            return line.strip()
    return output.strip()


def parse_nmap_xml(path: str | Path, run_id: str) -> tuple[list[Host], list[Finding]]:
    path, content = read_capture(path, "nmap")
    reject_xml_declarations(content, path, "nmap")
    try:
        root = ET.fromstring(content)
    except ET.ParseError as error:
        raise AdapterError(f"nmap: {path} is not parsable XML ({error})") from error
    validate_tree(root, path, "nmap")
    if root.tag != "nmaprun":
        raise AdapterError(f"nmap: {path} root element is <{root.tag}>, expected <nmaprun>")

    run_start = _iso(root.get("start"), "")
    hosts: list[Host] = []
    findings: list[Finding] = []
    record_index = 0

    for host_node in root.findall("host"):
        status = host_node.find("status")
        if status is not None and status.get("state") != "up":
            continue
        address = next(
            (
                node.get("addr")
                for node in host_node.findall("address")
                if node.get("addrtype") == "ipv4"
            ),
            None,
        )
        if not address:
            continue

        hostname_node = host_node.find("hostnames/hostname")
        hostname = hostname_node.get("name") if hostname_node is not None else None
        os_matches = host_node.findall("os/osmatch")
        best_os = max(os_matches, key=lambda node: int(node.get("accuracy") or 0), default=None)
        first_seen = _iso(host_node.get("starttime"), run_start)
        last_seen = _iso(host_node.get("endtime"), first_seen)

        services: list[Service] = []
        for port_node in host_node.findall("ports/port"):
            state = port_node.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = _service(port_node)
            services.append(service)

            for script in port_node.findall("script"):
                output = script.get("output") or ""
                script_id = script.get("id") or "script"
                for cve in sorted(set(CVE_PATTERN.findall(output))):
                    record_index += 1
                    label = service.name or str(service.port)
                    findings.append(
                        Finding.make(
                            host_ip=address,
                            port=service.port,
                            protocol=service.protocol,
                            url=None,
                            tool="nmap",
                            tool_native_id=f"{script_id}:{cve}",
                            title=f"{script_id} reports {cve} on {label}",
                            description=output.strip(),
                            evidence=_cve_line(output, cve),
                            cve_ids=[cve],
                            native_severity=None,
                            native_confidence=None,
                            first_seen=first_seen,
                            last_seen=last_seen,
                            provenance=Provenance(
                                tool="nmap",
                                raw_path=str(path),
                                record_index=record_index,
                                run_id=run_id,
                            ),
                        )
                    )

        hosts.append(
            Host(
                ip=address,
                hostname=hostname,
                os_guess=best_os.get("name") if best_os is not None else None,
                services=tuple(services),
            )
        )

    return hosts, findings
