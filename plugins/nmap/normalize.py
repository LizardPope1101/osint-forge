# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Normalize Nmap XML host and open-port records."""

import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def main() -> int:
    source = Path(sys.argv[1]) / "results.xml"
    if source.is_symlink():
        raise ValueError("Nmap source cannot be a symbolic link")
    if source.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Nmap XML exceeds the normalizer limit")
    root = ET.fromstring(source.read_bytes())
    findings = []
    candidates = []
    for host in root.findall("host"):
        addresses = sorted(
            address.get("addr", "")
            for address in host.findall("address")
            if address.get("addr")
        )
        hostnames = sorted(
            name.get("name", "")
            for name in host.findall("./hostnames/hostname")
            if name.get("name")
        )
        host_value = addresses[0] if addresses else (hostnames[0] if hostnames else None)
        findings.append({
            "kind": "network_host",
            "category": "infrastructure",
            "title": "Observed network host",
            "value": host_value,
            "attributes": {"addresses": addresses, "hostnames": hostnames},
            "source_file": "results.xml",
        })
        for address in addresses:
            candidates.append({
                "type": "ip",
                "value": address,
                "source_file": "results.xml",
            })
        for hostname in hostnames:
            candidates.append({
                "type": "domain",
                "value": hostname.casefold().removesuffix("."),
                "source_file": "results.xml",
            })
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            service_data = dict(sorted(service.attrib.items())) if service is not None else {}
            protocol = port.get("protocol", "")
            port_id = port.get("portid", "")
            findings.append({
                "kind": "open_network_service",
                "category": "infrastructure",
                "title": f"Open {protocol} port {port_id}",
                "value": f"{host_value}:{port_id}" if host_value else port_id,
                "attributes": {
                    "host": host_value,
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_data,
                },
                "source_file": "results.xml",
            })
    unique_candidates = {
        (candidate["type"], candidate["value"], candidate["source_file"]): candidate
        for candidate in candidates
    }
    print(json.dumps({
        "schema": 2,
        "findings": findings,
        "candidates": [
            unique_candidates[key] for key in sorted(unique_candidates)
        ],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
