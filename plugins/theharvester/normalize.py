#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Normalize theHarvester JSON without performing network activity."""

import ipaddress
import json
from pathlib import Path
import re
import sys


EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


def as_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def as_domain(value: str) -> str | None:
    candidate = value.strip().casefold().removesuffix(".")
    return candidate if DOMAIN.fullmatch(candidate) else None


def add_candidate(
    candidates: dict[tuple[str, str], dict[str, str]],
    entity_type: str,
    value: str | None,
) -> None:
    if value:
        candidates[(entity_type, value)] = {
            "type": entity_type,
            "value": value,
            "source_file": "results.json",
        }


def string_list(payload: dict[str, object], key: str) -> list[str]:
    values = payload.get(key, [])
    if not isinstance(values, list) or not all(
        isinstance(value, str) for value in values
    ):
        raise ValueError(f"theHarvester {key} must be a list of strings")
    return values


def main() -> int:
    source = Path(sys.argv[1]) / "results.json"
    if source.is_symlink():
        raise ValueError("theHarvester source cannot be a symbolic link")
    if source.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("theHarvester JSON exceeds the normalizer limit")
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("theHarvester JSON root must be an object")

    candidates: dict[tuple[str, str], dict[str, str]] = {}
    findings = []

    for email in sorted(set(string_list(payload, "emails"))):
        if EMAIL.fullmatch(email.strip()):
            value = email.strip().casefold()
            add_candidate(candidates, "email", value)
            findings.append({
                "kind": "discovered_email",
                "category": "email",
                "title": "Observed email address",
                "value": value,
                "attributes": {},
                "source_file": "results.json",
            })

    for raw_host in sorted(set(string_list(payload, "hosts"))):
        host, separator, address = raw_host.strip().partition(":")
        domain = as_domain(host)
        ip = as_ip(address) if separator else as_ip(host)
        add_candidate(candidates, "domain", domain)
        add_candidate(candidates, "ip", ip)
        if domain or ip:
            findings.append({
                "kind": "discovered_host",
                "category": "infrastructure",
                "title": "Observed domain host",
                "value": domain or ip,
                "attributes": {"domain": domain, "ip": ip},
                "source_file": "results.json",
            })

    for raw_ip in sorted(set(string_list(payload, "ips"))):
        add_candidate(candidates, "ip", as_ip(raw_ip))

    print(json.dumps({
        "schema": 2,
        "findings": findings,
        "candidates": [candidates[key] for key in sorted(candidates)],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
