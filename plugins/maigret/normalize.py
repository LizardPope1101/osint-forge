# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Normalize Maigret's simple JSON report."""

import json
from pathlib import Path
import sys


NEGATIVE = ("not found", "available", "unknown", "illegal", "error")


def main() -> int:
    output = Path(sys.argv[1])
    sources = sorted((output / "reports").glob("*_simple.json"))
    if not sources:
        raise FileNotFoundError("Maigret simple JSON report was not produced")
    source = sources[0]
    if source.is_symlink() or source.parent.is_symlink():
        raise ValueError("Maigret source cannot use a symbolic link")
    if source.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Maigret JSON exceeds the normalizer limit")
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Maigret output must be a JSON object")
    findings = []
    for site, record in sorted(payload.items()):
        if isinstance(record, str):
            record = {"url": record, "status": "Claimed"}
        if not isinstance(record, dict):
            continue
        url = record.get("url") or record.get("url_user") or record.get("profile_url")
        status = str(record.get("status", record.get("status_code", ""))).lower()
        if not url or any(marker in status for marker in NEGATIVE):
            continue
        findings.append({
            "kind": "username_profile",
            "category": "usernames",
            "title": f"Possible username profile on {site}",
            "value": str(url),
            "attributes": {
                str(key): value for key, value in sorted(record.items())
            },
            "source_file": source.relative_to(output).as_posix(),
        })
    print(json.dumps({"schema": 1, "findings": findings}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
