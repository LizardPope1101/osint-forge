# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Normalize Sherlock's CSV report."""

import csv
import json
from pathlib import Path
import sys


NEGATIVE = ("not found", "available", "unknown", "error")


def main() -> int:
    output = Path(sys.argv[1])
    sources = sorted(output.glob("*.csv"))
    if not sources:
        raise FileNotFoundError("Sherlock CSV report was not produced")
    source = sources[0]
    if source.is_symlink():
        raise ValueError("Sherlock source cannot be a symbolic link")
    if source.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Sherlock CSV exceeds the normalizer limit")
    with source.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    findings = []
    for row in rows:
        normalized = {str(key): value for key, value in row.items() if key is not None}
        lowered = {key.lower(): value for key, value in normalized.items()}
        site = lowered.get("name") or lowered.get("site name") or lowered.get("site")
        url = (
            lowered.get("url_user")
            or lowered.get("url")
            or lowered.get("profile url")
        )
        status = str(
            lowered.get("exists", lowered.get("status", ""))
        ).lower()
        if not url or any(marker in status for marker in NEGATIVE):
            continue
        findings.append({
            "kind": "username_profile",
            "category": "usernames",
            "title": f"Possible username profile on {site or 'unknown site'}",
            "value": str(url),
            "attributes": dict(sorted(normalized.items())),
            "source_file": source.name,
        })
    findings.sort(key=lambda item: (item["title"], item["value"]))
    print(json.dumps({"schema": 1, "findings": findings}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
