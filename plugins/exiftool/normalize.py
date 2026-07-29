# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Normalize ExifTool JSON output into the OSINT Forge finding contract."""

import json
from pathlib import Path
import sys


def main() -> int:
    output = Path(sys.argv[1])
    source = output / "stdout.log"
    if source.is_symlink():
        raise ValueError("ExifTool source cannot be a symbolic link")
    if source.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("ExifTool JSON exceeds the normalizer limit")
    records = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError("ExifTool output must be a JSON array")
    findings = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        source_file = record.get("SourceFile")
        findings.append({
            "kind": "metadata_record",
            "category": "metadata",
            "title": f"File metadata record {index + 1}",
            "value": str(source_file) if source_file is not None else None,
            "attributes": {
                str(key): value
                for key, value in sorted(record.items())
                if key != "SourceFile"
            },
            "source_file": "stdout.log",
        })
    print(json.dumps({"schema": 1, "findings": findings}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
