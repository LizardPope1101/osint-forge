# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Normalize GHunt JSON output into the OSINT Forge finding contract."""

import json
from pathlib import Path
import sys


def main() -> int:
    source = Path(sys.argv[1]) / "results.json"
    if source.is_symlink():
        raise ValueError("GHunt source cannot be a symbolic link")
    if source.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("GHunt JSON exceeds the normalizer limit")
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, (dict, list)):
        raise ValueError("GHunt output must be a JSON object or array")
    finding = {
        "kind": "google_account_record",
        "category": "email",
        "title": "GHunt account record",
        "value": None,
        "attributes": {"result": payload},
        "source_file": "results.json",
    }
    print(json.dumps({"schema": 1, "findings": [finding]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
