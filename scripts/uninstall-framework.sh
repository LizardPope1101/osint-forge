#!/usr/bin/env bash
set -Eeuo pipefail
if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo." >&2
    exit 1
fi
rm -f /usr/local/bin/osint
rm -rf /usr/local/share/osint-forge
echo "Framework removed. Installed third-party tools and case data were left intact."
