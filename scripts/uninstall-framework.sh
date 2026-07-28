#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
set -Eeuo pipefail
if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo." >&2
    exit 1
fi
INSTALL_ROOT="${OSINT_FORGE_INSTALL_ROOT:-/usr/local/share/osint-forge}"
BIN_DIR="${OSINT_FORGE_BIN_DIR:-/usr/local/bin}"
for path in "$INSTALL_ROOT" "$BIN_DIR"; do
    if [[ "$path" != /* || "$path" == "/" ]]; then
        echo "Refusing unsafe uninstall path: $path" >&2
        exit 1
    fi
done
rm -f -- "$BIN_DIR/osint"
rm -rf -- "$INSTALL_ROOT"
echo "Framework removed. Installed third-party tools and case data were left intact."
