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
marker="$INSTALL_ROOT/.osint-forge-install"
if [[ -L "$INSTALL_ROOT" || ! -f "$marker" ]]; then
    echo "Refusing to remove an unrecognized installation: $INSTALL_ROOT" >&2
    exit 1
fi
expected_sha256="$(sed -n 's/^launcher_sha256=//p' "$marker")"
launcher="$BIN_DIR/osint"
if [[ -e "$launcher" || -L "$launcher" ]]; then
    if [[ -L "$launcher" || ! -f "$launcher" \
          || -z "$expected_sha256" \
          || "$(sha256sum "$launcher" | cut -d' ' -f1)" != "$expected_sha256" ]]; then
        echo "Refusing to remove an unrecognized launcher: $launcher" >&2
        exit 1
    fi
    rm -f -- "$launcher"
fi
rm -rf -- "$INSTALL_ROOT"
echo "Framework removed. Installed third-party tools and case data were left intact."
