#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_USER="${SUDO_USER:-${USER:-$(id -un)}}"
TARGET_HOME="${OSINT_FORGE_TARGET_HOME:-$(getent passwd "$TARGET_USER" | cut -d: -f6)}"
INSTALL_ROOT="${OSINT_FORGE_INSTALL_ROOT:-/usr/local/share/osint-forge}"
BIN_DIR="${OSINT_FORGE_BIN_DIR:-/usr/local/bin}"
ETC_ROOT="${OSINT_FORGE_ETC_ROOT:-/etc/osint-forge}"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo ./scripts/install-framework.sh" >&2
    exit 1
fi

for path in "$TARGET_HOME" "$INSTALL_ROOT" "$BIN_DIR" "$ETC_ROOT"; do
    if [[ "$path" != /* || "$path" == "/" ]]; then
        echo "Refusing unsafe installation path: $path" >&2
        exit 1
    fi
done
if [[ -z "$TARGET_HOME" || ! -d "$TARGET_HOME" ]]; then
    echo "Could not determine a valid home directory for $TARGET_USER." >&2
    exit 1
fi

install -d -m 0755 "$(dirname -- "$INSTALL_ROOT")" "$BIN_DIR" "$ETC_ROOT"
staging="$(mktemp -d "${INSTALL_ROOT}.new.XXXXXX")"
backup="$(mktemp -d "${INSTALL_ROOT}.old.XXXXXX")"
rmdir -- "$backup"
cleanup() {
    rm -rf -- "$staging"
}
trap cleanup EXIT

cp -a "$ROOT/forge" "$ROOT/plugins" "$ROOT/scripts" "$ROOT/workflows" "$staging/"
find "$staging" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$staging" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
find "$staging" -type d -exec chmod 0755 {} +
find "$staging" -type f -name '*.sh' -exec chmod 0755 {} +
chmod 0755 "$staging/forge/osint_forge.py"
launcher_sha256="$(sha256sum "$ROOT/bin/osint" | cut -d' ' -f1)"
printf 'schema=1\nlauncher_sha256=%s\n' "$launcher_sha256" \
    > "$staging/.osint-forge-install"
chmod 0644 "$staging/.osint-forge-install"

if [[ -e "$INSTALL_ROOT" || -L "$INSTALL_ROOT" ]]; then
    if [[ -L "$INSTALL_ROOT" || ! -d "$INSTALL_ROOT" ]]; then
        echo "Refusing to replace unsafe installation target: $INSTALL_ROOT" >&2
        exit 1
    fi
    if [[ ! -f "$INSTALL_ROOT/.osint-forge-install" ]] \
        && [[ ! -f "$INSTALL_ROOT/forge/osint_forge.py" \
              || ! -d "$INSTALL_ROOT/plugins" \
              || ! -d "$INSTALL_ROOT/scripts" ]]; then
        echo "Refusing to replace unrecognized directory: $INSTALL_ROOT" >&2
        exit 1
    fi
    mv -- "$INSTALL_ROOT" "$backup"
fi
if ! mv -- "$staging" "$INSTALL_ROOT"; then
    if [[ -e "$backup" || -L "$backup" ]]; then
        mv -- "$backup" "$INSTALL_ROOT"
    fi
    exit 1
fi
if [[ -e "$backup" || -L "$backup" ]]; then
    rm -rf -- "$backup"
fi
trap - EXIT

install -m 0755 "$ROOT/bin/osint" "$BIN_DIR/osint"

user_config="$TARGET_HOME/.config/osint-forge"
install -d -o "$TARGET_USER" -g "$TARGET_USER" -m 0700 "$user_config"
if [[ ! -e "$user_config/targets.txt" ]]; then
    install -o "$TARGET_USER" -g "$TARGET_USER" -m 0600 \
        "$ROOT/config/targets.example.txt" "$user_config/targets.txt"
fi

echo "OSINT Forge installed."
echo
echo "Try:"
echo "  osint forge list"
echo "  osint forge categories"
echo "  osint forge install usernames"
echo "  osint forge doctor"
