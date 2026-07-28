#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_USER="${SUDO_USER:-$USER}"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo ./scripts/install-framework.sh" >&2
    exit 1
fi

install -d -m 0755 /usr/local/share/osint-forge
cp -a "$ROOT/forge" "$ROOT/plugins" "$ROOT/scripts" /usr/local/share/osint-forge/
find /usr/local/share/osint-forge -type d -exec chmod 0755 {} +
find /usr/local/share/osint-forge -type f -name '*.sh' -exec chmod 0755 {} +
chmod 0755 /usr/local/share/osint-forge/forge/osint_forge.py

install -m 0755 "$ROOT/bin/osint" /usr/local/bin/osint
install -d -m 0755 /etc/osint-forge

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
