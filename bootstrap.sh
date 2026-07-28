#!/usr/bin/env bash
set -Eeuo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
  echo "OSINT Forge bootstrap currently supports Debian-based systems (apt-get)." >&2
  exit 1
fi

if [[ ${EUID} -eq 0 ]]; then
  APT=(apt-get)
elif command -v sudo >/dev/null 2>&1; then
  APT=(sudo apt-get)
else
  echo "sudo is required when bootstrap.sh is not run as root." >&2
  exit 1
fi

"${APT[@]}" update
"${APT[@]}" install -y \
  ca-certificates \
  git \
  pipx \
  python3 \
  python3-pip \
  python3-venv \
  sudo

python3 "$(dirname "$0")/install.py"

