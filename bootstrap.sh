#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
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

if [[ ${EUID} -eq 0 && -n ${SUDO_USER:-} && ${SUDO_USER} != "root" ]]; then
  sudo -H -u "$SUDO_USER" pipx ensurepath
else
  pipx ensurepath
fi

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ ${EUID} -eq 0 ]]; then
  "$ROOT/scripts/install-framework.sh"
else
  sudo "$ROOT/scripts/install-framework.sh"
fi
