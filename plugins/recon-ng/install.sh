#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
need git
need python3
base="/opt/osint-forge/recon-ng"
run mkdir -p /opt/osint-forge
if [[ "$dry_run" == "1" ]]; then
    run git clone https://github.com/lanmaster53/recon-ng "$base"
else
    if [[ ! -d "$base/.git" ]]; then git clone https://github.com/lanmaster53/recon-ng "$base"; fi
    python3 -m venv "$base/.venv"
    "$base/.venv/bin/pip" install --upgrade pip wheel
    "$base/.venv/bin/pip" install -r "$base/REQUIREMENTS"
    install -m 0755 "${OSINT_FORGE_PLUGIN_DIR}/launcher.sh" /usr/local/bin/recon-ng
fi
