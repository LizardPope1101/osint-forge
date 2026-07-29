#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
base="/opt/osint-forge/recon-ng"
run git -C "$base" pull --ff-only
run "$base/.venv/bin/pip" install -r "$base/REQUIREMENTS"
run install -m 0755 "${OSINT_FORGE_PLUGIN_DIR}/launcher.sh" /usr/local/bin/recon-ng
