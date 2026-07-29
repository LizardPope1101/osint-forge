#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
# shellcheck source=plugins/spiderfoot/build-dependencies.sh
source "${OSINT_FORGE_PLUGIN_DIR}/build-dependencies.sh"
# shellcheck source=plugins/spiderfoot/requirements-compat.sh
source "${OSINT_FORGE_PLUGIN_DIR}/requirements-compat.sh"
base="/opt/osint-forge/spiderfoot"
install_spiderfoot_build_dependencies
run git -C "$base" pull --ff-only
requirements="$(spiderfoot_requirements_file "$base" "$base/.venv/bin/python")"
run "$base/.venv/bin/pip" install -r "$requirements"
run install -m 0755 "${OSINT_FORGE_PLUGIN_DIR}/launcher.sh" /usr/local/bin/spiderfoot
