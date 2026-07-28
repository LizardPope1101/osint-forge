#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
set -Eeuo pipefail

plugin_id="${OSINT_FORGE_PLUGIN_ID:?missing plugin id}"
plugin_dir="${OSINT_FORGE_PLUGIN_DIR:?missing plugin dir}"
dry_run="${OSINT_FORGE_DRY_RUN:-0}"

say() { printf '%s\n' "$*"; }
run() {
    if [[ "$dry_run" == "1" ]]; then
        printf 'DRY-RUN:'
        printf ' %q' "$@"
        printf '\n'
    else
        "$@"
    fi
}
need() {
    command -v "$1" >/dev/null 2>&1 || {
        say "Missing dependency: $1"
        return 1
    }
}
as_target_user() {
    local target="${SUDO_USER:-$USER}"
    if [[ "$(id -u)" -eq 0 && "$target" != "root" ]]; then
        run sudo -H -u "$target" "$@"
    else
        run "$@"
    fi
}
