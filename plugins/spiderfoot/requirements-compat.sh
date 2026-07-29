#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later

spiderfoot_requirements_file() {
    local base="${1:?missing SpiderFoot directory}"
    local python="${2:?missing Python interpreter}"
    local upstream="${base}/requirements.txt"
    local overlay="${base}/.osint-forge-requirements.txt"
    local temporary

    if ! "$python" -c \
        'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)'
    then
        printf '%s\n' "$upstream"
        return 0
    fi

    if [[ "${dry_run:-0}" == "1" ]]; then
        printf '%s\n' "$overlay"
        return 0
    fi

    temporary="$(mktemp "${base}/.osint-forge-requirements.XXXXXX")"
    if ! awk '
        /^[[:space:]]*lxml([<>=!~].*)?$/ {
            print "lxml>=5.3,<6"
            found++
            next
        }
        { print }
        END {
            if (found != 1) {
                exit 1
            }
        }
    ' "$upstream" >"$temporary"
    then
        rm -f "$temporary"
        printf 'Expected exactly one lxml requirement in %s\n' "$upstream" >&2
        return 1
    fi

    chmod 0644 "$temporary"
    mv -f "$temporary" "$overlay"
    printf '%s\n' "$overlay"
}
