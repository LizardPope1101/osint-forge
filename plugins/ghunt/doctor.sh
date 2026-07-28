#!/usr/bin/env bash
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
need "ghunt"
"ghunt" --help >/dev/null 2>&1 || true
say "OK: ghunt"
