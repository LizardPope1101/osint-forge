#!/usr/bin/env bash
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
need spiderfoot
spiderfoot --help >/dev/null 2>&1 || true
say "OK: spiderfoot"
