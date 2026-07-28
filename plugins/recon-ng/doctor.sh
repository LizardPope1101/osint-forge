#!/usr/bin/env bash
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
need recon-ng
recon-ng --help >/dev/null
say "OK: recon-ng"
