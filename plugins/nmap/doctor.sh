#!/usr/bin/env bash
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
need nmap
nmap --version | head -n 1
