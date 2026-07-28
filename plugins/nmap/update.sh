#!/usr/bin/env bash
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
run apt-get update
run apt-get install --only-upgrade -y nmap
