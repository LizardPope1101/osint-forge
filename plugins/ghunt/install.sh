#!/usr/bin/env bash
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
need pipx
as_target_user pipx install "ghunt"
