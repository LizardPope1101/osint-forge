#!/usr/bin/env bash
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
base="/opt/osint-forge/spiderfoot"
run git -C "$base" pull --ff-only
run "$base/.venv/bin/pip" install -r "$base/requirements.txt"
