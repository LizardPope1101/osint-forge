#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
need git
need python3
base="/opt/osint-forge/spiderfoot"
run mkdir -p /opt/osint-forge
if [[ "$dry_run" == "1" ]]; then
    run git clone https://github.com/smicallef/spiderfoot "$base"
else
    if [[ ! -d "$base/.git" ]]; then git clone https://github.com/smicallef/spiderfoot "$base"; fi
    python3 -m venv "$base/.venv"
    "$base/.venv/bin/pip" install --upgrade pip wheel
    "$base/.venv/bin/pip" install -r "$base/requirements.txt"
    cat >/usr/local/bin/spiderfoot <<'EOF'
#!/usr/bin/env bash
exec /opt/osint-forge/spiderfoot/.venv/bin/python /opt/osint-forge/spiderfoot/sf.py "$@"
EOF
    chmod 0755 /usr/local/bin/spiderfoot
fi
