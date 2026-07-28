#!/usr/bin/env bash
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
need git
need python3
base="/opt/osint-forge/recon-ng"
run mkdir -p /opt/osint-forge
if [[ "$dry_run" == "1" ]]; then
    run git clone https://github.com/lanmaster53/recon-ng "$base"
else
    if [[ ! -d "$base/.git" ]]; then git clone https://github.com/lanmaster53/recon-ng "$base"; fi
    python3 -m venv "$base/.venv"
    "$base/.venv/bin/pip" install --upgrade pip wheel
    "$base/.venv/bin/pip" install -r "$base/REQUIREMENTS"
    cat >/usr/local/bin/recon-ng <<'EOF'
#!/usr/bin/env bash
exec /opt/osint-forge/recon-ng/.venv/bin/python /opt/osint-forge/recon-ng/recon-ng "$@"
EOF
    chmod 0755 /usr/local/bin/recon-ng
fi
