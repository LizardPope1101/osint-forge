#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 -m py_compile forge/osint_forge.py
python3 -m unittest discover -s tests -v
./bin/osint forge validate
bash -n bootstrap.sh bin/osint scripts/*.sh plugins/*/*.sh docs/plugin-template/*.sh

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -e SC1090,SC2034 \
        bootstrap.sh bin/osint scripts/*.sh plugins/*/*.sh docs/plugin-template/*.sh
else
    echo "WARN: shellcheck is not installed; skipped shell lint" >&2
fi

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git diff --check
else
    echo "WARN: not a Git worktree; skipped git diff check" >&2
fi
echo "All available development checks passed."
