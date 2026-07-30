#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
need pipx
as_target_user pipx install --force \
    "git+https://github.com/laramies/theHarvester.git@4.11.1"
