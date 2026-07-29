#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
umask 0077
exec /opt/osint-forge/spiderfoot/.venv/bin/python /opt/osint-forge/spiderfoot/sf.py "$@"
