#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later

spiderfoot_build_dependencies=(
    build-essential
    cargo
    libffi-dev
    libjpeg-dev
    libopenjp2-7-dev
    libssl-dev
    libtinyxml2-dev
    libxml2-dev
    libxslt1-dev
    python3-dev
    swig
    zlib1g-dev
)

install_spiderfoot_build_dependencies() {
    run apt-get update
    run apt-get install -y "${spiderfoot_build_dependencies[@]}"
}
