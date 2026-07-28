# OSINT Forge

[![CI](https://github.com/LizardPope1101/osint-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/LizardPope1101/osint-forge/actions/workflows/ci.yml)

OSINT Forge is a modular tool manager and workflow layer for a minimal
Debian-based OSINT workstation.

Use it only for lawful research. Network scanning must be limited to systems
you own or are explicitly authorized to assess.

## Fresh Debian/Ubuntu installation

```bash
git clone https://github.com/LizardPope1101/osint-forge.git
cd osint-forge
chmod +x bootstrap.sh
./bootstrap.sh
```

The bootstrap installs the base dependencies (`python3`, `python3-venv`,
`python3-pip`, `pipx`, `git`, `sudo`, and `ca-certificates`) and installs the
framework. Individual OSINT tools remain opt-in.

```bash
osint forge list
osint forge categories
osint forge doctor
osint forge validate
osint forge version
```

## Install and maintain tools

```bash
osint forge install maigret
osint forge install maigret sherlock ghunt
osint forge install usernames
osint forge install infrastructure --dry-run

osint forge update maigret
osint forge doctor
osint forge remove recon-ng
```

Dry-run mode previews lifecycle commands without requiring optional tool
dependencies to be installed.

## Run one adapter

```bash
osint run maigret username example_handle -o ~/OSINT-Cases/example/maigret
osint run exiftool image photograph.jpg -o ~/OSINT-Cases/example/metadata
```

## Batch processing

Edit `~/.config/osint-forge/targets.txt`:

```ini
[Emails]
analyst@example.com

[Usernames]
example_handle

[Domains]
example.com

[Images]
./photograph.jpg
```

Then run:

```bash
osint batch --name initial-sweep
osint batch --plugins maigret sherlock --name usernames-only
```

The batch engine discovers compatible installed plugins from their manifests.
Results default to `~/OSINT-Cases/Batch-Runs/`. Framework state is stored
consistently in `~/.local/state/osint-forge/`.
Unknown names passed to `--plugins` are rejected instead of being silently
ignored.

## Modular plugin system

Every tool is a self-contained plugin:

```text
plugins/<tool>/
├── manifest.json
├── install.sh
├── update.sh
├── remove.sh
└── doctor.sh
```

The manifest declares categories, commands, supported target types, lifecycle
scripts, root requirements, and target adapters. Adapter commands are argument
arrays rather than interpolated shell strings.

Validate the complete plugin contract without executing a plugin:

```bash
osint forge validate
osint forge validate --json
```

Copy `docs/plugin-template` to start a new plugin. See
[`docs/PLUGIN-API.md`](docs/PLUGIN-API.md) for the full contract.

## Uninstall the framework

```bash
sudo ./scripts/uninstall-framework.sh
```

This removes the OSINT Forge launcher and framework files. Installed
third-party tools and case data are left intact.

## Security

Do not report vulnerabilities publicly. Follow the project's
[Security Policy](.github/SECURITY.md) for scope and private-reporting guidance.

## License

OSINT Forge is licensed under the
[GNU General Public License v3.0 or later](LICENSE).

Copyright © 2026 LizardPope1101.

OSINT Forge installs and invokes independent third-party programs; it does not
relicense them. Each program remains subject to its own license. See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
