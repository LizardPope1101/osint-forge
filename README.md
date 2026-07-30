# OSINT Forge

[![CI](https://github.com/LizardPope1101/osint-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/LizardPope1101/osint-forge/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/LizardPope1101/osint-forge)](https://github.com/LizardPope1101/osint-forge/releases/latest)

OSINT Forge is a modular OSINT tool manager and evidence-preserving
investigation workflow for a minimal Debian-based workstation. Its v1.0
direction is an authorized, bounded intelligence workflow that can start with
multiple known entities, coordinate compatible tools, correlate new leads, and
produce transparent confidence-filtered reporting without discarding raw
evidence.

Use it only for lawful research. Network scanning must be limited to systems
you own or are explicitly authorized to assess.

## Requirements

OSINT Forge supports Debian stable and Ubuntu 24.04 with Python 3.10 through
3.13. Use the latest stable release for investigations. The `main` branch is
the active development branch and may contain changes intended for the next
release.

## Fresh Debian/Ubuntu installation

Clone the latest stable tag:

```bash
git clone --branch v0.3.1 https://github.com/LizardPope1101/osint-forge.git
cd osint-forge
chmod +x bootstrap.sh
./bootstrap.sh
```

The bootstrap installs the base dependencies (`python3`, `python3-venv`,
`python3-pip`, `pipx`, `git`, `sudo`, and `ca-certificates`) and installs the
framework. It also configures pipx's standard per-user binary directory for
future login shells. Open a new terminal after bootstrap if the shell does not
yet find a newly installed pipx command. Individual OSINT tools remain opt-in.

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
ignored. Adapter and batch output paths reject symbolic links, including
symbolic-link parent directories.

## Case management

Create a private, resumable investigation workspace and document why the work
is authorized:

```bash
osint case create example-case \
  --purpose "Investigate authorized brand impersonation" \
  --authorization "Written authorization from Example Organization"

osint case add example-case username example_handle
osint case add example-case email analyst@example.com
osint case add example-case name "Example Person"
osint case add example-case phone "+1 (555) 555-0100"
osint case add example-case address "1 Example Way, Example City, NY"
osint case run example-case --plugins maigret sherlock
osint case status example-case
osint case entities example-case
osint case report example-case
osint case report example-case --format all
```

Case data defaults to `~/OSINT-Cases/<case-id>/`. Metadata, targets, raw tool
output, commands, timestamps, plugin versions, exit statuses, and an
append-only activity log are stored with owner-only permissions. Re-running
`osint case run` skips successful jobs and retries failed or missing jobs.
Use `--rerun` to execute successful jobs again.

The default Markdown report remains available at `report.md`. In v0.4,
`--format all` also produces a versioned JSON master report, HTML report, and
CSV findings summary. Findings retain target, plugin, command, run, timestamp,
exit-status, source-file, and raw-output provenance. Use
`osint case findings` for stable finding IDs and `osint case annotate` for
confidence or analyst notes. `--shareable` creates conservatively redacted
copies that still require review before distribution.

Normalized findings remain unverified leads. See
[`docs/CASE-MANAGEMENT.md`](docs/CASE-MANAGEMENT.md) and
[`docs/REPORTING.md`](docs/REPORTING.md).

Version 0.4 also exposes a versioned entity foundation. Name, phone, and
address seeds can be added even when no current plugin consumes them, and
`osint case entities` projects every case target into a canonical,
provenance-linked seed entity. This is additive groundwork for later
correlation and controlled recursive discovery; it does not infer identity or
automatically pursue new targets.
See [`docs/ENTITY-MODEL.md`](docs/ENTITY-MODEL.md) for the versioned contract
and forward-compatibility rules.

## Modular plugin system

Every tool is a self-contained plugin:

```text
plugins/<tool>/
├── manifest.json
├── install.sh
├── update.sh
├── remove.sh
├── doctor.sh
└── normalize.py
```

The manifest declares categories, commands, supported target types, lifecycle
scripts, root requirements, target adapters, and (for batch plugins) a
normalizer. Adapter commands are argument arrays rather than interpolated shell
strings.

Validate the complete plugin contract without executing a plugin:

```bash
osint forge validate
osint forge validate --json
```

Copy `docs/plugin-template` to start a new plugin. See
[`docs/PLUGIN-API.md`](docs/PLUGIN-API.md) for the full contract.

## Roadmap

The complete recursive intelligence workflow is a committed v1.0 goal, not a
post-v1.0 possibility. Development proceeds additively so current case,
plugin, evidence, and CLI behavior remains testable while the new entity,
correlation, and discovery layers mature.

See the canonical repository [Roadmap to v1.0](docs/ROADMAP.md) and the
[architecture tracking issue](https://github.com/LizardPope1101/osint-forge/issues/44).
Release work is tracked in:

- [v0.4: normalized reporting and seed entities](https://github.com/LizardPope1101/osint-forge/issues/6)
- [v0.5: entity-aware plugin expansion](https://github.com/LizardPope1101/osint-forge/issues/13)
- [v0.6: entity-aware planning and workflows](https://github.com/LizardPope1101/osint-forge/issues/18)
- [v0.7: evidence integrity and portable exports](https://github.com/LizardPope1101/osint-forge/issues/14)
- [v0.8: correlation and transparent confidence](https://github.com/LizardPope1101/osint-forge/issues/15)
- [v0.9: controlled recursive discovery and v1 contract freeze](https://github.com/LizardPope1101/osint-forge/issues/17)
- [v1.0: stable intelligence workflow](https://github.com/LizardPope1101/osint-forge/issues/16)

Until v1.0, minor releases may include breaking changes. Review the
[changelog](CHANGELOG.md) before upgrading.

## Uninstall the framework

```bash
sudo ./scripts/uninstall-framework.sh
```

This removes the OSINT Forge launcher and framework files. Installed
third-party tools and case data are left intact.

## Security

Do not report vulnerabilities publicly. Follow the project's
[Security Policy](.github/SECURITY.md) for scope and private-reporting guidance.

## Project governance

Project ownership, decision authority, access control, policy precedence, and
administrative change management are defined in
[`GOVERNANCE.md`](GOVERNANCE.md). AI-assisted work and the exclusive authority
to connect AI systems to the repository are governed by
[`AI_POLICY.md`](AI_POLICY.md). Contributors should also review
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

OSINT Forge is licensed under the
[GNU General Public License v3.0 or later](LICENSE).

Copyright © 2026 LizardPope1101.

OSINT Forge installs and invokes independent third-party programs; it does not
relicense them. Each program remains subject to its own license. See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
