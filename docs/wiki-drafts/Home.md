# OSINT Forge

OSINT Forge is a modular, open-source command-line framework for building and
running authorized OSINT workflows on Debian and Ubuntu. It installs and
maintains trusted tools through reviewed plugins, processes individual or batch
targets, and preserves private, reproducible case records.

> Use OSINT Forge only for lawful research. Scan infrastructure only when you
> own it or have explicit authorization.

## Current release

**v0.3.1** remains the latest stable release. Use the stable tag for real
authorized work.

- [Release v0.3.1](https://github.com/LizardPope1101/osint-forge/releases/tag/v0.3.1)
- [Changelog](https://github.com/LizardPope1101/osint-forge/blob/main/CHANGELOG.md)
- [[Roadmap]] — committed through v1.0, tentative through v2.0

## v0.4 development status

The `main` branch is currently **v0.4.0-dev**. Its normalized-reporting
implementation has passed local and hosted automated validation but is not a
release candidate until live Debian VM testing is complete.

Development capabilities include:

- a versioned common finding and report contract;
- ExifTool, GHunt, Maigret, Nmap, and Sherlock normalizers;
- deterministic JSON, Markdown, HTML, and CSV reports;
- complete target, plugin, command, run, timestamp, exit, source-file, and
  raw-output provenance;
- explicit failed, previewed, normalization-error, and orphaned-review states;
- analyst confidence and notes;
- stable finding IDs across equivalent reruns; and
- conservative shareable redaction.

See [[Normalized Reporting]] and [[Case Management]].

## Start here

- [[Installation]] — install or upgrade on Debian and Ubuntu
- [[Command Reference]] — complete CLI overview
- [[Case Management]] — create, run, resume, inspect, review, and report cases
- [[Normalized Reporting]] — report contracts, formats, annotations, and redaction
- [[Batch Workflows]] — process organized target files
- [[Plugin Catalog]] — included tools, targets, and limitations
- [[Plugin Development]] — build and validate governed plugins
- [[Architecture]] — framework, state, schemas, and execution model
- [[Development and CI]] — tests, environments, and pull requests
- [[Troubleshooting]] — diagnose installation and runtime problems
- [[Security and Ethics]] — authorization, privacy, and vulnerabilities
- [[Licensing and Contributions]] — GPL terms and contribution rules
- [[Release Process]] — sequential release gates
- [[Roadmap]] — committed releases and tentative goals

## Quick start

```bash
git clone --branch v0.3.1 https://github.com/LizardPope1101/osint-forge.git
cd osint-forge
chmod +x bootstrap.sh
./bootstrap.sh

osint forge validate
osint forge list
osint --version
```

Individual tools remain opt-in. Install only what an authorized workflow
requires.

Copyright © 2026 LizardPope1101.
