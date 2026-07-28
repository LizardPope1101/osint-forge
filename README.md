# OSINT Forge

OSINT Forge is a modular tool manager and workflow layer for a minimal Debian-based research workstation.

The framework itself does not hardcode how Maigret, Nmap, Recon-ng, or any other program is installed. Every tool is a self-contained plugin with:

```text
plugins/<tool>/
├── manifest.json
├── install.sh
├── update.sh
├── remove.sh
└── doctor.sh
```

The manifest declares:

- category and searchable tags
- installed commands
- supported target types
- whether it can participate in batch jobs
- lifecycle scripts
- target adapters

## Install the framework

```bash
unzip osint-forge.zip
cd osint-forge
sudo ./scripts/install-framework.sh
```

## Browse the catalog

```bash
osint forge list
osint forge categories
osint forge search username
osint forge info maigret
```

## Install tools

One tool:

```bash
osint forge install maigret
```

Several tools:

```bash
osint forge install maigret sherlock ghunt
```

An entire category:

```bash
osint forge install usernames
osint forge install infrastructure
```

Preview without changing the system:

```bash
osint forge install infrastructure --dry-run
```

## Maintain tools

```bash
osint forge update maigret
osint forge update usernames
osint forge update infrastructure
osint forge doctor
osint forge remove recon-ng
```

## Run one adapter

```bash
osint run maigret username example_handle -o ~/OSINT-Cases/example/maigret
osint run exiftool image photograph.jpg -o ~/OSINT-Cases/example/metadata
```

Nmap adapters use a restrained top-100-port service scan, but should only be used against infrastructure you own or are explicitly authorized to assess:

```bash
osint run nmap domain example.org -o ~/Authorized-Assessments/example
```

## Dynamic batch processing

Edit:

```text
~/.config/osint-forge/targets.txt
```

Example:

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

Run every installed plugin that advertises batch support for those target types:

```bash
osint batch --name initial-sweep
```

Restrict the participating plugins:

```bash
osint batch --plugins maigret sherlock --name usernames-only
```

The batch engine does not contain a list of tools. It discovers compatible installed plugins from their manifests. Installing a new batch-capable plugin automatically makes it available to the batch engine.

## Adding a plugin

Copy the example:

```bash
cp -a docs/plugin-template plugins/new-tool
```

Then edit `manifest.json` and the four lifecycle scripts. No change to `osint_forge.py` is needed.

Validate locally without installing the framework:

```bash
export OSINT_FORGE_ROOT="$PWD"
export OSINT_FORGE_STATE="$PWD/.test-state"
./bin/osint forge list
./bin/osint forge install new-tool --dry-run
```

See `docs/PLUGIN-API.md` for the plugin contract.
