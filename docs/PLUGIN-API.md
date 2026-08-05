# Plugin API

Plugins are conditional verification and enrichment sensors in the v0.8
search-first architecture. Search-provider evidence is discovered or imported
through the strict, versioned adapter and result contracts described in
[Correlation and Confidence](CORRELATION.md). A provider name is not a plugin,
and `osint case observe` does not install, execute, or contact one. The
operator-selected `osint case search CASE ADAPTER` command executes an argv
adapter without treating it as a plugin.

## Directory contract

```text
plugins/example/
├── manifest.json
├── install.sh
├── update.sh
├── remove.sh
├── doctor.sh
└── normalize.py
```

The plugin directory name and `manifest.json` `id` must match. IDs use
lowercase letters, numbers, and single hyphens between components.

## Manifest

```json
{
  "schema": 2,
  "plugin_version": "1",
  "id": "example",
  "name": "Example Tool",
  "description": "One-line description.",
  "category": "usernames",
  "homepage": "https://example.org/",
  "upstream_license": "MIT",
  "upstream_license_url": "https://example.org/license",
  "tags": ["people", "batch"],
  "commands": ["example"],
  "supports": ["username"],
  "entities": {
    "accepted": ["username"],
    "emitted": []
  },
  "batch": true,
  "normalizer": "normalize.py",
  "lifecycle": {
    "install": "install.sh",
    "update": "update.sh",
    "remove": "remove.sh",
    "doctor": "doctor.sh"
  },
  "requires_root": {
    "install": false,
    "update": false,
    "remove": false,
    "doctor": false
  },
  "adapters": {
    "username": {
      "command": ["example", "--json", "results.json", "{target}"]
    }
  }
}
```

`upstream_license` should use an SPDX expression when one exists. Use a
documented `LicenseRef-...` identifier for a custom license and link directly
to the authoritative license text. These fields describe the independent
upstream tool; they do not change the OSINT Forge license.

## Supported target types

Core target types are:

- `address`
- `email`
- `username`
- `domain`
- `ip`
- `image`
- `file`
- `name`
- `phone`

A core target type is not necessarily supported by a current plugin. Plugins
receive only types listed in their own `supports` and `adapters` contracts.

## Entity-aware contract

Schema 2 retains `supports` for execution compatibility and adds `entities`.
`entities.accepted` must be a sorted, unique copy of `supports`.
`entities.emitted` is the sorted, unique set of entity types the normalizer may
emit as candidate observations. Empty emission is explicit and valid.

Schema 1 remains readable during the v0.5 transition but cannot emit candidate
entities. Unknown future schema versions fail validation.

## Adapter placeholders

- `{target}`: the validated target
- `{output_dir}`: the tool-specific output directory
- `{plugin_dir}`: the plugin directory

Adapters are argument arrays, not shell strings. This prevents shell interpolation of untrusted target values.
Every target listed in `supports` must have an adapter when `batch` is `true`.
Every batch plugin must declare a `normalizer`. Its path must be a regular file
inside the plugin directory and cannot be a symbolic link.
Lifecycle script paths must be relative files contained within the plugin
directory.

## Normalizer contract

Core invokes a normalizer with the current Python interpreter and one argument:
the absolute raw-output directory for a completed job. The working directory is
also that raw-output directory. A normalizer only reads preserved output and
emits one JSON object:

```json
{
  "schema": 2,
  "findings": [
    {
      "kind": "username_profile",
      "category": "usernames",
      "title": "Possible username profile on Example",
      "value": "https://social.example/example_handle",
      "attributes": {"status": "Claimed"},
      "source_file": "results.json"
    }
  ],
  "candidates": [
    {
      "type": "domain",
      "value": "profile.example",
      "source_file": "results.json"
    }
  ]
}
```

`kind`, `title`, and `source_file` are required non-empty strings. `value` is a
string or null. `attributes` is a JSON object. `source_file` is relative to raw
output, must exist, and cannot traverse or use symbolic links outside that
boundary. Core adds finding ID, target, plugin, command, timestamps, run,
outcome, confidence, notes, and raw-output provenance.

Normalizers must be deterministic, standard-library-only, network-free,
read-only, and consistently sorted. They should fail nonzero when required
structured output is missing or malformed. Changes require synthetic positive
and negative fixtures.

Candidate records are extracted observations, not relationships or identity
claims. `type` must appear in the plugin's `entities.emitted`; `value` must be
non-empty text; and `source_file` follows the same confinement rules as
findings. Core assigns deterministic candidate IDs and adds plugin, target,
run, raw-output, and source-file provenance. Candidate entities are never
executed recursively. Version 0.8 may correlate them with preserved provider
observations, but that does not schedule plugin work or convert tool output
into analyst-confirmed intelligence.

## Lifecycle environment

Lifecycle scripts receive:

- `OSINT_FORGE_PLUGIN_ID`
- `OSINT_FORGE_PLUGIN_DIR`
- `OSINT_FORGE_ROOT`
- `OSINT_FORGE_STATE`
- `OSINT_FORGE_DRY_RUN`
- `OSINT_FORGE_ASSUME_YES`

They should source:

```bash
source "${OSINT_FORGE_ROOT}/scripts/plugin-common.sh"
```

The helper provides:

- `run`
- `need`
- `say`
- `as_target_user`

Every system-changing command should be wrapped with `run` so dry-run mode
remains accurate. Use `need` for dependencies; in dry-run mode it reports a
requirement without failing the preview.
