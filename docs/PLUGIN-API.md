# Plugin API

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
  "schema": 1,
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

## Entity-aware contract trajectory

The current schema 1 `supports` field declares accepted case target types.
Under the committed [Roadmap to v1.0](ROADMAP.md), v0.5 will introduce a
versioned contract that also declares candidate entity types a plugin
normalizer can emit.

That future contract must:

- remain explicit and machine-validatable;
- preserve the raw source file and target provenance for every candidate;
- distinguish extracted observations from identity or relationship inferences;
- use deterministic, network-free normalizers;
- reject unknown future schema versions; and
- avoid silently treating arbitrary finding values as entities.

Until that schema is implemented and released, plugin authors must use only
the documented schema 1 fields below.

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
  "schema": 1,
  "findings": [
    {
      "kind": "username_profile",
      "category": "usernames",
      "title": "Possible username profile on Example",
      "value": "https://social.example/example_handle",
      "attributes": {"status": "Claimed"},
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
