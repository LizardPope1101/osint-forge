# Plugin API

## Directory contract

```text
plugins/example/
├── manifest.json
├── install.sh
├── update.sh
├── remove.sh
└── doctor.sh
```

The plugin directory name and `manifest.json` `id` must match.

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

- `email`
- `username`
- `domain`
- `ip`
- `image`
- `file`

## Adapter placeholders

- `{target}`: the validated target
- `{output_dir}`: the tool-specific output directory
- `{plugin_dir}`: the plugin directory

Adapters are argument arrays, not shell strings. This prevents shell interpolation of untrusted target values.

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

Every system-changing command should be wrapped with `run` so dry-run mode remains accurate.
