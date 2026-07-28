# Plugin authoring

Create `plugins/<id>/manifest.json`. The directory name and manifest `id` must
match.

```json
{
  "id": "example",
  "name": "Example",
  "targets": ["usernames"],
  "lifecycle": {
    "detect": {"command": "example"},
    "install": {"argv": ["pipx", "install", "example"], "root": false},
    "update": {"argv": ["pipx", "upgrade", "example"], "root": false},
    "remove": {"argv": ["pipx", "uninstall", "example"], "root": false}
  },
  "adapter": {
    "target_type": "usernames",
    "argv": ["example", "--output", "{output_dir}", "{target}"]
  }
}
```

The adapter is invoked once for every matching target. Supported placeholders
are `{target}` and `{output_dir}`. Keep every command and argument as a distinct
JSON array element. OSINT Forge deliberately does not invoke a shell.

