# Contributing to OSINT Forge

Thank you for improving OSINT Forge.

## Contribution terms

By submitting a contribution, you certify that you have the right to submit
it and agree that it may be distributed under the GNU General Public License
version 3 or any later version (`GPL-3.0-or-later`).

Do not submit code, datasets, credentials, personal information, or other
material that you do not have the right to distribute.

## Development expectations

- Keep the framework modular; tool-specific behavior belongs in a plugin.
- Keep adapter commands as argument arrays. Do not interpolate targets into
  shell command strings.
- Preserve restrained defaults for network and infrastructure tools.
- Never commit API keys, authentication cookies, case data, or investigation
  results.
- Include or update documentation when behavior changes.
- Test lifecycle operations with `--dry-run` before exercising them on a host.

## Validation

Before opening a pull request, run:

```bash
./scripts/dev-check.sh
```

GitHub Actions repeats these checks and also runs ShellCheck and a Debian
container integration test across the supported Python versions.

## Adding a plugin

Copy `docs/plugin-template`, then follow `docs/PLUGIN-API.md`. A plugin should
declare its upstream project, license, supported targets, lifecycle scripts,
root requirements, and adapter commands.

The upstream tool remains an independent work under its own license. Do not
copy upstream source code into OSINT Forge unless its license is compatible and
the required notices are included.
