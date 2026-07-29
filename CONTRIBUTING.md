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
- Use only synthetic, non-sensitive fixtures in tests, examples, issues, and
  pull requests.
- Preserve raw evidence, provenance, owner-only permissions, resumability, and
  schema migration behavior when changing case or reporting features.
- Batch plugins must include a deterministic, standard-library-only normalizer
  and synthetic fixtures covering positive, negative, malformed, and missing
  output. Normalizers cannot use the network or modify raw evidence.
- Reporting changes must verify traceability, explicit failed and previewed
  outcomes, cross-format agreement, redaction, and deterministic regeneration.
- Include or update documentation when behavior changes.
- Stage unreleased wiki revisions in `docs/wiki-drafts/`; publish them only
  after the applicable live-validation and sequential release gates pass.
- Test lifecycle operations with `--dry-run` before exercising them on a host.

## Validation

Before opening a pull request, run:

```bash
./scripts/dev-check.sh
```

GitHub Actions repeats these checks and also runs ShellCheck and a Debian
stable and Ubuntu 24.04 clean-install test. Python checks run across versions
3.10 through 3.13.

Changes should include focused tests for affected behavior. Before requesting
review, confirm:

- Unit, integration, CLI, and plugin-contract tests pass
- Shell syntax and ShellCheck pass for changed scripts
- New files have appropriate executable modes and SPDX identifiers
- Documentation links and command examples remain valid
- Installation, upgrade, and uninstall behavior remain safe when affected
- No credentials, targets, case artifacts, or investigation results are
  present in the diff

Pull requests should explain what changed, why it changed, user impact, and the
validation performed. Keep unrelated changes in separate pull requests.

## Adding a plugin

Copy `docs/plugin-template`, then follow `docs/PLUGIN-API.md`. A plugin should
declare its upstream project, license, supported targets, lifecycle scripts,
root requirements, and adapter commands.

Every plugin candidate must also receive an explicit maintenance, licensing,
installation, safety, and authorization review. It must pass install, update,
remove, doctor, contract, dry-run, and disposable-environment tests before
entering the catalog. Record an accept, defer, or reject decision rather than
silently weakening these requirements.

The upstream tool remains an independent work under its own license. Do not
copy upstream source code into OSINT Forge unless its license is compatible and
the required notices are included.
