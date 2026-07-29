# Development and CI

OSINT Forge treats tests, documentation, permissions, packaging, and clean
installation as release requirements.

## Local checks

```bash
./scripts/dev-check.sh
```

The v0.4 development line currently runs 69 deterministic unit, integration,
contract, lifecycle, case, normalizer, provenance, redaction, and report tests.
The development check compiles core and plugin normalizers, validates contracts,
checks shell syntax and executable modes, and runs ShellCheck when installed.

## GitHub Actions

Every pull request runs seven jobs:

- Python 3.10, 3.11, 3.12, and 3.13 plus plugin contracts;
- shell quality and ShellCheck;
- clean install, upgrade, integration, lifecycle, and uninstall on Debian
  stable; and
- the same clean workflow on Ubuntu 24.04.

## Reporting expectations

Reporting changes must verify deterministic regeneration, raw-source
traceability, consistent JSON/Markdown/HTML/CSV views, explicit failed and
previewed outcomes, annotation persistence, conservative redaction, owner-only
permissions, malformed output, provenance disagreement, and path/symlink
rejection.

Use only synthetic data. Never commit real targets, credentials, cookies,
tokens, case files, or investigation results.

Required checks must pass before merge. Live supported-environment validation
is an additional release gate, not a substitute for CI. See [[Release Process]].
