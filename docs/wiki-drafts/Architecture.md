# Architecture

OSINT Forge is a small Python orchestration layer around independently
installed tools. Core logic stays generic; tool-specific execution and
normalization live in reviewed plugins.

## Major components

- `bin/osint` — launcher
- `forge/osint_forge.py` — CLI, catalog, validation, execution, batch, and cases
- `forge/reporting.py` — normalized report contract, provenance, redaction, and renderers
- `plugins/<tool>/` — manifest, lifecycle scripts, adapters, and normalizer
- `config/` — shipped configuration templates
- `docs/` — canonical repository documentation and plugin template
- `tests/` — deterministic unit, integration, and report fixtures
- `scripts/` — install, uninstall, and development checks

## State and data

- Framework state: `~/.local/state/osint-forge/`
- User configuration: `~/.config/osint-forge/`
- Default batch output: `~/OSINT-Cases/Batch-Runs/`
- Default case root: `~/OSINT-Cases/<case-id>/`
- Installed framework: `/usr/local/share/osint-forge/`
- Launcher: `/usr/local/bin/osint`

Framework-created state and result artifacts use owner-only permissions.
Uninstall preserves configuration, third-party tools, and case data.

## Plugin model

Manifests declare metadata, target support, lifecycle entry points, root needs,
safe argument-array adapters, and—when batch-capable—a plugin-owned normalizer.
The loader rejects malformed contracts, ID mismatches, unsafe paths, missing
normalizers, and incomplete batch coverage.

## Execution and reporting model

Single and batch execution validate targets and invoke argument arrays without
shell interpolation. Case mode adds authorization metadata, append-only
activity, resumable version-aware jobs, raw records, and protected reports.

Completed structured output is parsed by the owning plugin normalizer. Core
validates the normalizer response, verifies status provenance, assigns stable
finding IDs, applies analyst reviews, and renders deterministic JSON, Markdown,
HTML, and CSV. Raw evidence is never modified.

## Trust boundaries

OSINT Forge controls command construction, paths, permissions, contracts,
provenance, annotations, and redaction structure. Upstream tools control their
queries, authentication, output quality, dependencies, and service
interactions. Automated output is an unverified lead, not established fact.

See [[Case Management]] and [[Normalized Reporting]].
