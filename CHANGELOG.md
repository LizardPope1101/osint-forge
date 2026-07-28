# Changelog

All notable changes to OSINT Forge will be documented here.

The project follows [Semantic Versioning](https://semver.org/). Until the first
stable release, minor versions may include breaking changes.

## Unreleased

### Added

- Automated GitHub Actions checks for Python, shell, plugin contracts, and a
  Debian smoke test
- Unit tests for discovery, target validation, batch parsing, safe slugs,
  adapter argument boundaries, and dry-run behavior
- `osint forge validate` with text and JSON output
- `osint forge version` and global `osint --version`
- Issue forms, pull-request checklist, CODEOWNERS, and Dependabot configuration

## 0.1.0 - 2026-07-28

### Added

- Modular manifest-based plugin catalog
- Plugin lifecycle management
- Single-target adapters and parallel batch workflows
- Initial ExifTool, GHunt, Maigret, Nmap, Recon-ng, Sherlock, and SpiderFoot
  plugins
- Fresh Debian/Ubuntu bootstrap
- GPL-3.0-or-later licensing, contribution guide, security policy, and wiki
