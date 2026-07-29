# Changelog

All notable changes to OSINT Forge will be documented here.

The project follows [Semantic Versioning](https://semver.org/). Until the first
stable release, minor versions may include breaking changes.

## Unreleased

### Fixed

- Add pipx's per-user binary directory to plugin lifecycle environments so
  doctor, update, and removal checks agree with installed-plugin detection.
- Configure pipx's user path during bootstrap for future login shells.
- Flush lifecycle headings before child-process output when logs are piped.

## 0.3.0 - 2026-07-28

### Added

- Versioned case workspaces with documented purpose and authorization scope
- `osint case create`, `add`, `run`, `status`, and `report` commands
- Resumable execution that skips successful jobs and retries failed or missing
  jobs
- Append-only case activity logs and provenance-linked Markdown summaries
- Migration handling for legacy case metadata and rejection of unknown future
  schemas

### Security

- Case metadata, targets, activity logs, reports, raw output, notes, findings,
  and run directories use owner-only permissions
- Case IDs, symbolic-link paths, and report destinations are validated to
  prevent directory traversal or case-data escape
- Custom reports cannot overwrite case metadata, append-only activity logs,
  raw-run records, or existing files without an explicit safe override
- Batch output roots are restricted to owner-only permissions

### Fixed

- Development checks run cleanly from GitHub source archives that do not
  contain Git metadata

## 0.2.0 - 2026-07-28

### Added

- Automated GitHub Actions checks for Python, shell, plugin contracts, and
  clean Debian and Ubuntu lifecycle tests
- Unit and integration tests for discovery, target validation, batch parsing,
  safe slugs, adapter argument boundaries, lifecycle behavior, installation,
  private output permissions, and dry-run behavior
- `osint forge validate` with text and JSON output
- `osint forge version` and global `osint --version`
- Issue forms, pull-request checklist, CODEOWNERS, and Dependabot configuration

### Fixed

- Reject lifecycle scripts that escape their plugin directory.
- Validate plugin identifiers, versions, tags, and complete batch adapter coverage.
- Refuse to load malformed plugin contracts during normal catalog operations.
- Record adapter launch failures instead of crashing without a status report.
- Return clean lifecycle errors when a script cannot be started.
- Prevent simultaneous batch runs from colliding on the same output directory.
- Reject unknown batch plugin filters and conflicting catalog status filters.
- Make dry-run lifecycle previews work before optional dependencies are installed.
- Make plugin doctor checks fail when an installed command's self-check fails.
- Discover and execute pipx-installed tools from the standard per-user binary directory.
- Replace framework files through a staged upgrade so obsolete files cannot survive updates.
- Validate framework installation paths and preserve configuration during tested uninstall cycles.
- Add consistent SPDX ownership and license identifiers to every lifecycle script.
- Create framework state, copied target lists, logs, and result summaries with
  owner-only permissions.

### Changed

- Expand CI coverage across Python 3.10 through 3.13 and run integration tests
  inside clean Debian and Ubuntu containers.
- Pin GitHub Actions to immutable commit SHAs while retaining Dependabot updates.

## 0.1.0 - 2026-07-28

### Added

- Modular manifest-based plugin catalog
- Plugin lifecycle management
- Single-target adapters and parallel batch workflows
- Initial ExifTool, GHunt, Maigret, Nmap, Recon-ng, Sherlock, and SpiderFoot
  plugins
- Fresh Debian/Ubuntu bootstrap
- GPL-3.0-or-later licensing, contribution guide, security policy, and wiki
