# Changelog

All notable changes to OSINT Forge will be documented here.

The project follows [Semantic Versioning](https://semver.org/). Until the first
stable release, minor versions may include breaking changes.

## Unreleased

### Added

- Versioned normalized finding and report contracts for all case-capable
  plugins.
- Deterministic JSON, Markdown, HTML, and CSV case reports linked to preserved
  raw evidence.
- Analyst confidence and note annotations through `osint case annotate`.
- Conservative `--shareable` report redaction.

### Changed

- Batch plugins now declare plugin-owned normalizers, and successful case jobs
  rerun when their plugin contract version changes.
- Reports retain completed, failed, and previewed outcomes and surface
  normalization errors instead of silently dropping them.

### Security

- Validate normalizer and report paths inside their plugin, raw-output, and
  case boundaries; reject symbolic-link traversal.
- Write reports and analyst reviews with owner-only permissions.

## 0.3.1 - 2026-07-29

### Security

- Reject symbolic-link case paths, output directories, activity logs, and
  private logs instead of following them.
- Validate persisted case metadata, target records, job records, and derived
  identifiers before using them.
- Escape Markdown control characters from case metadata and tool records when
  generating reports.
- Refuse to replace or uninstall unrecognized framework directories and
  launchers.

### Fixed

- Wait for active case workers to settle after interruption before finalizing
  provenance or cleaning temporary storage.
- Report unreadable, missing, and non-UTF-8 batch inputs cleanly, and avoid
  creating empty run artifacts when no installed plugin matches.
- Treat stale installation records as uninstalled when the underlying command
  is missing.
- Keep SpiderFoot update previews quiet before its virtual environment exists.
- Add pipx's per-user binary directory to plugin lifecycle environments so
  doctor, update, and removal checks agree with installed-plugin detection.
- Configure pipx's user path during bootstrap for future login shells.
- Flush lifecycle headings before child-process output when logs are piped.
- Enforce an owner-only umask for files and directories created by upstream
  adapter processes inside case output.
- Enforce owner-only permissions on every intermediate batch output directory.
- Use UTC batch run identifiers consistent with case and provenance timestamps.
- Protect Recon-ng API keys and workspace data with an owner-only launcher
  umask on both fresh installs and updates.
- Protect SpiderFoot configuration, credentials, and scan data with the same
  owner-only launcher policy on fresh installs and updates.
- Provision SpiderFoot's native compiler, Python, XML/XSLT, SSL/FFI, image,
  SWIG, and Rust build dependencies on supported Debian and Ubuntu systems.
- Use an isolated lxml 5.x compatibility overlay for SpiderFoot on Python 3.13
  and newer while preserving upstream requirements on older interpreters.
- Launch SpiderFoot from its application directory so relative templates and
  static assets resolve regardless of the operator's current directory.

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
