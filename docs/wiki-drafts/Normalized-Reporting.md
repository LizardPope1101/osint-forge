# Normalized Reporting

OSINT Forge v0.4 converts heterogeneous tool output into a common finding
contract without modifying raw evidence. JSON is the machine-readable master;
Markdown, HTML, and CSV are deterministic views.

## Generate reports

```bash
osint case report example-case
osint case report example-case --format json
osint case report example-case --format all
```

| Format | Default file |
|---|---|
| Markdown | `report.md` |
| JSON | `report.json` |
| HTML | `report.html` |
| CSV | `findings.csv` |

Artifacts use mode `0600`. Markdown and HTML link to preserved evidence. CSV
contains one row per finding; JSON also contains outcomes, errors, attributes,
orphaned reviews, redaction metadata, and integrity checks.

## Finding contract

Each finding includes:

- a stable content-derived ID;
- kind, category, title, value, and tool-specific attributes;
- confidence and analyst note;
- target identity; and
- plugin/framework versions, run, outcome, exit code, command, timestamps,
  exact source file, and raw-output directory.

IDs survive equivalent reruns while the plugin, target, source filename, and
normalized content remain unchanged. The newest run stays in provenance.

## Analyst review

```bash
osint case findings example-case
osint case findings example-case --json
osint case annotate example-case FINDING_ID --confidence medium
osint case annotate example-case FINDING_ID --note "Needs corroboration."
osint case annotate example-case FINDING_ID --clear-note
```

Reviews are separate from raw output. A review whose finding disappears is
retained and reported as orphaned instead of silently deleted.

## Shareable redaction

```bash
osint case report example-case --format all --shareable
```

The `structure-only-v1` policy removes purpose, authorization scope, original
case ID, targets, original job/run IDs, commands, raw/source paths, finding
values and attributes, notes, and error detail. Structural fields such as
plugin, category, finding kind/title, outcome, exit code, timestamps, and
confidence remain. Context can still disclose information; review every export.

## Failure behavior

Failed and previewed jobs remain explicit but are not normalized. Missing,
malformed, oversized, inconsistent, or unsafe completed output becomes a
normalization error. Available reports are written and the command exits
nonzero; failure is never silently converted into an empty success.
