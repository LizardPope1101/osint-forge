# Normalized Reporting

OSINT Forge v0.4 converts heterogeneous tool output into a common finding
contract without replacing raw evidence. JSON is the machine-readable master;
Markdown, HTML, and CSV are deterministic views of the same report.

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

All artifacts use mode `0600`. Markdown and HTML link to preserved evidence.
CSV contains one row per finding; JSON also contains outcomes, errors,
attributes, orphaned reviews, and integrity metadata.

## Contract and provenance

The versioned JSON root includes case metadata, summaries, targets, every
completed/failed/previewed outcome, normalized findings, normalization errors,
orphaned reviews, and traceability checks.

Every finding includes a stable content-derived ID; kind, category, title,
value, and tool-specific attributes; confidence and analyst note; target
identity; and plugin/framework versions, run ID, outcome, exit code, command,
timestamps, exact source file, and raw-output directory.

IDs remain stable across reruns while the plugin, target, source filename, and
normalized content are unchanged. The latest run remains recorded separately
in provenance. New findings start at `unverified`; tool output is never
accepted as fact automatically.

## Analyst review

```bash
osint case findings example-case
osint case findings example-case --json
osint case annotate example-case FINDING_ID --confidence medium
osint case annotate example-case FINDING_ID --note "Needs corroboration."
osint case annotate example-case FINDING_ID --clear-note
```

Reviews live in `findings/reviews.json`, separate from raw output. If source
changes remove a finding, its review is retained and reported as orphaned.

## Shareable redaction

```bash
osint case report example-case --format all --shareable
```

This writes `shareable-report.md`, `shareable-report.json`,
`shareable-report.html`, and `shareable-findings.csv`. The
`structure-only-v1` policy removes case purpose, authorization scope, original
case ID, target values and IDs, original job/run IDs, commands, raw/source
paths, finding values and attributes, analyst notes, and error detail.

Plugin names, categories, finding kinds/titles, outcome states, exit codes,
timestamps, and confidence remain. Redaction cannot understand every
contextual inference, so inspect each artifact before distribution.

## Failure behavior

Failed and previewed adapters remain explicit outcomes but are not normalized.
If a completed job has missing, malformed, oversized, or unsafe structured
output, available reports are written with a normalization error and the
command exits nonzero. Failed normalization is never silently treated as an
empty successful result.
