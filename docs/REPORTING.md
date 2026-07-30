# Normalized Reporting

Normalized findings are the evidence input for the emerging entity model; they
are not automatically identity-resolved entities. See
[Entity Model](ENTITY-MODEL.md) for the seed contract and future correlation
boundary.

The [Roadmap to v1.0](ROADMAP.md) extends reporting from normalized tool output
to evidence-backed intelligence. Future reports will preserve lower-confidence
leads and contradictions internally while allowing a final intelligence view
to apply an explicit confidence threshold. No automated score will replace raw
evidence, source independence analysis, correlation rationale, or analyst
judgment.

OSINT Forge converts heterogeneous tool output into a common finding contract
without replacing raw evidence. Report schema 2 also carries deterministic
candidate observations emitted under plugin schema 2. JSON is the
machine-readable master;
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
attributes, candidate observations, orphaned reviews, and integrity metadata.

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

Every candidate includes a stable content-derived ID, entity type, value,
`extracted_observation` classification, originating target, plugin and plugin
version, run ID, exact source file, and raw-output directory. Its type must be
declared in the plugin's `entities.emitted` contract. Candidate values are not
relationships, identity conclusions, or automatically queued work.

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
Candidate values, target identifiers, run identifiers, and source paths are
also removed.

Plugin names, categories, finding kinds/titles, outcome states, exit codes,
timestamps, and confidence remain. Redaction cannot understand every
contextual inference, so inspect each artifact before distribution.

## Failure behavior

Failed and previewed adapters remain explicit outcomes but are not normalized.
If a completed job has missing, malformed, oversized, or unsafe structured
output, available reports are written with a normalization error and the
command exits nonzero. Failed normalization is never silently treated as an
empty successful result.
