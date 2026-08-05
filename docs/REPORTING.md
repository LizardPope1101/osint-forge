# Normalized Reporting

Normalized findings are the evidence input for the emerging entity model; they
are not automatically identity-resolved entities. See
[Entity Model](ENTITY-MODEL.md) for the seed contract and future correlation
boundary.

The stable reporting destination is defined in the
[v1.0 Product Contract](V1-PRODUCT-CONTRACT.md): preserved evidence, a complete
internal intelligence graph, and a deterministic final profile are separate
views.

Version 0.8 extends reporting from normalized tool output to evidence-backed
intelligence. Reports preserve provider observations, relationships,
lower-confidence leads, contradictions, source-independence analysis,
correlation rationale, verification status, temporal status, and scoped
confidence. No automated score replaces raw evidence or analyst judgment.

Identity confidence and currentness are independent. Provider temporal
assessments are preserved and conflicting assessments become explicit
contradictions; Forge does not infer currentness from recency alone. A historically
well-supported address or phone number must not appear as current merely
because its identity relationship is strong or it is the newest available
record.

The future v1.0 final profile includes only values meeting the selected
identity and currentness policy. Historical, conflicting, unresolved, rejected, and
lower-confidence observations remain explicitly available in the internal
report. The report also records why collection stopped and never equates an
exhausted queue with universal completeness.

OSINT Forge converts heterogeneous tool output into a common finding contract
without replacing raw evidence. Report schema 3 adds the provider intelligence
graph to the schema-2 candidate observations emitted by plugin schema 2. JSON is the
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
CSV contains finding and relationship rows; JSON also contains outcomes, errors,
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

Provider observations are imported with `osint case observe` and remain linked
to their preserved JSON evidence. The intelligence view and normalized reports
deduplicate canonical facts without dropping provider history. Repeated
mirrors or syndicated results remain dependent corroboration. Every automated
relationship and assessment exposes its evidence, contradictions, method,
timestamp, rationale, and source-independence assumptions.

Confidence scopes are `seed_fidelity`, `observation`, `relationship`,
`identity`, and `currentness`. Verification status is one of `verified`,
`contradicted`, `inconclusive`, `tool_unavailable`, `tool_failed`,
`not_applicable`, and `not_attempted`. Temporal status is one of
`current_high_confidence`, `current_probable`, `historical_high_confidence`,
`conflicting`, `unresolved`, and `rejected`. Tool status remains separate from
confidence. When no verifier exists, reports retain and score provider evidence
while plainly identifying the tool-unavailable limitation. Nontrivial
verification states preserve sensor identity, version, method, and evidence;
they cannot be supplied as unsupported status labels.

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
Provider values, relationship endpoints, observation identifiers, source
identifiers, correlation rationale, and contradiction detail are likewise
removed from structure-only shareable views.

Plugin names, categories, finding kinds/titles, outcome states, exit codes,
timestamps, and confidence remain. Redaction cannot understand every
contextual inference, so inspect each artifact before distribution.

## Failure behavior

Failed and previewed adapters remain explicit outcomes but are not normalized.
If a completed job has missing, malformed, oversized, or unsafe structured
output, available reports are written with a normalization error and the
command exits nonzero. Failed normalization is never silently treated as an
empty successful result.
