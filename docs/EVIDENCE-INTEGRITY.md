# Evidence Integrity and Portability

OSINT Forge v0.7 adds versioned SHA-256 integrity manifests and deterministic
case bundles. The feature detects artifact changes and provides a safe way to
move a case; it does not claim forensic certification or legal chain of
custody.

## Integrity contract

`osint case integrity create CASE` writes `integrity.json` with schema version,
algorithm, case ID, framework version, and the sorted relative path, byte size,
and SHA-256 digest of every regular material case artifact. The manifest does
not hash itself.

`osint case integrity verify CASE` independently reports missing, modified,
and unexpected artifacts. A valid result means that the current regular files
match that snapshot. It does not prove an artifact is accurate, authentic, or
lawfully collected. Any legitimate subsequent case change invalidates the old
snapshot until the operator deliberately creates a new one.

Symbolic links, sockets, devices, and other non-regular artifacts are rejected.
Paths are always relative to the case root.

## Bundle contract

Bundles use a deterministic ZIP container with fixed member timestamps,
lexical ordering, owner-only file modes, and a versioned
`bundle-manifest.json`. Every payload member is size- and SHA-256-bound.
Repeated exports of unchanged content produce identical bytes.

Full-fidelity mode preserves all regular case artifacts plus the case integrity
manifest. It retains raw evidence, metadata, findings, entity inputs,
timestamps, reviews, workflow plans and decisions, and available framework,
plugin, schema, and workflow versions already present in those records.
It also materializes versioned `intelligence/entities.json` and
`intelligence/graph.json` snapshots. Entity and provider-observation
sources bind to the verified bundle path and SHA-256 digest whenever the source
artifact is available. In v0.8, full bundles also preserve imported provider
payloads, execution records, logs, and referenced evidence as ordinary case
artifacts. A generated normalized report contains the derived provider graph; that inference never
replaces its source evidence or becomes source truth.

Redacted mode is deliberately narrower. It contains only a redacted case
summary, structure-only entity projection, and redacted normalized report.
Raw evidence, target values, commands, local paths, authorization details, and
analyst notes are excluded. Redacted bundles are inspection-only because they
cannot reproduce a live case without the intentionally omitted evidence.

## Safe inspection and import

`osint case inspect BUNDLE` verifies a bundle without extracting or trusting
its metadata. Inspection rejects absolute paths, traversal, backslash paths,
empty components, duplicate members, symbolic links, directories, special
files, missing or extra members, size mismatches, digest mismatches, malformed
JSON, and unsupported schemas.

`osint case import BUNDLE` accepts only a fully verified full-fidelity bundle.
It refuses to overwrite an existing case or rename the case ID, writes through
owner-only directories and files, validates the imported `case.json` through
the normal case loader, and independently verifies the embedded case manifest.
On any failure it removes the incomplete destination.

## Trust boundary

SHA-256 answers whether bytes changed relative to a recorded manifest. It does
not identify the collector because v0.7 does not provide external-identity
digital signatures. Imported metadata remains evidence to inspect, not an
automatically trusted assertion. Source truth, authorization, collection
quality, attribution, currentness, and confidence remain separate analytical
questions for later versioned layers and human judgment.
