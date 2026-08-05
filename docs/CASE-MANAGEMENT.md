# Case Management

OSINT Forge cases provide a durable boundary around authorized investigation
work. A case records why the work exists, its authorization scope, targets,
execution provenance, raw tool output, and resumable job state.

Case metadata is not a substitute for permission. Only investigate targets
that you are legally and organizationally authorized to examine.

## Workflow

Create a case:

```bash
osint case create example-case \
  --purpose "Investigate authorized brand impersonation" \
  --authorization "Written authorization from Example Organization"
```

Add validated targets:

```bash
osint case add example-case username example_handle
osint case add example-case email analyst@example.com
osint case add example-case domain example.com
osint case add example-case ip 192.0.2.10
osint case add example-case name "Example Person"
osint case add example-case phone "+1 (555) 555-0100"
osint case add example-case address "1 Example Way, Example City, NY"
osint case add example-case image ./photograph.jpg
```

Preview compatible commands without executing tools:

```bash
osint case run example-case --dry-run
```

Resolve the conservative built-in public-identity workflow without starting
any plugin or making any network request:

```bash
osint case plan example-case --workflow public-identity
osint case plan example-case --workflow public-identity --json
osint case plan example-case --workflow public-identity -o ./plan.json
```

The plan treats every supplied seed as a separate entity. Co-reference is not
assumed. It records why each plugin/entity pair was selected, skipped, or
rejected; each stage's purpose and expected information gain; the installed
plugin version; concurrency and timeout bounds; and any seed type for which no
installed workflow plugin provides coverage. Named profiles live in
`workflows/`; an explicit JSON file can be supplied instead. Workflow files
reject unknown fields, unsupported future schemas, duplicate values, missing
dependencies, dependency cycles, and symbolic links.

Run every compatible installed batch plugin, or select specific plugins:

```bash
osint case run example-case
osint case run example-case --plugins maigret sherlock --jobs 2
osint case run example-case --workflow public-identity --jobs 4
```

`--workflow` and `--plugins` are mutually exclusive. A workflow run executes
only jobs selected by the same deterministic resolver used by `case plan`,
caps requested parallelism to the workflow maximum, enforces declared adapter
timeouts, records the complete resolved plan in `run.json`, and uses the
existing stable job identifiers for retry and resume behavior. Workflows are
not shell runners: plugin commands still come only from validated manifest
adapter arrays. Newly extracted candidates are never scheduled recursively.

Execute a reviewed provider adapter or import externally obtained provider
results, then inspect the deterministic intelligence graph:

```bash
osint case search example-case ./provider-adapter.json
osint case observe example-case example-search ./provider-results.json
osint case intelligence example-case
osint case intelligence example-case --json
```

`search` executes a reviewed, versioned argv adapter only for compatible case
seeds and preserves its status and logs. `observe` strictly validates
versioned JSON and preserves it inside the case without executing the named
provider. `intelligence` derives
observations, canonical entities, evidence-backed relationships,
contradictions, verification status, temporal status, and scoped confidence
from available evidence. Provider search is the primary discovery layer;
plugins remain conditional verification and enrichment sensors. See
[Correlation and Confidence](CORRELATION.md).

Inspect progress and create a local summary:

```bash
osint case status example-case
osint case status example-case --json
osint case entities example-case
osint case entities example-case --json
osint case report example-case
osint case report example-case --format all
osint case report example-case --format all --shareable
```

The default `report.md` can be regenerated in place. `--format` accepts
`markdown`, `json`, `html`, `csv`, or `all`. A custom `--output` is available
for one format, must remain inside the case directory, and will not replace an
existing file unless `--force` is supplied. Reserved metadata, review, and
raw-run paths cannot be used as report destinations.

## Integrity and portability

Create a snapshot manifest and verify it later:

```bash
osint case integrity create example-case
osint case integrity verify example-case
osint case integrity verify example-case --json
```

The manifest hashes every regular material case artifact with SHA-256 and
records its relative path and size. Verification fails for missing, modified,
or unexpected content. Because a manifest is a snapshot, later authorized case
activity requires creating a new manifest.

Create and independently inspect deterministic owner-only bundles:

```bash
osint case export example-case --mode full -o ./example-case.osint-case
osint case export example-case --mode redacted -o ./example-share.osint-case
osint case inspect ./example-case.osint-case
osint case import ./example-case.osint-case
```

Full bundles preserve all regular case artifacts and an independent integrity
manifest. Import is fail-closed, refuses overwrites and case-ID renaming, and
extracts only after validating every member name, type, size, and digest.
The bundle also materializes a versioned entity snapshot whose available
source artifacts are bound by relative path and SHA-256 digest.
Redacted bundles contain derived summaries only; raw evidence, targets,
commands, paths, authorization details, and analyst notes are excluded. They
cannot be imported as live cases. Human review remains required before sharing.
See [Evidence Integrity and Portability](EVIDENCE-INTEGRITY.md).

## Resume behavior

Each target/plugin pair has a stable job identifier. A normal case run:

- skips jobs whose latest real execution completed successfully;
- retries failed jobs;
- runs new jobs created by newly added targets or plugins; and
- preserves every run in a separate timestamped directory.

Use `--rerun` to run successful jobs again. Dry runs are recorded as
`previewed`, never `completed`, so a preview cannot suppress real execution.
If a run is interrupted, completed job state is saved and missing work remains
eligible for the next run.

## Directory schema

Cases default to `~/OSINT-Cases/<case-id>/`. Set `OSINT_FORGE_CASES` to use a
different root.

```text
<case-id>/
├── case.json
├── activity.jsonl
├── report.md
├── report.json
├── report.html
├── findings.csv
├── notes/
├── findings/
│   └── reviews.json
└── runs/
    └── <timestamp>/
        ├── run.json
        └── raw/
            └── <target-type>/
                └── <target-slug>/
                    └── <plugin>/
                        ├── status.json
                        ├── stdout.log
                        └── stderr.log
```

`case.json` is the versioned source of case metadata and current job state.
Schema version 1 contains:

- case ID, purpose, and authorization scope;
- creation and update timestamps;
- validated targets with stable target IDs; and
- current job status with plugin version, exit status, last run, and raw-output
  location.

`activity.jsonl` is append-only. Every line is an independent JSON event with a
UTC timestamp. Raw execution records preserve exact argument arrays rather
than reconstructed shell commands.

`notes/` is reserved for analyst-authored material. `findings/` is reserved for
derived and reviewed findings. Neither is mixed with raw tool output.

## Entity projection

The versioned, read-only entity projection combines operator-supplied seeds
with deterministic candidate observations from successful schema-2
normalizers:

```bash
osint case entities example-case --json
```

Every existing case target becomes a deterministic canonical entity with its
original value, comparison value, stable entity ID, seed origin, and source
target record. Email addresses and domains are compared case-insensitively;
phone formatting is normalized; and repeated whitespace and case are
normalized for names and addresses.

Seed confidence describes input fidelity only: the operator deliberately
supplied the value. It does not assert that the seed belongs to a particular
person, that an address is current, or that any relationship has been proven.
Extracted plugin candidates remain unverified observations with source target,
plugin, run, and raw-file provenance. Canonically equivalent candidates and
seeds merge without dropping any source. The compatibility entity projection's
relationship collection remains empty. The separate provider intelligence
graph can add relationships and confidence assessments only when their
evidence and rationale remain inspectable. Mirrors and syndicated copies
retain their history but do not count as independent corroboration.

This projection is derived rather than independently persisted. Seed state
comes from `case.json`; plugin candidates are rebuilt from preserved output.
Provider observations are rebuilt in the separate intelligence graph. Neither
view performs recursive discovery or opaque automated identity attribution.
See [Entity Model](ENTITY-MODEL.md) for the complete contract and its
confidence boundary.

By v1.0, a case is intended to carry the complete evidence graph for a bounded
investigation: supplied seeds, extracted candidates, relationships,
contradictions, confidence assessments, queue decisions, analyst actions, and
the rationale for each pursued lead. Preserved evidence, the internal
intelligence graph, and the confidence- and currentness-filtered final profile
remain distinct layers. These capabilities will arrive through the versioned
stages in the [Roadmap to v1.0](ROADMAP.md) and must satisfy the
[v1.0 Product Contract](V1-PRODUCT-CONTRACT.md). Version 0.8 keeps the
projection read-only and workflows continue to operate only on
operator-supplied case targets; discovered entities are not queued.

## Privacy and integrity

Case directories are mode `0700`; case-owned files are mode `0600`. Case IDs
cannot contain path separators, case directories cannot be symbolic links,
and generated reports cannot escape their case directory.

Integrity manifests and bundles provide tamper evidence and reproducible
transport. They do not certify who collected an artifact, establish legal
chain of custody, prove source truth, or replace lawful forensic procedure.

The report command normalizes supported tool output into a common, versioned
finding contract. It preserves every outcome—including failures and dry-run
previews—and links each finding to its exact raw source. Normalization failures
remain visible and cause a nonzero exit after available reports are written.

List and review findings with:

```bash
osint case findings example-case
osint case annotate example-case FINDING_ID \
  --confidence high \
  --note "Confirmed against an operator-owned profile."
```

Confidence values are `unverified`, `low`, `medium`, and `high`. Reviews are
stored separately in `findings/reviews.json` and never modify raw output.

Shareable reports use conservative structure-only redaction. Targets, commands,
paths, values, notes, errors, and stable case/run/job identifiers are removed.
Human review before distribution is still required. See
[Normalized Reporting](REPORTING.md).

## Schema compatibility

OSINT Forge records a numeric case schema. Legacy unversioned case metadata is
migrated to schema 1 with an appended migration event. A case created by a
newer unsupported schema is rejected instead of being silently rewritten.
