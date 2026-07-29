# Case Management

Cases are private, versioned, resumable workspaces that document authorization,
preserve raw execution provenance, normalize tool output, and retain analyst
review separately from evidence.

## Create and populate

```bash
osint case create example-case \
  --purpose "Investigate authorized brand impersonation" \
  --authorization "Written authorization from Example Organization"

osint case add example-case username example_handle
osint case add example-case email analyst@example.com
osint case add example-case domain example.com
osint case add example-case ip 192.0.2.10
osint case add example-case image ./photo.jpg
osint case add example-case file ./evidence.bin
```

Targets are validated, normalized, assigned stable IDs, and deduplicated.

## Preview, run, and resume

```bash
osint case run example-case --plugins maigret sherlock --dry-run
osint case run example-case --plugins maigret sherlock --jobs 2
osint case status example-case
osint case status example-case --json
```

Normal runs skip successful jobs only when their plugin contract version still
matches. Failed, missing, previewed, interrupted, or version-obsolete jobs
remain eligible. Use `--rerun` to execute current successful jobs again.

## Findings and reports

```bash
osint case findings example-case
osint case annotate example-case FINDING_ID --confidence high
osint case annotate example-case FINDING_ID --note "Corroborated manually."
osint case report example-case
osint case report example-case --format all
osint case report example-case --format all --shareable
```

The JSON master report and its Markdown, HTML, and CSV views are deterministic.
Every finding links to its exact preserved source. Failed and previewed jobs,
normalization errors, and orphaned reviews remain explicit.

Reviews live in `findings/reviews.json`. They never modify raw output. Findings
begin as `unverified`; available confidence values are `unverified`, `low`,
`medium`, and `high`.

## Privacy and integrity

Case directories use mode `0700`; case files use `0600`. Core validates case
IDs, metadata, targets, job state, plugin versions, status provenance, path
containment, report destinations, and symbolic links. A completed job whose
status disagrees with case state is not normalized.

Shareable reports remove targets, commands, raw/source paths, finding values
and attributes, notes, error detail, and stable case/run/job identifiers.
Always inspect an export before distribution.

The canonical repository guides are
[Case Management](https://github.com/LizardPope1101/osint-forge/blob/main/docs/CASE-MANAGEMENT.md)
and
[Normalized Reporting](https://github.com/LizardPope1101/osint-forge/blob/main/docs/REPORTING.md).
