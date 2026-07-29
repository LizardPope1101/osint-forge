# Troubleshooting

Start with:

```bash
osint --version
osint forge validate
osint forge doctor
```

## Reporting problems

List current findings and regenerate one machine-readable report:

```bash
osint case findings CASE --json
osint case report CASE --format json
```

A nonzero report exit may still leave a report file. Inspect
`normalization_errors`; OSINT Forge preserves available outcomes instead of
hiding the failure.

Common causes include:

- required structured output was not produced;
- upstream output changed or is malformed;
- a source exceeds the normalizer size limit;
- a raw, review, or report path uses a symbolic link or escapes its boundary;
- `status.json` disagrees with case state; or
- a plugin contract lacks a valid normalizer.

Failed and previewed jobs are intentionally not normalized. If a plugin version
changed, a previously successful job becomes eligible for rerun so its output
matches the current contract.

## Annotation problems

Run `osint case findings CASE` again and use an exact current finding ID. IDs
are stable across equivalent reruns, but changed normalized content produces a
new ID. Reviews for removed findings remain visible as orphaned.

## Permission problems

Case directories should be `0700` and case files `0600`. Parent directories,
copied exports, backups, archives, and upstream files outside Forge-managed
output remain the operator's responsibility.

Use synthetic data in bug reports. Report vulnerabilities privately through
the canonical
[security policy](https://github.com/LizardPope1101/osint-forge/blob/main/.github/SECURITY.md).
