# Correlation and Confidence

OSINT Forge 0.8 adds versioned execution, ingestion, and correlation contracts
for search-provider evidence. An authorized operator may execute a reviewed
provider adapter for compatible case seeds or import an already normalized
result:

```bash
osint case search CASE ./provider-adapter.json
osint case observe CASE PROVIDER INPUT
osint case intelligence CASE
osint case intelligence CASE --json
```

`search` executes a schema-1 argv adapter once for each compatible
operator-supplied seed, preserves its execution record and logs, and imports
its normalized output. `observe` validates and copies input into the private case rather than
retaining a dependency on the supplied path. `intelligence` deterministically
rebuilds the provider intelligence graph from every accepted provider
observation. Case seeds remain available in the entity projection, and plugin
findings remain available in normalized reports. Neither command performs
network access beyond the explicitly selected adapter, or schedules discovered
entities for follow-up.

## Provider-adapter contract

A provider adapter is a reviewed JSON contract with `schema`, `id`, `name`,
`provider_version`, `accepts`, `command`, and `timeout_seconds`, plus an
optional `environment` allowlist. `command` is
an argument array, never shell text, and must use `{query_type}`,
`{query_value}`, and `{output_dir}`. The adapter writes `provider.json` plus
referenced evidence into the private output directory. Forge enforces the
timeout, preserves stdout, stderr, the exact argv, version, timestamps, target,
exit status, exact validated adapter contract and SHA-256, and errors, then
validates the result contract below. Adapters receive a minimal environment;
only names explicitly listed in `environment` are forwarded in addition to
the safe runtime baseline. Tests use a
synthetic local adapter; operators choose and authorize any network provider
and manage its credentials outside case artifacts.

## Provider-result contract

Provider results use a versioned JSON object. Validation is fail-closed:
unknown fields, unsupported schemas, invalid enum values, symbolic links,
non-regular or oversized inputs, URL credentials, unsafe source paths, and a
query outside the operator-supplied case targets are rejected.

Schema 1 has this shape (optional values may be `null`):

```json
{
  "schema": 1,
  "provider": "example-search",
  "query": {"type": "email", "value": "analyst@example.com"},
  "results": [{
    "url": "https://public.example/profile",
    "title": "Example profile",
    "snippet": "Synthetic provider result.",
    "source_file": "evidence/result.json",
    "observed_at": "2026-08-04T12:00:00Z",
    "published_at": null,
    "entities": [{"type": "username", "value": "example_handle"}],
    "relationships": [{
      "source": {"type": "email", "value": "analyst@example.com"},
      "target": {"type": "username", "value": "example_handle"},
      "type": "uses_account"
    }],
    "source_identity": {
      "canonical_url": "https://public.example/profile",
      "publisher": "Example",
      "content_fingerprint": null,
      "syndication_group": null
    },
    "verification_status": "tool_unavailable",
    "verification": {
      "sensor": "example-verifier",
      "sensor_version": "1",
      "method": "compatibility-check",
      "evidence": []
    },
    "temporal_status": "unresolved"
  }]
}
```

The payload requires `schema`, `provider`, `query`, and `results`. Each result
requires `url`, `title`, `snippet`, `source_file`, `observed_at`, `entities`,
`relationships`, and `source_identity`; `published_at`, result-level status,
and relationship-level analytical states are optional. Verification states
other than `not_attempted` and `not_applicable` require a verification record
identifying the sensor, version, method, and evidence; affirmative,
contradictory, inconclusive, and failed states require non-empty evidence.
`source_file` is
resolved beside the payload, must remain inside that directory, and is copied
into the case with the normalized provider payload. Source identity may carry
a canonical URL, publisher, SHA-256 content fingerprint, or syndication group.
When present, the fingerprint must match the referenced evidence bytes; Forge
rejects a mismatch before using it for source-dependence analysis.

The normalized payload and referenced source evidence are preserved as primary
discovery evidence with case-relative provenance. Normalization never replaces
the source record. Provider evidence is the primary discovery layer; existing
plugins remain conditional verification and enrichment sensors.

Provider names describe provenance, not an installed plugin or executable.
Inputs must contain only synthetic, consenting, operator-owned, or otherwise
authorized public-source data. Credentials, cookies, private case material,
and restricted records do not belong in provider-result files.

## Intelligence graph

The versioned provider graph keeps these concepts distinct:

- observations: a source's support for one normalized fact;
- entities: canonical values discovered in provider evidence;
- relationships: typed, directed, evidence-backed links between entities;
- contradictions: explicit evidence that challenges an observation,
  relationship, identity conclusion, or currentness conclusion;
- confidence assessments: scoped, reproducible evaluations; and
- analyst review: separately stored human judgment, never rewritten as an
  automated inference.

Canonicalization and deduplication retain every source. Results with the same
underlying-source identifier are dependent even if several providers or tools
repeat them; mirrors and syndicated copies do not become independent
corroboration. Relationship and inference records include their supporting and
contradicting evidence, method, timestamp, and rationale, making automated
decisions inspectable and reversible.

## Confidence and status

Confidence is never one universal score. Assessments use the scopes
`seed_fidelity`, `observation`, `relationship`, `identity`, and `currentness`.
Each assessment records its method, evidence, timestamp, source-independence
analysis, contradictions, and contribution to the result. Strong identity
support does not establish currentness.

Verification status is independent of confidence and uses:

- `verified`;
- `contradicted`;
- `inconclusive`;
- `tool_unavailable`;
- `tool_failed`;
- `not_applicable`; or
- `not_attempted`.

When no compatible plugin can verify an observation, Forge retains and scores
the provider evidence and reports `tool_unavailable`. An unavailable or failed
tool is neither confirming nor contradicting evidence.

Temporal status uses:

- `current_high_confidence`;
- `current_probable`;
- `historical_high_confidence`;
- `conflicting`;
- `unresolved`; or
- `rejected`.

The contract keeps observation time separate from source publication or update
time. Providers may supply a supported temporal assessment; Forge preserves it,
marks disagreeing assessments `conflicting`, and creates a contradiction. It
does not independently infer identifier reassignment or the semantic role of a
contact point, so evidence lacking that analysis must remain `unresolved`. The
newest available record alone is not enough to label a value current.

## Deliberate boundary

Version 0.8 executes only explicitly selected provider adapters against case
seeds. It does not infer that separate seeds identify one person without
evidence, automatically run verification plugins, recursively pursue a
candidate, or claim to produce the final v1.0 profile. Bounded queues, dynamic
next-action selection, stopping rules, and contract freeze belong to v0.9.
The stable confidence- and currentness-filtered profile belongs to v1.0.
