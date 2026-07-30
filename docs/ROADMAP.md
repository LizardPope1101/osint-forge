# Roadmap to v1.0

OSINT Forge is evolving from a modular OSINT tool manager into an
evidence-preserving intelligence system. By v1.0, an authorized operator will
be able to provide multiple known seed entities—such as names, email
addresses, usernames, phone numbers, addresses, domains, IP addresses, and
files—and let Forge coordinate a bounded investigation.

The defining v1.0 outcome is a three-seed-to-profile workflow: given a small
set of reliable identifiers such as a name, phone number, and email address,
Forge discovers additional public identifiers, tests whether they describe the
same subject, follows worthwhile leads within explicit limits, and produces a
current, confidence-filtered profile. The complete, testable outcome is defined
in the [v1.0 Product Contract](V1-PRODUCT-CONTRACT.md).

The v1.0 workflow will:

1. normalize the supplied seeds;
2. select compatible installed plugins;
3. preserve raw output and execution provenance;
4. extract additional candidate entities and relationships;
5. canonicalize and deduplicate them without losing sources;
6. correlate independent evidence and record contradictions;
7. assign scoped, transparent confidence assessments;
8. queue worthwhile discoveries for controlled follow-up;
9. repeat within explicit authorization and resource limits;
10. assess temporal status independently from identity confidence; and
11. produce a current profile that separates supported conclusions from
    historical, conflicting, unresolved, and rejected information.

The releases through v1.0 are project commitments. Their implementation details
may evolve when testing exposes a safer or more reliable design, but the
capabilities below are the intended stable destination.

## Governing principles

- Raw evidence and complete provenance are never replaced by normalized data.
- Observations, automated inferences, and analyst-confirmed intelligence remain
  distinguishable.
- Multiple tools repeating one underlying source do not count as independent
  corroboration.
- Canonicalization and deduplication retain every source and contradiction.
- Confidence is scoped, explainable, and evidence-backed rather than an opaque
  universal score.
- Confidence that an observation belongs to the subject is separate from
  confidence that it remains current.
- Plugins declare what entity types they accept and what candidate entities
  they can emit.
- Recursive discovery is opt-in, bounded, auditable, resumable, and constrained
  to the documented authorization scope.
- Existing interfaces evolve through versioned contracts, migrations, and
  compatibility tests.
- Every release receives comprehensive automated testing and the mandatory
  Debian VM test before tagging, performed either by a human with AI assistance
  or by an AI under explicit owner authorization.

## Release plan

| Release | Committed outcome |
|---|---|
| v0.4 | Normalized reports, canonical seed entities, provenance-linked findings, analyst annotations, and the first entity contract |
| v0.5 | Governed plugin expansion plus entity-aware plugin and extraction contracts |
| v0.6 | Multi-seed planning, reproducible workflows, information-gain rationale, and explainable plugin selection |
| v0.7 | Evidence hashing, verification, and portable entity-aware case exports |
| v0.8 | Entity relationships, transparent correlation, source independence, temporal status, contradictions, and scoped confidence |
| v0.9 | Opt-in bounded recursive discovery, stopping conditions, benchmarks, hardening, and the v1 contract freeze |
| v1.0 | Stable three-seed-to-profile workflow through controlled follow-up and confidence/currentness-filtered reporting |

### v0.4 — Reporting and seed entities

Tracking: [issue #6](https://github.com/LizardPope1101/osint-forge/issues/6)

- Normalize heterogeneous plugin output without replacing raw evidence.
- Generate deterministic JSON, Markdown, HTML, and CSV reports.
- Preserve finding-to-source provenance and explicit failed or previewed runs.
- Support analyst notes and confidence annotations without treating tool output
  as fact.
- Represent name, email, username, phone, address, domain, IP, file, and image
  seeds as canonical provenance-linked entities.
- Merge canonically equivalent seeds while retaining every source target.

### v0.5 — Entity-aware plugin expansion

Tracking: [issue #13](https://github.com/LizardPope1101/osint-forge/issues/13)

- Add only maintained, secure, useful, and license-compatible plugins through
  the governed evaluation process.
- Extend plugin contracts to declare accepted and emitted entity types.
- Require deterministic extraction of candidate entities from preserved output.
- Prioritize integrations that advance public identity and web-presence
  discovery.
- Preserve lifecycle, clean-install, normalizer, provenance, and regression
  coverage for the original and expanded catalog.

Implementation status: schema-2 entity contracts, candidate extraction, the
governed theHarvester integration, and all seven candidate decisions are
implemented for the v0.5 release candidate. Tagging remains blocked on the
mandatory live Debian release-candidate test.

### v0.6 — Planning and orchestration

Tracking: [issue #18](https://github.com/LizardPope1101/osint-forge/issues/18)

- Define versioned, reusable investigation workflows.
- Resolve several heterogeneous seeds as one case without assuming they
  identify the same subject.
- Select plugins according to entity compatibility and installed availability.
- Preview the resolved plan without network activity.
- Explain why every plugin and entity were scheduled.
- Record expected information gain and why a workflow stage is useful.
- Preserve ordered stages, bounded concurrency, timeouts, cancellation,
  resumption, and complete provenance.

### v0.7 — Evidence integrity and portability

Tracking: [issue #14](https://github.com/LizardPope1101/osint-forge/issues/14)

- Hash raw evidence and material case artifacts.
- Verify missing, modified, or unexpected content.
- Preserve entity and relationship provenance through export and import.
- Produce safe full-fidelity and conservatively redacted bundles.
- Detect traversal, unsafe links, corruption, and redaction failures.

### v0.8 — Correlation and confidence

Tracking: [issue #15](https://github.com/LizardPope1101/osint-forge/issues/15)

- Add evidence-backed relationships among people, accounts, identifiers,
  domains, infrastructure, locations, and artifacts.
- Deduplicate observations without erasing their source history.
- Distinguish observation confidence, relationship confidence, and identity
  confidence.
- Assess currentness separately from identity and relationship confidence.
- Account for source independence, staleness, conflicts, and analyst review.
- Keep every automated inference transparent, reversible, and separate from
  analyst-confirmed intelligence.

### v0.9 — Controlled recursive discovery and contract freeze

Tracking: [issue #17](https://github.com/LizardPope1101/osint-forge/issues/17)

- Add an opt-in queue for newly discovered entities.
- Select the next compatible tools using explicit, testable rules.
- Enforce maximum depth, runtime, requests, concurrency, confidence, plugin,
  target, and authorization-scope limits.
- Detect cycles and prevent duplicate or runaway work.
- Stop when the queue is exhausted, candidates fall below threshold, budgets
  are reached, scope blocks collection, or repeated passes add no material
  evidence.
- Benchmark recall, precision, false merges, false splits, temporal
  classification, provenance, abstention, and bounded completion on controlled
  datasets.
- Support deterministic pause, approval, resume, cancellation, and recovery.
- Harden and freeze the v1 CLI, plugin, case, entity, relationship, confidence,
  workflow, queue, report, integrity, and export contracts.

### v1.0 — Stable intelligence workflow

Tracking: [issue #16](https://github.com/LizardPope1101/osint-forge/issues/16)

- Accept multiple heterogeneous seeds in one authorized case.
- Demonstrate the canonical name/phone/email three-seed workflow using
  synthetic or consenting test subjects.
- Orchestrate collection, extraction, correlation, and bounded follow-up.
- Preserve the evidence graph and rationale behind every pursued lead.
- Produce a deterministic profile of current intelligence meeting explicit
  identity-confidence and currentness thresholds while retaining historical,
  conflicting, unresolved, rejected, and lower-confidence information
  internally.
- Complete compatibility, migration, privacy, security, clean-install, upgrade,
  archive, and live Debian release validation.

## What v1.0 will not claim

OSINT Forge will not claim certainty merely because tools agree. It will not
hide contradictory evidence, perform opaque identity attribution, erase raw
sources, run an unbounded investigation, or treat authorization metadata as a
substitute for actual permission.

The operator remains responsible for lawful use, source terms, collection
minimization, distribution, and final analytical judgment.

## Beyond v1.0

Post-v1.0 work is tentative. It may improve performance, usability,
visualization, collaboration, interoperability, deployment, and supported
entity or plugin coverage. Those goals are not promises and cannot displace
v1.0 stability, compatibility, security, provenance, or maintenance
obligations.
