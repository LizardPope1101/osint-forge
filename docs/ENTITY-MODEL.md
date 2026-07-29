# Entity Model

OSINT Forge is evolving from tool orchestration toward evidence-preserving
entity discovery and correlation. Version 0.4 establishes the first additive
contract: deterministic entities projected from operator-supplied case targets.

This foundation does not perform recursive discovery, automated identity
attribution, or relationship inference.

## Contract

Run:

```bash
osint case entities CASE_ID --json
```

The command returns an object with:

- `schema`: entity-contract version;
- `case_id`: owning case;
- `entity_count`: number of projected entities;
- `entities`: canonical seed entity records; and
- `relationships`: currently empty, reserved for later evidence-backed links.

Each seed entity contains:

- a deterministic entity ID derived from type and canonical value;
- the entity type;
- the preserved display value;
- a canonical comparison value;
- `seed` origin;
- confidence limited to operator-supplied input fidelity; and
- provenance linking back to the exact case target and addition timestamp.

The projection is deterministic and derived from `case.json`. It is not a
second writable source of truth.

## Seed types

Case targets and seed entities support:

- address
- domain
- email
- file
- image
- IPv4 address
- name
- phone number
- username

Plugins continue to run only for target types explicitly declared in their
manifests. A name, phone number, or address can therefore be recorded now
without being sent to an incompatible tool.

## Canonicalization

Canonicalization supports stable comparison and identifiers while preserving
the operator-supplied display value:

- email and domain values compare case-insensitively;
- phone values retain an optional leading `+` and remove formatting;
- names and addresses collapse whitespace and compare case-insensitively; and
- current file, image, IP, and username behavior remains unchanged.

Canonical equality is not proof that two records describe the same person.
Future entity resolution must preserve that distinction.

## Confidence boundary

A seed has confidence score `1.0` only within the scope `seed_fidelity`, using
the method `operator_supplied`. This means Forge accurately represented the
input. It does not mean:

- the value belongs to the subject;
- the value is current or accurate;
- two seeds identify the same person; or
- any relationship has been independently corroborated.

Later confidence models must state their scope, method, evidence, and
independence assumptions instead of collapsing every judgment into one opaque
number.

## Forward compatibility

Later releases can extend the contract with:

1. entities extracted from normalized findings;
2. evidence-backed relationships;
3. canonical deduplication that retains every source;
4. transparent confidence assessments;
5. plugin declarations for accepted and emitted entity types;
6. bounded discovery queues with cycle and scope controls; and
7. analyst-reviewed intelligence reporting.

Schema changes must remain versioned, tested, provenance-preserving, and
readable by explicit migrations or compatibility layers.
