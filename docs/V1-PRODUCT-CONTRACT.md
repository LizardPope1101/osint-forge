# v1.0 Product Contract

OSINT Forge v1.0 is an evidence-preserving, multi-seed public-source identity
discovery and profile-synthesis system. Its defining workflow begins with a
small set of reliable identifiers, discovers additional public identifiers,
tests whether the observations describe the same subject, follows worthwhile
leads within explicit limits, and produces a current, confidence-filtered
profile.

This contract defines the committed v1.0 outcome. It does not claim that every
person has a discoverable public record or that any investigation can be
literally complete.

## Primary operator outcome

Given three high-certainty seed data points—such as a name, phone number, and
email address—Forge must be able to:

1. preserve the supplied values and their stated certainty;
2. normalize and canonicalize the seeds without treating them as proof of one
   identity;
3. select compatible installed plugins and explain every selection;
4. preserve raw output and execution provenance;
5. extract candidate accounts, usernames, emails, phone numbers, locations,
   domains, websites, infrastructure, and other supported public identifiers;
6. evaluate whether each observation relates to the subject;
7. pursue eligible candidates through a bounded, auditable discovery queue;
8. distinguish current, historical, conflicting, unresolved, and rejected
   information;
9. retain the complete evidence graph internally; and
10. generate a final profile containing only conclusions that meet an explicit
    confidence and currentness policy.

The operator must be able to inspect why an item was included, excluded,
classified as historical, or left unresolved.

## Information layers

Forge must keep three layers distinct:

| Layer | Purpose |
|---|---|
| Preserved evidence | Immutable raw tool output, commands, versions, timestamps, integrity records, and source provenance |
| Intelligence graph | Seeds, observations, candidates, entities, relationships, contradictions, temporal assessments, reviews, queue decisions, and confidence components |
| Final profile | A deterministic view of sufficiently supported intelligence, filtered by explicit confidence and currentness rules |

The final profile never replaces the evidence graph. Lower-confidence leads and
contradictions remain available internally even when excluded from the profile.

## Profile domains

When supported by available lawful public sources, the intelligence graph may
represent:

- primary names and public aliases;
- usernames and public social-media profiles;
- email addresses;
- phone numbers;
- current and historical locations or addresses;
- websites, domains, and public infrastructure;
- public professional and organizational associations;
- public artifacts or files; and
- provenance-linked relationships among those entities.

A field is not guaranteed merely because the schema supports it. Missing
evidence must remain missing rather than being guessed.

## Confidence contract

Confidence is scoped and explainable. Forge must not collapse all judgments
into one opaque score.

At minimum it must distinguish:

- **seed fidelity:** whether Forge preserved the operator's input;
- **observation confidence:** whether a source supports the normalized fact;
- **relationship confidence:** whether two entities are connected;
- **identity confidence:** whether observations describe the same subject; and
- **currentness confidence:** whether an otherwise supported fact is likely
  current.

Each assessment must expose its evidence, method, timestamp, source
independence assumptions, contradictions, and contribution to the result.
Multiple tools repeating one underlying data source count as dependent
corroboration.

## Temporal status

Confidence that a fact belonged to the subject is separate from confidence
that it remains current. Supported profile values must have one of these
states:

- `current_high_confidence`;
- `current_probable`;
- `historical_high_confidence`;
- `conflicting`;
- `unresolved`; or
- `rejected`.

Temporal assessment considers observation time, source publication or update
time when available, newer contradictions, possible identifier reassignment,
and the semantic role of a location or contact point. An address, phone number,
or email cannot be labeled current solely because it is the newest available
record.

## Controlled discovery loop

New candidates enter a versioned discovery queue. Before execution, Forge must
record:

- the originating evidence;
- the proposed target and canonical identity;
- compatible plugins;
- expected information gain;
- confidence and eligibility;
- authorization-scope decision;
- resource and depth budgets; and
- the reason for pursuing, deferring, blocking, or rejecting the candidate.

The loop must prevent cycles, duplicate work, silent scope expansion, and
unbounded execution. Pause, approval, resume, cancellation, interruption, and
recovery are deterministic and auditable.

## Completion and stopping

Forge cannot prove that no undiscovered information exists. A case is
operationally exhausted when one or more explicit stopping conditions apply:

- no eligible candidates remain;
- remaining candidates fall below the pursuit threshold;
- configured depth, time, request, target, plugin, storage, or concurrency
  budgets are reached;
- authorization scope blocks further collection;
- repeated passes produce no material new evidence; or
- the operator stops the workflow.

The final report states which condition ended collection and must never
describe operational exhaustion as universal completeness.

## Final profile policy

The reporting policy defines whether `current_probable` values are included.
Only current values meeting the selected threshold may be asserted in the main
profile. Historical, conflicting, unresolved, and rejected items appear only
in their clearly labeled internal sections unless an operator deliberately
selects an expanded analytical view.

Every displayed conclusion includes:

- the value and entity type;
- temporal status;
- scoped confidence;
- last-observed or last-verified time when known;
- supporting and contradicting evidence;
- source-independence analysis; and
- a complete provenance path.

## Accuracy and quality measures

Release acceptance must use synthetic identities, consenting participants, or
other controlled datasets. It must measure:

- candidate recall;
- top-match precision;
- attribute precision;
- false merges;
- false splits;
- relationship precision;
- temporal-classification accuracy;
- provenance coverage;
- contradiction preservation;
- abstention quality; and
- bounded completion without cycles or scope escape.

No accuracy claim may be published without a documented dataset, method,
sample size, limitations, and reproducible result.

## Safety and responsibility boundary

Forge is designed for lawful public-source work within a documented
authorization scope. It does not grant permission to investigate a person,
access private systems, evade access controls, acquire restricted records, or
use the resulting information for a regulated eligibility decision.

The operator remains responsible for lawful purpose, collection minimization,
source terms, final analytical judgment, and distribution of sensitive
results. Product defaults must favor private evidence, restrained collection,
transparent uncertainty, and the ability to stop.

## Release mapping

| Release | Contract delivered |
|---|---|
| v0.5 | Accepted/emitted entity contracts and deterministic candidate observations |
| v0.6 | Multi-seed planning, information-gain rationale, and reproducible entity-aware workflows |
| v0.7 | Verifiable evidence and portable intelligence graphs |
| v0.8 | Relationships, source-aware correlation, temporal status, contradictions, and scoped confidence |
| v0.9 | Bounded recursive discovery, stopping conditions, hardening, benchmarks, and contract freeze |
| v1.0 | Stable three-seed-to-profile workflow with confidence- and currentness-filtered reporting |

The [Roadmap to v1.0](ROADMAP.md) and release issues allocate delivery, but
this document is the canonical product outcome.
