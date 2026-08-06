# Interactive UI Product Contract

OSINT Forge v1.0 includes one complete guided terminal interface governed by a
simple standard:

> If you can read, you can run OSINT Forge.

Running `osint` with no arguments opens the interface. The advanced CLI remains
available for experienced operators, scripts, automation, and AQAD. Both
interfaces call the same application services and investigation engine. The
interactive interface is not a separate implementation of case or collection
behavior.

## One implementation and one release gate

The interactive UI is delivered as one cohesive v1.0 implementation. Internal
engineering and QA may use dependency-ordered checkpoints, but OSINT Forge will
not publish a `v0.9.1` through `v0.9.9` sequence of partial UI releases and will
not claim that the v1.0 UI is complete until this entire contract passes.

## Required operator journey

A first-time operator can complete this journey without documentation:

1. create, open, or resume a case;
2. state its purpose and authorization scope;
3. add names, emails, usernames, phone numbers, addresses, domains, IPs,
   images, and files;
4. review and safely edit the starting information;
5. start one bounded investigation with recommended defaults;
6. understand what Forge is doing and why;
7. pause, resume, stop, or recover the investigation;
8. resolve ambiguous identity matches without contaminating the case;
9. review findings, evidence, confidence, verification, and exclusions; and
10. generate the final report.

The interface may expose more detail on request, but it must never require an
operator to know plugin identifiers, memorize commands, edit JSON/YAML/text
files, or manage case directories.

## Screen contract

Every screen must make five facts apparent:

- where the operator is;
- what information is needed;
- which choices are available;
- what happens next; and
- how to go back, save, pause, resume, stop, or exit.

Questions use plain language and are asked one at a time. Optional fields are
identified. Input is validated immediately. A rejected value never discards
previously accepted information. Defaults are visible and conservative.

The permanent top-level destinations are Create New Case, Open Existing Case,
Resume Paused Investigation, Recent Cases, Reports, Settings, Plugin Manager,
System Status, Help, and Exit. Context-appropriate navigation remains visible;
`0` goes back and `Q` exits safely. Investigation screens additionally expose
save, pause, resume, and stop actions when those actions are valid.

## Investigation control contract

The interface explains the discovery loop in operator language:

1. preserve the supplied starting information;
2. choose compatible public-source searches and verification tools;
3. collect and preserve observations;
4. identify possible new leads;
5. validate, deduplicate, and confidence-score them;
6. request review for ambiguous identity matches;
7. investigate eligible leads within the authorized limits; and
8. stop at queue, confidence, scope, time, request, depth, storage, or operator
   boundaries.

The operator can select automatic continuation within safeguards, review new
targets before continuation, pause after each cycle, or stop and report current
results. Forge confirms destructive, unusually expensive, or scope-expanding
actions before performing them.

## Measurable acceptance criteria

Release validation must demonstrate all of the following on a clean supported
system using synthetic, consenting, operator-owned, or otherwise authorized
data:

- With no arguments, `osint` opens the main menu; every existing advanced CLI
  command retains its prior behavior and machine-consumable output.
- A new user completes the entire required operator journey without reading
  external documentation or manually opening a case artifact.
- Every supported seed type accepts a valid fixture and rejects an invalid
  fixture with a correction that preserves the rest of the case.
- An interrupted session reopens the same case without losing accepted data or
  duplicating completed work.
- Every menu and prompt has deterministic automated coverage for valid input,
  invalid input, back, EOF, and safe exit.
- Recursive progress identifies the current cycle, active action, reason,
  elapsed/budget state, discoveries, deferred items, failures, and stop reason
  without exposing raw internal noise by default.
- Ambiguous candidates never enter the confirmed subject graph or recursive
  queue until the configured review policy permits it.
- Pause, resume, stop, cancellation, crash recovery, budget exhaustion, and
  queue exhaustion produce auditable deterministic state transitions.
- Report generation exposes supported findings and clearly separated
  historical, conflicting, unresolved, rejected, low-confidence, and
  tool-unverified material according to the product contract.
- Keyboard-only use, narrow-terminal rendering, plain-text output, screen-reader
  reading order, and non-color operation remain functional.

Any failed criterion is a v1.0 release blocker. A menu that merely launches
commands does not satisfy this contract.

## Implementation readiness boundary

The interface is developed as one v1.0 change set, but readiness is measured
against the engine contract it coordinates. The deterministic UI framework can
be completed and reviewed before live collection begins:

| Capability | Deterministic UI boundary | Required engine boundary |
| --- | --- | --- |
| Cases and seeds | Create, open, edit scope, registry-driven add/edit/remove, import, deduplicate | Existing case service |
| Planning | Explain the resolved plan without network activity | Existing workflow planner |
| Execution | Start/resume a saved case cycle and preserve completed-job skipping | Existing case runner |
| Recursive control | Persist policy, budgets, lifecycle, recovery, and operator decisions | v0.9 queue must enforce depth, time, request, storage, and authorization budgets |
| Pause and stop | Expose valid controls and durable requested state | v0.9 runner must provide cooperative mid-run pause/cancel checkpoints |
| Ambiguity | Quarantine, display, accept, reject, defer, and audit decisions | v0.9 correlation/queue must populate candidates and consume reviewed decisions |
| Findings and reports | Display normalized confidence/provenance summaries and generate all formats | Existing reporting service; v0.9 adds recursive classifications |
| Plugins | Catalog, compatibility, doctor, preview, install, update, and remove | Existing plugin lifecycle service |

The UI must not pretend that saving a budget or pause request enforces it. Final
integration is permitted only after the v0.9 queue and runner expose the listed
application-service operations. The final release trigger is then the complete
automated suite followed by clean-install, real-plugin, interruption, recovery,
narrow-terminal, non-color, accessibility, and first-time-user validation.
