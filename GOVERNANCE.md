# Governance and Maintainer Authority

OSINT Forge is an owner-maintained open-source project. This document defines
project authority, decision-making, access control, and administrative change
management.

## Project owner

LizardPope1101 is the project owner, lead maintainer, and final decision-maker.
He alone may:

- grant, change, or revoke repository and organization access;
- appoint maintainers or delegates and define their authority;
- authorize or connect AI systems to the repository;
- approve governance, security, release, and licensing-policy revisions;
- merge changes, create or delete protected refs, tag releases, and publish or
  withdraw official releases;
- make final plugin accept, defer, or reject decisions;
- coordinate private vulnerability handling and disclosure; and
- determine the official roadmap, project status, and upstream identity.

Delegation is explicit, limited, and revocable. Repository permissions do not
grant authority beyond the scope LizardPope1101 has stated.

LizardPope1101 may delegate defined development, testing, review, merge,
release, and administrative-closeout actions to an AI he has connected and
authorized. Such delegation must identify its repository and environment
scope, remains subject to `AI_POLICY.md` and every release gate, and does not
allow the AI to modify or expand the policies governing its own authority.

## Contributors and reviewers

Contributors may propose code, tests, documentation, issues, and reviews.
Acceptance of a contribution does not confer maintainership, ownership,
release authority, repository-administration authority, or permission to
represent the project.

Review comments are advisory unless made by LizardPope1101 or by a maintainer
acting within explicitly delegated authority. Every contributor remains
responsible for the legality, licensing, security, accuracy, and quality of
submitted work.

## Decision process

Routine technical decisions are resolved through repository evidence:
documented requirements, reproducible tests, supported-platform behavior,
security impact, maintenance burden, compatibility, and project scope.
Discussion is welcome, but LizardPope1101 makes the final decision when
reasonable alternatives remain or consensus is absent.

Substantial changes normally use a focused branch and pull request. A narrow
direct commit may be used for an administrative correction, typo, link,
metadata update, or urgent fix when LizardPope1101 specifically authorizes it.
Direct commits remain subject to appropriate validation and verification.

## Release administration

An official release is not administratively complete when its tag or GitHub
release is published. The numbered wiki Release Process also requires a
post-publication closeout that:

- announces the release in GitHub Discussions with a high-level overview and a
  link to the versioned changelog;
- updates every applicable repository document and wiki page to match the
  released behavior and stable version; and
- verifies the announcement, documentation, wiki links, release artifacts, and
  installation from the published tag.

These actions are release gates rather than optional publicity or deferred
housekeeping. LizardPope1101 retains final authority over announcement wording,
documentation scope, and release completion.

## Policy precedence

Applicable law and the GNU General Public License cannot be waived by project
policy. Subject to those requirements, specialized policies govern their own
areas:

1. `.github/SECURITY.md` governs vulnerabilities, sensitive reporting, and
   security handling.
2. The published wiki
   [Release Process](https://github.com/LizardPope1101/osint-forge/wiki/Release-Process)
   governs official releases and its numbered gates.
3. `AI_POLICY.md` governs AI access and AI-assisted project work.
4. This file governs project authority and administrative decisions not
   assigned elsewhere.
5. `CONTRIBUTING.md` governs ordinary contribution workflow.
6. Other repository and wiki documentation governs its stated subject.

When policies appear to conflict, the more specific applicable rule controls.
LizardPope1101 resolves remaining ambiguity and records any material exception
in the relevant issue, pull request, advisory, or policy revision. No exception
may waive law, license obligations, authorization boundaries, or private
vulnerability handling.

## Access and automation

Access follows least privilege. Credentials, GitHub Apps, tokens, keys,
authenticated sessions, bots, and automations may be authorized only by
LizardPope1101. AI-specific access is additionally governed by
`AI_POLICY.md`.

Unauthorized access or automation may result in immediate revocation,
credential rotation, closure or reversal of affected changes, and security
review.

## Emergency authority

LizardPope1101 may temporarily restrict access, disable automation, revert or
withdraw affected changes, close public discussion, remove a release, or take
other proportionate action to contain a credible security, legal, privacy,
licensing, or data-integrity risk.

Emergency action should preserve evidence and history when safe. Normal review,
testing, documentation, and release gates resume before a replacement release
is published.

## Inactivity and succession

Project inactivity does not transfer repository ownership, credentials,
maintainer authority, release authority, or the OSINT Forge project identity.
The GPL permits lawful forks under their own administration, but a fork may not
claim to be an official OSINT Forge release or act on behalf of this repository.

Any official succession must be declared by LizardPope1101 through a signed or
otherwise verifiable repository announcement that identifies the successor and
the authority transferred.

## Policy changes

Only LizardPope1101 may approve changes to this document. Governance changes
should be focused, reviewable, documented in repository history, and reflected
in the project wiki when they affect published administrative guidance.
