# Security and Ethics

OSINT Forge is for lawful, authorized research. Public availability does not
eliminate privacy, contractual, ethical, or authorization obligations.

## Authorization

- Record purpose and authorization scope before starting a case.
- Scan networks only with ownership or explicit permission.
- Respect law, contracts, service terms, rate limits, and policy.
- Use restrained defaults and concurrency.
- Stop when scope is unclear or authorization expires.

## Evidence and findings

- Never commit targets, credentials, cookies, tokens, cases, or results.
- Preserve raw evidence separately from normalized findings and analyst review.
- Treat every automated result as an unverified lead until corroborated.
- Keep failures, uncertainty, normalization errors, and orphaned reviews visible.
- Protect parent directories, backups, archives, reports, and exports.

## Redaction

`osint case report CASE --format all --shareable` removes target values, stable
case/run/job identifiers, commands, source/raw paths, result values and
attributes, notes, and error detail. Structural metadata remains. Redaction
cannot understand every contextual inference, so human review is mandatory
before sharing.

## Operational safeguards

Adapters use argument arrays. Plugin, case, review, normalizer-source, and
report paths are contained and symbolic-link protected. Core checks stored
status against case state before normalization. Framework-created case and
batch artifacts use owner-only permissions.

## Vulnerabilities

Never disclose a suspected vulnerability in a public issue, pull request,
discussion, wiki page, log, or report. Use
[GitHub private vulnerability reporting](https://github.com/LizardPope1101/osint-forge/security/advisories/new).

The canonical
[Security Policy](https://github.com/LizardPope1101/osint-forge/blob/main/.github/SECURITY.md)
governs scope and reporting.
