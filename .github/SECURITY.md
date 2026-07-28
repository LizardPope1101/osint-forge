# Security Policy

## Supported versions

OSINT Forge is currently in pre-1.0 development. Security fixes are applied to
the latest stable release and the active `main` branch when applicable. Older
releases, commits, forks, archived releases, and locally modified installations
are not separately supported.

| Version | Supported |
|---|---|
| Latest stable release | Yes |
| Active `main` branch | Yes, development |
| Older releases or commits | No |
| Third-party OSINT tools | By their upstream maintainers |

Users performing real authorized work should use the latest stable release.
The `main` branch may contain unreleased changes and is intended for
development and testing.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, pull request,
discussion, wiki page, log, or case report.

Use GitHub's private vulnerability reporting for this repository when it is
available:

https://github.com/LizardPope1101/osint-forge/security/advisories/new

If private reporting is unavailable, contact the maintainer privately through
an established channel and include only enough information to arrange a secure
exchange. Do not place exploit details, credentials, personal information,
targets, authentication material, or case data in a public channel.

A useful report includes:

- A concise description of the vulnerability and its likely impact
- The affected OSINT Forge commit, file, command, and plugin
- The operating system and relevant dependency versions
- Minimal, reproducible steps using synthetic or non-sensitive test data
- Logs with secrets, tokens, cookies, target data, and personal information
  removed
- Any suggested mitigation or patch
- Whether the vulnerability is already public or known to be exploited

Do not perform testing against systems, accounts, people, or infrastructure
without authorization. Do not use real case data to demonstrate a flaw.

## Scope

Security issues in scope include:

- Command or argument injection
- Privilege escalation or unsafe `sudo` behavior
- Unsafe lifecycle-script execution
- Path traversal or arbitrary file writes
- Insecure handling of credentials, cookies, tokens, or configuration
- Sensitive data exposure through logs, state files, or reports
- Loss or corruption of case data, provenance, activity history, or raw output
- Unsafe case import, export, report, redaction, or integrity behavior
- Manifest validation bypasses
- Unsafe plugin discovery or loading
- Dependency or installer behavior introduced by OSINT Forge
- Authorization checks or safeguards implemented by OSINT Forge

The following are generally outside this project's direct scope:

- Vulnerabilities in independently installed tools such as Nmap, GHunt,
  Maigret, Sherlock, Recon-ng, SpiderFoot, or ExifTool
- Incorrect or false-positive results produced by an upstream tool
- Third-party websites, APIs, data brokers, or services queried by a tool
- Social engineering, credential stuffing, doxxing, or unauthorized scanning
- Problems caused solely by unsupported local modifications

Report upstream vulnerabilities to the affected upstream project. If OSINT
Forge's integration makes an upstream issue materially worse, bypasses a
safeguard, or exposes users unexpectedly, also report the integration issue
privately here.

## Response and disclosure

Reports are handled on a best-effort basis; the project does not promise a
fixed response or remediation service level.

The preferred process is:

1. Confirm receipt and establish a private communication channel.
2. Reproduce and assess the report without using sensitive targets.
3. Develop and test a fix or mitigation.
4. Coordinate a release and disclosure timeline when practical.
5. Credit the reporter if requested and appropriate.

Please allow a reasonable remediation period before public disclosure. The
project may publish a security advisory describing affected versions,
mitigations, and upgrade instructions after a fix is available.

## Safe-harbor intent

Good-faith research that stays within authorization, avoids privacy violations,
minimizes data access, and follows this policy will not be treated as malicious
by the OSINT Forge project. This statement does not authorize testing of
third-party systems and cannot bind third parties or law-enforcement agencies.

## Operational security

Users should:

- Review lifecycle scripts before granting elevated privileges.
- Install only the plugins required for an authorized workflow.
- Keep API keys, cookies, and tokens outside the repository and target files.
- Protect `~/.local/state/osint-forge/` and case-output directories.
- Preserve raw evidence separately from interpretation.
- Verify the destination and redaction level before sharing any case export or
  report.
- Use restrained concurrency and network-scan defaults.
- Keep the framework and all independently installed tools updated.
- Never commit targets, reports, credentials, or case data.

OSINT Forge creates its own state and result artifacts with owner-only
permissions. Users remain responsible for permissions on parent directories,
backups, exported reports, and files created independently by upstream tools.
