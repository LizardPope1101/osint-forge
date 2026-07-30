# v0.5 governed plugin evaluation

Evaluated on 2026-07-30 for the v0.5 catalog. Admission requires current
maintenance, clear licensing, supported Debian/Ubuntu installation, a
restrained argument-array adapter, deterministic structured normalization, and
a useful role not already covered more safely.

| Candidate | Decision | Rationale |
|---|---|---|
| theHarvester | **Accepted** | Actively maintained, GPL-2.0-only, supports Python 3.12+, produces JSON, and passively extracts domains, email addresses, and IP addresses. Forge pins release 4.11.1 and restricts it to `crtsh,rapiddns`, 100 results, quiet mode, and domain targets. No API key is required for the accepted defaults. |
| WhatsMyName | **Deferred** | The actively maintained CC-BY-SA-4.0 project is an authoritative dataset rather than a governed executable client. Existing Maigret and Sherlock integrations already provide username searches. Reconsider as a versioned data-provider contract. |
| Holehe | **Rejected for v0.5** | GPL-3.0 licensing is compatible, but upstream has not changed since 2024 and its CLI performs an automatic PyPI version check that may self-update at runtime. Its password-recovery/account-registration probes also need finer per-site policy controls before admission. |
| Amass | **Deferred** | Actively maintained and Apache-2.0 licensed, but its attack-surface scope and active discovery modes overlap infrastructure tooling and exceed the identity-focused v0.5 priority. Reconsider with a passive-only, version-pinned adapter. |
| Photon | **Deferred** | GPL-3.0 and maintained in 2026, but its crawler can collect secrets and broad web content, and its filesystem output needs a narrower stable extraction contract before admission. |
| Social Analyzer | **Rejected for v0.5** | Useful and AGPL-3.0 licensed, but it substantially overlaps Maigret and Sherlock and has a documented modern-Node dependency incompatibility. The installation footprint is not yet reliable on supported clean systems. |
| h8mail | **Rejected for v0.5** | BSD-3-Clause licensing is compatible, but upstream has been inactive since 2022. Its breach/password-data focus creates unnecessary sensitivity and credential-provider complexity for the public-identity catalog. |

Decisions apply to v0.5 only. Deferred tools require a new evaluation against
their then-current upstream state. Rejected tools are not prohibited forever,
but the stated blocker must be resolved before reconsideration.

## Accepted theHarvester boundary

- Accepted entity: `domain`
- Emitted candidate entities: `domain`, `email`, `ip`
- Default sources: `crtsh,rapiddns`
- Installed upstream release: `4.11.1` from the authoritative Git tag
- Result limit: 100
- Credentials: none for the default sources
- Recursion: disabled
- Active DNS resolution, brute force, takeover testing, screenshots, Shodan,
  API scanning, and user-supplied source expansion: disabled
- Every candidate is classified as an unverified extracted observation and
  links to the preserved `results.json`, originating target, plugin version,
  and run
