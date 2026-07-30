# AI-Assisted Development Policy

OSINT Forge uses artificial intelligence as a development aid under human
ownership, authorization, and accountability. AI can accelerate analysis,
implementation, testing, review, and documentation, but it does not replace
maintainer judgment or project requirements.

## Exclusive connection authority

**LizardPope1101 is the only person permitted to connect an AI system to the
OSINT Forge repository, GitHub account, or repository-integrated tooling.**

Connection includes direct access through a GitHub App, OAuth authorization,
personal access token, SSH credential, authenticated browser session, API
integration, MCP server, IDE agent, bot, automation service, or comparable
mechanism. It includes authenticated read-only and write access.

No contributor, collaborator, reviewer, maintainer delegate, or other person
may establish such a connection under any circumstances. LizardPope1101 may
authorize AI-assisted work, but may not delegate the act of establishing
repository access. Repository permissions do not imply AI-connection
authority.

Public search-engine indexing, unauthenticated retrieval of this public
repository, and a contributor manually providing selected non-sensitive public
material to an otherwise disconnected AI are not direct repository
connections. Those activities remain subject to the contributor rules below.

Only LizardPope1101 may authorize, install, configure, scope, use, or remove an
AI repository integration; grant it credentials or an authenticated session;
permit it to perform repository actions; or revoke and rotate its access.

## Contributor use of AI

Contributors may use disconnected AI assistance for brainstorming,
explanation, drafting, local coding, test design, documentation, or review
when all of the following are true:

- The AI has no direct authenticated or integrated repository access.
- The contributor personally reviews, understands, and accepts responsibility
  for every submitted change.
- Material AI assistance is disclosed in the pull request when it
  substantially generated or transformed code, tests, documentation, or
  analysis.
- The work follows the same tests, review, security, licensing, provenance,
  and documentation requirements as wholly human-written work.
- AI output is treated as untrusted until independently checked.
- No credentials, private communications, personal information, case data,
  investigation results, restricted material, or non-public vulnerability
  details are supplied to the AI.
- The contributor confirms that all submitted material can lawfully be
  distributed under the project's license.

AI use does not excuse defects, fabricated evidence, unsupported claims,
incompatible code, copyright violations, or incomplete review.

## Maintainer-operated AI workflow

An AI connected or directed by LizardPope1101 may work only within the scope he
authorizes. It must:

1. Establish the task, constraints, affected release, and authorization
   boundary.
2. Inspect current repository state before changing it.
3. Make focused, reviewable changes and preserve unrelated work.
4. Add or update tests and repository documentation with behavior changes.
5. Run all available relevant validation and inspect the results.
6. Use branches and pull requests for substantial changes unless a narrow
   direct update is specifically authorized.
7. Require hosted checks to pass before merging.
8. Verify the resulting state on `main`.
9. Follow every sequential release gate before tagging or publishing.
10. Complete and verify the post-publication administrative closeout, including
    the Discussions announcement, changelog link, repository documentation,
    and applicable wiki updates.

An authorized AI may create or merge changes when LizardPope1101 grants that
authority for the stated task. That authority does not extend to unrelated
repositories, accounts, credentials, communications, destructive actions, or
publication outside the authorized project workflow.

## Human oversight and accountability

LizardPope1101 remains the final project authority. AI recommendations are
advisory unless he approves or delegates the corresponding action. An AI must:

- state material assumptions, limitations, failures, and unresolved risks;
- never claim a test, merge, publication, or verification occurred without
  evidence;
- stop when required access, authorization, or a consequential project
  decision is missing;
- avoid destructive or difficult-to-reverse actions unless clearly
  authorized;
- preserve repository history and prefer focused commits and pull requests;
- distinguish automated output from verified findings; and
- leave security, licensing, governance, and release gates intact.

Human authorization and accountability remain mandatory for
security-sensitive changes, credentials and permissions, licensing decisions,
vulnerability handling, live testing, and release readiness. LizardPope1101
may personally perform a review or explicitly delegate defined testing,
review, merge, and release actions to an authorized AI. Delegation does not
permit the AI to expand its own scope or alter the policies governing its
authority.

## Testing and releases

AI assistance does not reduce the testing burden. Release candidates must
complete every numbered gate in the authoritative wiki Release Process.
Automated candidate validation must use the repository QA harness in its
fail-closed release profile. Its exact-commit state, step logs, exit codes, and
evidence manifest must be retained and verified. The harness supplements rather
than replaces live Debian validation.

Live release testing may use either of two modes selected and authorized by
LizardPope1101:

- **Human-operated mode:** the AI devises and furnishes controlled tests, a
  human runs them on the authorized Debian VM, and the human returns complete
  output for AI review.
- **Autonomous mode:** an owner-authorized AI runs controlled tests directly
  on a dedicated testing VM and may perform only the repository, VM, patch,
  merge, release, and closeout actions expressly included in its authorization.

Autonomous mode is valid only when the VM runs a current stable Debian release;
the tested commit and authorization scope are recorded; test data is synthetic,
reserved, loopback, operator-owned, or explicitly authorized; commands,
timestamps, versions, output, exit codes, defects, patches, reruns, and
conclusions are preserved; and the agent fails closed on any missing access,
failed gate, material uncertainty, or scope conflict. Evidence must be
reviewable after the run and stored with owner-only permissions when it may
contain sensitive operational detail.

Autonomous execution does not reduce or replace any release gate. Defects
require corrective patches and renewed automated and live validation before
tagging. An AI may not approve a change to this policy, reinterpret its own
authority, use real third-party personal data for testing, or attest a test it
did not execute and verify.

An AI must not treat a merge as a release, tag an unvalidated commit, bypass a
failed check, suppress a failed result, or publish before required gates pass.
After publication, it must not declare the release process complete until the
required announcement and documentation closeout has been verified.

## Security, privacy, and OSINT data

Connected AI must receive the minimum access required for the authorized task.
Credentials must not be committed, printed into logs, copied into chat,
embedded in prompts, or exposed in generated artifacts.

Real OSINT targets, case files, raw results, authentication data, private
reports, and vulnerability details must not be used as development prompts or
fixtures. Development uses synthetic, reserved, operator-owned, loopback, or
explicitly authorized data.

## Quality, provenance, and enforcement

AI-generated material receives no presumption of correctness. Tests must be
reproducible, results must not be invented or selectively represented, and
documentation must describe actual behavior. The human submitting or approving
a change remains accountable for it regardless of AI involvement.

Unauthorized AI repository connections may result in rejection or closure of
the contribution, access removal, credential rotation, reversal of affected
changes, and security review. Anyone unsure whether a tool constitutes a
connection must ask LizardPope1101 before using it. When in doubt, the tool
must remain disconnected.

Only LizardPope1101 may approve changes to this policy. The repository version
is the canonical policy for a checked-out commit or release; the published wiki
provides the current readable counterpart. LizardPope1101 resolves any
discrepancy through a documented policy update.
