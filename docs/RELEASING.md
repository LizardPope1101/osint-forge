# Releasing OSINT Forge

The authoritative release procedure is the numbered
[Release Process](https://github.com/LizardPope1101/osint-forge/wiki/Release-Process)
in the project wiki. Complete every numbered step in order. Each step is a
gate: verify it before beginning the next step. Do not skip, combine, reorder,
or treat a pending check as complete.

If that wiki page is revised, its newest published process governs subsequent
releases. This file intentionally does not duplicate the checklist, which
prevents two release procedures from drifting apart.

Release-related AI activity is governed by [`AI_POLICY.md`](../AI_POLICY.md).
Only LizardPope1101 may connect or authorize an AI system to access the
repository. The authoritative process requires live testing on a current
Debian stable VM after merge and before tagging. That gate may be
human-operated with AI assistance or autonomously executed by an AI under
explicit owner authorization. Both modes require complete retained evidence,
fail-closed handling, and a patch-and-retest loop when defects are found.

Publishing the GitHub release does not complete the process. The authoritative
procedure includes a mandatory administrative closeout after publication:

- announce the release in GitHub Discussions with a high-level overview and a
  link to the versioned changelog;
- update every applicable repository document to describe the released
  behavior and identify the new stable version;
- update every applicable wiki page, including release, command, operational,
  architectural, and roadmap guidance; and
- verify the announcement, documentation, wiki links, release artifacts, and
  installation from the published tag.

Administrative closeout is a numbered release gate. It may not be skipped or
treated as optional follow-up work.

Do not publish a release containing target data, reports, credentials, cookies,
tokens, local state, or investigation artifacts.
