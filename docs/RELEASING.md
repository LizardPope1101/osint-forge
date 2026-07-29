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
repository. The authoritative process requires AI-assisted, human-operated
testing on a current Debian stable VM after merge and before tagging, including
a patch-and-retest loop when defects are found.

Do not publish a release containing target data, reports, credentials, cookies,
tokens, local state, or investigation artifacts.
