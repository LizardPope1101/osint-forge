# Autonomous Codex QA

On the dedicated Debian testing VM, start Codex and development QA from a clean
checkout with one command:

```bash
./scripts/codex-qa.sh
```

Start the stricter release-candidate and live Debian workflow only from a clean,
current `main` branch:

```bash
./scripts/codex-qa.sh release
```

The launcher performs fail-closed Debian, Git, Codex authentication, GitHub
authentication, repository, and release-candidate preflight checks. Release
mode also requires passwordless `sudo`, an exact match with `origin/main`, and
uses unrestricted Codex execution only within the dedicated testing VM.

Codex runs non-interactively inside a persistent `tmux` session. The launcher
stores its exact prompt, metadata, JSONL event stream, exit code, and final
message under `~/OSINT-Forge-QA/codex-sessions/`, with owner-only permissions.
It authorizes testing and corrective patch loops but expressly excludes
tagging, publication, and release announcements.

Inspect or control the session without disturbing its evidence:

```bash
./scripts/codex-qa.sh status
./scripts/codex-qa.sh attach
./scripts/codex-qa.sh stop
```

Detach from the live `tmux` view with `Ctrl-b d`. A transport disconnect does
not erase the QA harness checkpoint; Codex must verify and resume the bound
evidence rather than treating an incomplete step as passed.

The underlying exact-commit validation, resume rules, and evidence guarantees
are documented in [`QA-HARNESS.md`](QA-HARNESS.md).
