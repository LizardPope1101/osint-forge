# QA Harness

`scripts/qa-harness.py` is the durable validation entry point for development
checkpoints and release candidates. It supplements the fast
`scripts/dev-check.sh` workflow with resumable execution, exact-commit
validation, private evidence, and tamper detection.

## Guarantees

Every run:

- binds its evidence to the exact Git commit, Git tree, framework version,
  validation profile, and ordered test plan;
- writes an atomic `state.json` ledger and `events.jsonl` event stream;
- records every command, timestamp, exit code, and combined output in a
  separate step log;
- creates evidence with directories mode `0700` and files mode `0600`;
- prevents concurrent execution through a host-and-process lock;
- fails closed when a required tool, candidate ref, clean tree, checkpoint, or
  test result is missing or inconsistent;
- resumes only on the same commit, tree, version, profile, and test plan;
- verifies the hashes of passed-step logs before skipping them; and
- produces `MANIFEST.sha256` covering every evidence file.

The harness does not turn a failed or interrupted step into a pass. A resume
reruns that step and preserves the previous state transitions in the event
stream. Changing the source, candidate commit, test plan, or completed evidence
requires a new run.

## Development profile

Use the development profile for ordinary checkpoints:

```bash
./scripts/qa-harness.py \
  --profile development \
  --authorization "Local development validation for issue NUMBER"
```

The development profile runs the Python suite, plugin contracts, CLI smoke
tests, shell syntax, repository and executable-mode checks, Markdown links,
credential-pattern review, version consistency, and all plugin lifecycle
dry-runs. It uses ShellCheck when available and records its absence. A dirty
worktree is rejected by default; `--allow-dirty` is available only for local
development while preparing a commit.

## Release profile

Run the release profile only from the exact clean candidate:

```bash
./scripts/qa-harness.py \
  --profile release \
  --candidate-ref origin/main \
  --authorization "Owner-authorized vX.Y.Z release validation"
```

The release profile additionally:

- requires ShellCheck rather than skipping it;
- forbids the dirty-tree override;
- requires authenticated GitHub CLI access;
- verifies all seven CI jobs and both CodeQL analyses on the exact candidate
  commit;
- creates Git tar and ZIP source archives;
- proves their extracted contents are identical and contain no Git metadata;
  and
- runs the complete Python suite and plugin-contract validation independently
  from both extracted archives.

This automated profile is one release gate. It does not replace controlled live
Debian testing, publication verification, or administrative closeout.

## Resume after interruption

The failure message prints the exact resume command. It has this form:

```bash
./scripts/qa-harness.py \
  --profile release \
  --resume ~/OSINT-Forge-QA/runs/RUN-ID
```

On resume, every passed step is skipped only after its evidence hash is
verified. Failed, interrupted, or incomplete steps run again. If the repository
or plan changed, start a new run instead.

## Verify retained evidence

Verify a completed or failed run at any later time:

```bash
./scripts/qa-harness.py \
  --verify ~/OSINT-Forge-QA/runs/RUN-ID
```

Verification fails for a changed, missing, or unmanifested evidence file.
Store completed evidence outside the source tree. If it is archived elsewhere,
retain the entire run directory and independently record the archive hash.

## Evidence layout

```text
RUN-ID/
├── MANIFEST.sha256
├── events.jsonl
├── logs/
│   └── NN-step-name.log
├── state.json
└── dry-run-state/
```

`state.json` is the machine-readable conclusion. A valid release-gate result
requires `"status": "passed"`, a matching candidate commit, and a successful
manifest verification.
