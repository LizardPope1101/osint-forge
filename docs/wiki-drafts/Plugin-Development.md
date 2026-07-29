# Plugin Development

Tool-specific behavior belongs in a self-contained plugin.

```text
plugins/<tool>/
├── manifest.json
├── install.sh
├── update.sh
├── remove.sh
├── doctor.sh
└── normalize.py
```

## Contract requirements

A manifest declares identity, version, description, category, tags, upstream
project and license, supported targets, commands, lifecycle scripts, root
requirements, batch capability, argument-array adapters, and a normalizer for
every batch-capable plugin.

- IDs match directory names.
- Plugin-owned paths cannot escape the plugin directory or use symbolic links.
- Adapter commands are arrays, never interpolated shell text.
- Every batch-supported target requires an adapter.
- Every batch plugin declares an existing normalizer.
- Invalid contracts are rejected during catalog loading.

## Normalizers

Core invokes `normalize.py` with the raw-output directory for one completed
job. It must read evidence without modifying it, use no network access, and
emit deterministic contract JSON to standard output.

Normalizers use only the Python standard library, reject oversized or unsafe
sources, sort findings consistently, and fail nonzero for required malformed
or missing structured output. Core adds IDs, target, command, timestamps,
version, run, outcome, confidence, notes, and raw provenance.

Changes require synthetic positive, negative, malformed, missing, and path
safety fixtures where applicable.

## Validation

```bash
osint forge validate
osint forge validate --json
./scripts/dev-check.sh
```

Exercise installation and real output in a disposable supported environment
before release. See the canonical
[Plugin API](https://github.com/LizardPope1101/osint-forge/blob/main/docs/PLUGIN-API.md).
