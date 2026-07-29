# Command Reference

OSINT Forge has four command families: framework management, single-adapter
execution, batch execution, and durable case management.

## Global and framework management

```bash
osint --help
osint --version
osint forge list [--installed | --available] [--json]
osint forge search QUERY
osint forge info TOOL
osint forge categories
osint forge install TOOL... [--dry-run]
osint forge update TOOL... [--dry-run]
osint forge remove TOOL... [--dry-run]
osint forge doctor [TOOL...]
osint forge validate [--json]
osint forge version
```

## Run one adapter

```bash
osint run PLUGIN {email,username,domain,ip,image,file} TARGET \
  [--output PATH] [--dry-run]
```

## Batch processing

```bash
osint batch [INPUT] [--name NAME] [--output-root PATH] \
  [--plugins TOOL...] [--jobs 1-8] [--dry-run]
```

The default input is `~/.config/osint-forge/targets.txt`. See
[[Batch Workflows]].

## Case management

```bash
osint case create CASE --purpose TEXT --authorization TEXT
osint case add CASE {domain,email,file,image,ip,username} TARGET
osint case run CASE [--plugins TOOL...] [--jobs 1-8] [--rerun] [--dry-run]
osint case status CASE [--json]
osint case findings CASE [--json]
osint case annotate CASE FINDING \
  [--confidence {unverified,low,medium,high}] \
  [--note TEXT | --clear-note]
osint case report CASE \
  [--format {markdown,json,html,csv,all}] \
  [--shareable] [--output PATH] [--force]
```

`--output` applies to one report format. Default report files can be
regenerated; custom files require `--force` to replace. Report paths must stay
inside the case and cannot use reserved or symbolic-link paths.

## Exit behavior

Commands return nonzero for validation failures, unknown tools, failed
lifecycle operations, malformed or inconsistent case data, failed jobs, and
normalization errors. A report with a normalization error is written with the
error preserved before the command returns nonzero.

See [[Case Management]] and [[Normalized Reporting]].
