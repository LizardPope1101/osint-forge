#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable

__version__ = "0.2.0-dev"

SYSTEM_ROOT = Path("/usr/local/share/osint-forge")
STATE_ROOT = Path.home() / ".local/state/osint-forge"
CONFIG_ROOT = Path("/etc/osint-forge")
SOURCE_ROOT = Path(__file__).resolve().parents[1]

EMAIL_RE = re.compile(r"^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63}$", re.I)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Z0-9](?:[A-Z0-9\-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}$", re.I)
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
USERNAME_RE = re.compile(r"^[^\s/@]{1,128}$")
TARGET_TYPES = {"email", "username", "domain", "ip", "image", "file"}
ADAPTER_PLACEHOLDERS = {"{target}", "{output_dir}", "{plugin_dir}"}


def forge_root() -> Path:
    override = os.environ.get("OSINT_FORGE_ROOT")
    if override:
        return Path(override).expanduser().resolve()
    if SYSTEM_ROOT.exists():
        return SYSTEM_ROOT
    return SOURCE_ROOT


def state_root() -> Path:
    override = os.environ.get("OSINT_FORGE_STATE")
    return Path(override).expanduser().resolve() if override else STATE_ROOT


def plugin_root() -> Path:
    return forge_root() / "plugins"


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def load_manifest(plugin_dir: Path) -> dict[str, Any]:
    path = plugin_dir / "manifest.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RuntimeError(f"Missing manifest: {path}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {path}: {exc}") from exc

    required = {"schema", "id", "name", "description", "category", "lifecycle", "commands", "supports"}
    missing = sorted(required - set(data))
    if missing:
        raise RuntimeError(f"{path}: missing fields: {', '.join(missing)}")
    if data["id"] != plugin_dir.name:
        raise RuntimeError(f"{path}: id must match directory name")
    return data


def catalog() -> dict[str, tuple[Path, dict[str, Any]]]:
    result: dict[str, tuple[Path, dict[str, Any]]] = {}
    if not plugin_root().exists():
        return result
    for directory in sorted(plugin_root().iterdir()):
        if not directory.is_dir() or not (directory / "manifest.json").exists():
            continue
        manifest = load_manifest(directory)
        result[manifest["id"]] = (directory, manifest)
    return result


def validate_plugin_directory(plugin_dir: Path) -> tuple[list[str], list[str]]:
    """Return manifest errors and warnings without executing plugin code."""
    errors: list[str] = []
    warnings: list[str] = []
    path = plugin_dir / "manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return ([f"{plugin_dir.name}: missing manifest.json"], warnings)
    except json.JSONDecodeError as exc:
        return ([f"{plugin_dir.name}: invalid JSON: {exc}"], warnings)

    required = {
        "schema", "plugin_version", "id", "name", "description", "category",
        "homepage", "upstream_license", "upstream_license_url", "commands",
        "supports", "batch", "lifecycle", "requires_root", "adapters",
    }
    missing = sorted(required - set(manifest))
    if missing:
        errors.append(f"{plugin_dir.name}: missing fields: {', '.join(missing)}")

    plugin_id = manifest.get("id")
    if plugin_id != plugin_dir.name:
        errors.append(
            f"{plugin_dir.name}: manifest id {plugin_id!r} must match directory name"
        )
    if manifest.get("schema") != 1:
        errors.append(f"{plugin_dir.name}: unsupported schema {manifest.get('schema')!r}")

    for field in ("name", "description", "category", "homepage",
                  "upstream_license", "upstream_license_url"):
        if field in manifest and not isinstance(manifest[field], str):
            errors.append(f"{plugin_dir.name}: {field} must be a string")

    commands = manifest.get("commands")
    if not isinstance(commands, list) or not commands or not all(
        isinstance(item, str) and item for item in commands
    ):
        errors.append(f"{plugin_dir.name}: commands must be a non-empty string array")

    supports = manifest.get("supports")
    if not isinstance(supports, list) or not all(isinstance(item, str) for item in supports):
        errors.append(f"{plugin_dir.name}: supports must be a string array")
        supports = []
    unknown_targets = sorted(set(supports) - TARGET_TYPES)
    if unknown_targets:
        errors.append(
            f"{plugin_dir.name}: unsupported target types: {', '.join(unknown_targets)}"
        )

    if not isinstance(manifest.get("batch"), bool):
        errors.append(f"{plugin_dir.name}: batch must be true or false")

    lifecycle = manifest.get("lifecycle")
    root_map = manifest.get("requires_root")
    if not isinstance(lifecycle, dict):
        errors.append(f"{plugin_dir.name}: lifecycle must be an object")
        lifecycle = {}
    if not isinstance(root_map, dict):
        errors.append(f"{plugin_dir.name}: requires_root must be an object")
        root_map = {}
    for action in ("install", "update", "remove", "doctor"):
        rel = lifecycle.get(action)
        if not isinstance(rel, str) or not rel:
            errors.append(f"{plugin_dir.name}: lifecycle.{action} must name a script")
        else:
            script = plugin_dir / rel
            if not script.is_file():
                errors.append(f"{plugin_dir.name}: missing lifecycle script {rel}")
            elif not os.access(script, os.X_OK):
                errors.append(f"{plugin_dir.name}: lifecycle script is not executable: {rel}")
        if action not in root_map or not isinstance(root_map.get(action), bool):
            errors.append(f"{plugin_dir.name}: requires_root.{action} must be boolean")

    adapters = manifest.get("adapters")
    if not isinstance(adapters, dict):
        errors.append(f"{plugin_dir.name}: adapters must be an object")
        adapters = {}
    for target_type, adapter in adapters.items():
        if target_type not in TARGET_TYPES:
            errors.append(f"{plugin_dir.name}: adapter has unknown target type {target_type}")
        if target_type not in supports:
            errors.append(f"{plugin_dir.name}: adapter {target_type} is not listed in supports")
        command = adapter.get("command") if isinstance(adapter, dict) else None
        if not isinstance(command, list) or not command or not all(
            isinstance(token, str) and token for token in command
        ):
            errors.append(
                f"{plugin_dir.name}: adapter {target_type} command must be a non-empty string array"
            )
            continue
        placeholders = {
            match
            for token in command
            for match in re.findall(r"\{[^{}]+\}", token)
        }
        unsupported = sorted(placeholders - ADAPTER_PLACEHOLDERS)
        if unsupported:
            errors.append(
                f"{plugin_dir.name}: adapter {target_type} uses unsupported placeholders: "
                + ", ".join(unsupported)
            )
        if "{target}" not in " ".join(command):
            warnings.append(f"{plugin_dir.name}: adapter {target_type} does not use {{target}}")

    if manifest.get("batch") and not adapters:
        errors.append(f"{plugin_dir.name}: batch plugin must define at least one adapter")
    return errors, warnings


def record_path(plugin_id: str) -> Path:
    return state_root() / "installed" / f"{plugin_id}.json"


def installed_record(plugin_id: str) -> dict[str, Any] | None:
    path = record_path(plugin_id)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def is_installed(plugin_id: str) -> bool:
    rec = installed_record(plugin_id)
    if rec is not None:
        return True
    entry = catalog().get(plugin_id)
    if not entry:
        return False
    _, manifest = entry
    return bool(manifest["commands"]) and all(shutil.which(c) for c in manifest["commands"])


def save_record(plugin_id: str, manifest: dict[str, Any], action: str) -> None:
    path = record_path(plugin_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    prior = installed_record(plugin_id) or {}
    data = {
        "plugin": plugin_id,
        "name": manifest["name"],
        "installed_at": prior.get("installed_at", now()),
        "updated_at": now(),
        "last_action": action,
        "manifest_version": manifest.get("plugin_version", "1"),
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def remove_record(plugin_id: str) -> None:
    record_path(plugin_id).unlink(missing_ok=True)


def require_plugin(plugin_id: str) -> tuple[Path, dict[str, Any]]:
    try:
        return catalog()[plugin_id]
    except KeyError:
        raise SystemExit(f"Unknown plugin: {plugin_id}. Use 'osint forge search <term>'.")


def lifecycle_script(plugin_dir: Path, manifest: dict[str, Any], action: str) -> Path:
    rel = manifest["lifecycle"].get(action)
    if not rel:
        raise SystemExit(f"{manifest['id']} does not define '{action}'.")
    path = plugin_dir / rel
    if not path.exists():
        raise SystemExit(f"Missing lifecycle script: {path}")
    return path


def run_lifecycle(
    plugin_id: str,
    action: str,
    *,
    dry_run: bool = False,
    assume_yes: bool = False,
) -> int:
    plugin_dir, manifest = require_plugin(plugin_id)
    script = lifecycle_script(plugin_dir, manifest, action)
    env = {
        **os.environ,
        "OSINT_FORGE_PLUGIN_ID": plugin_id,
        "OSINT_FORGE_PLUGIN_DIR": str(plugin_dir),
        "OSINT_FORGE_ROOT": str(forge_root()),
        "OSINT_FORGE_STATE": str(state_root()),
        "OSINT_FORGE_DRY_RUN": "1" if dry_run else "0",
        "OSINT_FORGE_ASSUME_YES": "1" if assume_yes else "0",
    }
    cmd = [str(script)]
    needs_root = bool(manifest.get("requires_root", {}).get(action, False))
    if needs_root and os.geteuid() != 0 and not dry_run:
        if not shutil.which("sudo"):
            raise SystemExit(f"{plugin_id} {action} requires root and sudo is unavailable.")
        cmd.insert(0, "sudo")
        # Preserve only Forge variables explicitly.
        cmd[1:1] = ["--preserve-env=OSINT_FORGE_PLUGIN_ID,OSINT_FORGE_PLUGIN_DIR,OSINT_FORGE_ROOT,OSINT_FORGE_STATE,OSINT_FORGE_DRY_RUN,OSINT_FORGE_ASSUME_YES"]

    print(f"{action.upper():8} {plugin_id}: {shlex.join(cmd)}")
    completed = subprocess.run(cmd, env=env, check=False)
    if completed.returncode == 0 and not dry_run:
        if action in {"install", "update"}:
            save_record(plugin_id, manifest, action)
        elif action == "remove":
            remove_record(plugin_id)
    return completed.returncode


def expand_selection(values: Iterable[str]) -> list[str]:
    cat = catalog()
    chosen: list[str] = []
    for value in values:
        if value in cat:
            ids = [value]
        else:
            ids = [pid for pid, (_, m) in cat.items() if m["category"] == value or value in m.get("tags", [])]
            if not ids:
                raise SystemExit(f"No plugin or category named '{value}'.")
        for pid in ids:
            if pid not in chosen:
                chosen.append(pid)
    return chosen


def cmd_list(args: argparse.Namespace) -> int:
    entries = catalog()
    if not entries:
        print("No plugins found.")
        return 1

    rows = []
    for pid, (_, m) in entries.items():
        installed = is_installed(pid)
        if args.installed and not installed:
            continue
        if args.available and installed:
            continue
        rows.append((pid, m["category"], "installed" if installed else "available", m["description"]))

    if args.json:
        print(json.dumps([
            {"id": a, "category": b, "status": c, "description": d}
            for a, b, c, d in rows
        ], indent=2))
        return 0

    width = max([len(r[0]) for r in rows] + [4])
    for pid, category, status, description in rows:
        mark = "✓" if status == "installed" else " "
        print(f"{mark} {pid:<{width}}  {category:<15} {status:<10} {description}")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    terms = [t.casefold() for t in args.terms]
    matches = []
    for pid, (_, m) in catalog().items():
        haystack = " ".join([
            pid, m["name"], m["description"], m["category"],
            *m.get("tags", []), *m.get("supports", []), *m.get("commands", [])
        ]).casefold()
        if all(term in haystack for term in terms):
            matches.append(pid)
    if not matches:
        print("No matching plugins.")
        return 1
    return cmd_list(argparse.Namespace(installed=False, available=False, json=False, _selection=matches)) if False else _print_ids(matches)


def _print_ids(ids: list[str]) -> int:
    cat = catalog()
    width = max(len(i) for i in ids)
    for pid in ids:
        _, m = cat[pid]
        status = "installed" if is_installed(pid) else "available"
        print(f"{pid:<{width}}  {m['category']:<15} {status:<10} {m['description']}")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    _, m = require_plugin(args.plugin)
    data = dict(m)
    data["status"] = "installed" if is_installed(args.plugin) else "available"
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    print(f"{m['name']} ({m['id']})")
    print(f"Status:      {data['status']}")
    print(f"Category:    {m['category']}")
    print(f"Description: {m['description']}")
    print(f"Homepage:    {m.get('homepage', '-')}")
    print(f"Commands:    {', '.join(m['commands']) or '-'}")
    print(f"Supports:    {', '.join(m['supports']) or '-'}")
    print(f"Batch:       {'yes' if m.get('batch', False) else 'no'}")
    notes = m.get("notes")
    if notes:
        print(f"Notes:       {notes}")
    return 0


def action_many(args: argparse.Namespace, action: str) -> int:
    plugins = expand_selection(args.selection)
    failures = 0
    for pid in plugins:
        if action == "install" and is_installed(pid) and not args.force:
            print(f"SKIP     {pid}: already installed")
            continue
        if action in {"update", "remove"} and not is_installed(pid) and not args.force:
            print(f"SKIP     {pid}: not installed")
            continue
        failures += run_lifecycle(pid, action, dry_run=args.dry_run, assume_yes=args.yes) != 0
    return 1 if failures else 0


def cmd_doctor(args: argparse.Namespace) -> int:
    ids = expand_selection(args.selection) if args.selection else [
        pid for pid in catalog() if is_installed(pid)
    ]
    if not ids:
        print("No installed plugins to check.")
        return 0
    failures = 0
    for pid in ids:
        plugin_dir, manifest = require_plugin(pid)
        if not manifest["lifecycle"].get("doctor"):
            print(f"SKIP     {pid}: no doctor check")
            continue
        rc = run_lifecycle(pid, "doctor", dry_run=False)
        failures += rc != 0
    return 1 if failures else 0


def validate_target(target_type: str, value: str) -> bool:
    if target_type == "email":
        return bool(EMAIL_RE.fullmatch(value))
    if target_type == "username":
        return bool(USERNAME_RE.fullmatch(value))
    if target_type == "domain":
        return bool(DOMAIN_RE.fullmatch(value))
    if target_type == "ip":
        if not IP_RE.fullmatch(value):
            return False
        return all(0 <= int(part) <= 255 for part in value.split("."))
    if target_type in {"image", "file"}:
        return Path(value).expanduser().is_file()
    return bool(value.strip())


def adapter_command(
    plugin_dir: Path,
    manifest: dict[str, Any],
    target_type: str,
    value: str,
    output_dir: Path,
) -> list[str]:
    adapters = manifest.get("adapters", {})
    adapter = adapters.get(target_type)
    if not adapter:
        raise SystemExit(f"{manifest['id']} does not support target type '{target_type}'.")
    command = adapter.get("command")
    if not isinstance(command, list) or not command:
        raise SystemExit(f"{manifest['id']}: invalid adapter command.")
    mapping = {
        "{target}": value,
        "{output_dir}": str(output_dir),
        "{plugin_dir}": str(plugin_dir),
    }
    result = []
    for token in command:
        for key, replacement in mapping.items():
            token = token.replace(key, replacement)
        result.append(token)
    return result


def run_adapter(plugin_id: str, target_type: str, value: str, output_dir: Path, dry_run: bool) -> int:
    plugin_dir, manifest = require_plugin(plugin_id)
    if not is_installed(plugin_id) and not dry_run:
        print(f"MISS     {plugin_id}: not installed", file=sys.stderr)
        return 127
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = adapter_command(plugin_dir, manifest, target_type, value, output_dir)
    if dry_run:
        print(f"DRY      {plugin_id}: {shlex.join(cmd)}")
        return 0
    print(f"RUN      {plugin_id}: {target_type}={value}")
    with (output_dir / "stdout.log").open("w", encoding="utf-8") as out, \
         (output_dir / "stderr.log").open("w", encoding="utf-8") as err:
        completed = subprocess.run(cmd, cwd=output_dir, stdout=out, stderr=err, check=False)
    status = {
        "plugin": plugin_id,
        "target_type": target_type,
        "target": value,
        "command": cmd,
        "exit_code": completed.returncode,
        "completed_at": now(),
    }
    (output_dir / "status.json").write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    return completed.returncode


def cmd_run(args: argparse.Namespace) -> int:
    if not validate_target(args.type, args.target):
        raise SystemExit(f"Invalid {args.type}: {args.target}")
    output = args.output.expanduser().resolve()
    return run_adapter(args.plugin, args.type, args.target, output, args.dry_run)


def parse_batch_file(path: Path) -> list[tuple[str, str]]:
    aliases = {
        "email": "email", "emails": "email",
        "username": "username", "usernames": "username", "handles": "username",
        "domain": "domain", "domains": "domain",
        "ip": "ip", "ips": "ip", "addresses": "ip",
        "image": "image", "images": "image",
        "file": "file", "files": "file",
    }
    current = None
    result = []
    seen = set()
    for lineno, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = aliases.get(line[1:-1].strip().casefold())
            if current is None:
                raise SystemExit(f"{path}:{lineno}: unknown section")
            continue
        if current is None:
            raise SystemExit(f"{path}:{lineno}: target before section")
        value = re.split(r"\s+[;#]", line, maxsplit=1)[0].strip()
        if current in {"image", "file"}:
            p = Path(value).expanduser()
            if not p.is_absolute():
                p = (path.parent / p).resolve()
            value = str(p)
        if not validate_target(current, value):
            raise SystemExit(f"{path}:{lineno}: invalid {current}: {value}")
        key = (current, value.casefold())
        if key not in seen:
            seen.add(key)
            result.append((current, value))
    return result


def safe_slug(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._@+-]+", "_", value).strip("._")[:80] or "target"
    digest = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"{clean}--{digest}"


def cmd_batch(args: argparse.Namespace) -> int:
    source = args.input.expanduser().resolve()
    targets = parse_batch_file(source)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = args.output_root.expanduser().resolve() / f"{stamp}-{safe_slug(args.name).rsplit('--',1)[0]}"
    run_dir.mkdir(parents=True)
    shutil.copy2(source, run_dir / "targets-input.txt")

    cat = catalog()
    jobs = []
    for target_type, value in targets:
        for pid, (_, manifest) in cat.items():
            if not manifest.get("batch", False) or target_type not in manifest.get("supports", []):
                continue
            if args.plugins and pid not in args.plugins:
                continue
            if not is_installed(pid):
                continue
            out = run_dir / f"{target_type}s" / safe_slug(value) / pid
            jobs.append((pid, target_type, value, out))

    print(f"Run directory: {run_dir}")
    print(f"Targets: {len(targets)} | Jobs: {len(jobs)} | Concurrency: {args.jobs}")
    if not jobs:
        print("No installed batch-capable plugins matched these target sections.", file=sys.stderr)
        return 1

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [
            pool.submit(run_adapter, pid, typ, value, out, args.dry_run)
            for pid, typ, value, out in jobs
        ]
        for job, future in zip(jobs, futures):
            results.append((*job[:3], future.result()))

    summary = {
        "created_at": now(),
        "input": str(source),
        "run_directory": str(run_dir),
        "target_count": len(targets),
        "job_count": len(jobs),
        "results": [
            {"plugin": p, "type": t, "target": v, "exit_code": rc}
            for p, t, v, rc in results
        ],
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    failures = sum(rc != 0 for *_, rc in results)
    print(f"Completed with {failures} failed job(s).")
    return 1 if failures else 0


def cmd_categories(args: argparse.Namespace) -> int:
    groups: dict[str, list[str]] = {}
    for pid, (_, m) in catalog().items():
        groups.setdefault(m["category"], []).append(pid)
    for category in sorted(groups):
        print(f"{category}: {', '.join(sorted(groups[category]))}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    directories = [
        directory
        for directory in sorted(plugin_root().iterdir())
        if directory.is_dir()
    ] if plugin_root().exists() else []
    errors: list[str] = []
    warnings: list[str] = []
    if not directories:
        errors.append("no plugin directories found")
    for directory in directories:
        plugin_errors, plugin_warnings = validate_plugin_directory(directory)
        errors.extend(plugin_errors)
        warnings.extend(plugin_warnings)

    payload = {
        "plugin_count": len(directories),
        "errors": errors,
        "warnings": warnings,
        "valid": not errors,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for warning in warnings:
            print(f"WARN     {warning}")
        for error in errors:
            print(f"ERROR    {error}", file=sys.stderr)
        status = "valid" if not errors else "invalid"
        print(
            f"Validated {len(directories)} plugin(s): "
            f"{len(errors)} error(s), {len(warnings)} warning(s) — {status}"
        )
    return 1 if errors else 0


def cmd_version(args: argparse.Namespace) -> int:
    print(f"OSINT Forge {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="osint", description="OSINT Forge modular tool manager")
    parser.add_argument("--version", action="version", version=f"OSINT Forge {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    forge = sub.add_parser("forge", help="manage OSINT Forge tools")
    fs = forge.add_subparsers(dest="forge_command", required=True)

    p = fs.add_parser("list")
    p.add_argument("--installed", action="store_true")
    p.add_argument("--available", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list)

    p = fs.add_parser("search")
    p.add_argument("terms", nargs="+")
    p.set_defaults(func=cmd_search)

    p = fs.add_parser("info")
    p.add_argument("plugin")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_info)

    for action in ("install", "update", "remove"):
        p = fs.add_parser(action)
        p.add_argument("selection", nargs="+", help="plugin IDs, categories, or tags")
        p.add_argument("-n", "--dry-run", action="store_true")
        p.add_argument("-y", "--yes", action="store_true")
        p.add_argument("--force", action="store_true")
        p.set_defaults(func=lambda a, x=action: action_many(a, x))

    p = fs.add_parser("doctor")
    p.add_argument("selection", nargs="*")
    p.set_defaults(func=cmd_doctor)

    p = fs.add_parser("categories")
    p.set_defaults(func=cmd_categories)

    p = fs.add_parser("validate", help="validate every plugin manifest and lifecycle contract")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_validate)

    p = fs.add_parser("version", help="show the framework version")
    p.set_defaults(func=cmd_version)

    p = sub.add_parser("run", help="run one plugin adapter")
    p.add_argument("plugin")
    p.add_argument("type", choices=["email", "username", "domain", "ip", "image", "file"])
    p.add_argument("target")
    p.add_argument("-o", "--output", type=Path, default=Path.cwd() / "osint-output")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("batch", help="run every matching installed batch plugin")
    p.add_argument("input", type=Path, nargs="?", default=Path.home() / ".config/osint-forge/targets.txt")
    p.add_argument("--name", default="batch")
    p.add_argument("--output-root", type=Path, default=Path.home() / "OSINT-Cases" / "Batch-Runs")
    p.add_argument("--plugins", nargs="*", default=[])
    p.add_argument("--jobs", type=int, default=2, choices=range(1, 9), metavar="1-8")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_batch)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
