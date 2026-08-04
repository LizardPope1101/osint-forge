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

try:
    from . import entities, integrity, reporting, workflows
except ImportError:
    import entities
    import integrity
    import reporting
    import workflows

__version__ = "0.7.0"

SYSTEM_ROOT = Path("/usr/local/share/osint-forge")
STATE_ROOT = Path.home() / ".local/state/osint-forge"
CONFIG_ROOT = Path("/etc/osint-forge")
SOURCE_ROOT = Path(__file__).resolve().parents[1]
CASE_SCHEMA = 1
CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

EMAIL_RE = re.compile(r"^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63}$", re.I)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Z0-9](?:[A-Z0-9\-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}$", re.I)
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
USERNAME_RE = re.compile(r"^[^\s/@]{1,128}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9 .()\-]{5,30}[0-9]$")
TARGET_TYPES = {
    "address", "domain", "email", "file", "image", "ip", "name", "phone",
    "username",
}
ADAPTER_PLACEHOLDERS = {"{target}", "{output_dir}", "{plugin_dir}"}
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


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


def workflow_root() -> Path:
    return forge_root() / "workflows"


def resolve_workflow(reference: str) -> tuple[Path, dict[str, Any]]:
    """Load a named built-in profile or an explicit JSON workflow path."""
    requested = Path(reference).expanduser()
    if requested.name != reference or requested.suffix:
        path = requested.resolve()
    else:
        if not workflows.ID_RE.fullmatch(reference):
            raise SystemExit("Workflow names must use lowercase letters, numbers, and hyphens.")
        path = workflow_root() / f"{reference}.json"
    try:
        workflow = workflows.load_workflow(path)
    except workflows.WorkflowError as exc:
        raise SystemExit(str(exc)) from exc
    return path, workflow


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def write_private_json(path: Path, data: dict[str, Any]) -> None:
    """Atomically write JSON that may contain targets or execution metadata."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        temporary.replace(path)
        path.chmod(0o600)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def write_private_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        temporary.replace(path)
        path.chmod(0o600)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def secure_private_directory(path: Path, root: Path, context: str) -> None:
    if path != root and root not in path.parents:
        raise RuntimeError(f"Refusing {context} directory outside {root}: {path}")
    relative_parts = path.relative_to(root).parts
    current = root
    for part in ("", *relative_parts):
        if part:
            current = current / part
        if current.is_symlink():
            raise RuntimeError(f"Refusing symbolic-link {context} directory: {current}")
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            if not current.is_dir():
                raise RuntimeError(f"{context.capitalize()} path is not a directory: {current}")
        current.chmod(0o700)


def secure_case_directory(path: Path, root: Path) -> None:
    secure_private_directory(path, root, "case")


def safe_output_directory(requested: Path, context: str) -> Path:
    """Return an absolute output path without following symbolic links."""
    path = Path(os.path.abspath(requested.expanduser()))
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            raise RuntimeError(
                f"Refusing symbolic-link {context} directory: {current}"
            )
    return path


def open_private_log(path: Path):
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | NOFOLLOW,
        0o600,
    )
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "w", encoding="utf-8")


def cases_root() -> Path:
    override = os.environ.get("OSINT_FORGE_CASES")
    root = (
        Path(override).expanduser().resolve()
        if override
        else (Path.home() / "OSINT-Cases").resolve()
    )
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    return root


def validate_case_id(case_id: str) -> str:
    if not CASE_ID_RE.fullmatch(case_id):
        raise SystemExit(
            "Case IDs must be 1-64 characters using letters, numbers, '.', '_', "
            "or '-', and must start with a letter or number."
        )
    return case_id


def case_path(case_id: str, *, must_exist: bool = True) -> Path:
    validate_case_id(case_id)
    root = cases_root()
    path = root / case_id
    if path.is_symlink():
        raise SystemExit(f"Refusing symbolic-link case directory: {path}")
    if must_exist and not path.is_dir():
        raise SystemExit(f"Unknown case: {case_id}")
    return path


def append_case_activity(path: Path, event: str, **details: Any) -> None:
    log_path = path / "activity.jsonl"
    descriptor = os.open(
        log_path,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | NOFOLLOW,
        0o600,
    )
    os.fchmod(descriptor, 0o600)
    entry = {"timestamp": now(), "event": event, **details}
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def migrate_case(path: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    schema = metadata.get("schema", 0)
    if not isinstance(schema, int) or schema < 0:
        raise SystemExit(f"{path.name}: invalid case schema")
    if schema > CASE_SCHEMA:
        raise SystemExit(
            f"{path.name}: case schema {schema} is newer than supported schema "
            f"{CASE_SCHEMA}"
        )
    if schema == 0:
        metadata["schema"] = 1
        metadata.setdefault("targets", [])
        metadata.setdefault("jobs", {})
        metadata.setdefault("updated_at", now())
        write_private_json(path / "case.json", metadata)
        append_case_activity(path, "case_migrated", from_schema=0, to_schema=1)
    return metadata


def load_case(case_id: str) -> tuple[Path, dict[str, Any]]:
    path = case_path(case_id)
    metadata_path = path / "case.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"{case_id}: missing case.json")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{case_id}: invalid case.json: {exc}") from exc
    if not isinstance(metadata, dict):
        raise SystemExit(f"{case_id}: case.json must contain an object")
    metadata = migrate_case(path, metadata)
    required = {
        "schema", "id", "purpose", "authorization_scope", "created_at",
        "updated_at", "targets", "jobs",
    }
    missing = sorted(required - set(metadata))
    if missing:
        raise SystemExit(f"{case_id}: case metadata missing: {', '.join(missing)}")
    if metadata["id"] != case_id:
        raise SystemExit(f"{case_id}: case ID does not match its directory")
    text_fields = ("purpose", "authorization_scope", "created_at", "updated_at")
    if any(
        not isinstance(metadata[field], str) or not metadata[field].strip()
        for field in text_fields
    ):
        raise SystemExit(f"{case_id}: invalid case metadata text field")
    if not isinstance(metadata["targets"], list) or not isinstance(metadata["jobs"], dict):
        raise SystemExit(f"{case_id}: invalid targets or jobs collection")
    for target in metadata["targets"]:
        if (
            not isinstance(target, dict)
            or not isinstance(target.get("id"), str)
            or target.get("type") not in TARGET_TYPES
            or not isinstance(target.get("value"), str)
            or not isinstance(target.get("added_at"), str)
        ):
            raise SystemExit(f"{case_id}: invalid target record")
        if target["id"] != target_id(target["type"], target["value"]):
            raise SystemExit(f"{case_id}: target ID does not match its value")
    for job_id, state in metadata["jobs"].items():
        if (
            not isinstance(job_id, str)
            or not isinstance(state, dict)
            or not isinstance(state.get("status"), str)
        ):
            raise SystemExit(f"{case_id}: invalid job record")
        if "exit_code" in state and not isinstance(state["exit_code"], int):
            raise SystemExit(f"{case_id}: invalid job exit code")
    path.chmod(0o700)
    metadata_path.chmod(0o600)
    return path, metadata


def save_case(path: Path, metadata: dict[str, Any]) -> None:
    metadata["updated_at"] = now()
    write_private_json(path / "case.json", metadata)


def target_id(target_type: str, value: str) -> str:
    digest = hashlib.sha256(f"{target_type}\0{value}".encode()).hexdigest()[:16]
    return f"{target_type}-{digest}"


def case_job_id(plugin_id: str, target_type: str, value: str) -> str:
    digest = hashlib.sha256(
        f"{plugin_id}\0{target_type}\0{value}".encode()
    ).hexdigest()[:20]
    return f"{plugin_id}-{digest}"


def create_case_run_directory(path: Path) -> Path:
    runs = path / "runs"
    runs.mkdir(mode=0o700, exist_ok=True)
    runs.chmod(0o700)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for attempt in range(1000):
        name = stamp if attempt == 0 else f"{stamp}-{attempt}"
        candidate = runs / name
        try:
            candidate.mkdir(mode=0o700)
            return candidate
        except FileExistsError:
            continue
    raise RuntimeError(f"Could not allocate a run directory under {runs}")


def normalize_case_target(target_type: str, value: str) -> str:
    value = value.strip()
    if target_type in {"image", "file"}:
        value = str(Path(value).expanduser().resolve())
    elif target_type in {"name", "address"}:
        value = " ".join(value.split())
    elif target_type == "phone":
        prefix = "+" if value.startswith("+") else ""
        value = prefix + "".join(character for character in value if character.isdigit())
    if not validate_target(target_type, value):
        raise SystemExit(f"Invalid {target_type}: {value}")
    return value


def canonical_entity_value(target_type: str, value: str) -> str:
    """Return a stable comparison value without changing preserved evidence."""
    if target_type in {"email", "domain"}:
        return value.casefold().removesuffix(".")
    if target_type in {"name", "address"}:
        return " ".join(value.split()).casefold()
    if target_type == "phone":
        prefix = "+" if value.startswith("+") else ""
        return prefix + "".join(character for character in value if character.isdigit())
    return value


def load_manifest(plugin_dir: Path) -> dict[str, Any]:
    path = plugin_dir / "manifest.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RuntimeError(f"Missing manifest: {path}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise RuntimeError(f"{path}: manifest root must be an object")
    required = {"schema", "id", "name", "description", "category", "lifecycle", "commands", "supports"}
    missing = sorted(required - set(data))
    if missing:
        raise RuntimeError(f"{path}: missing fields: {', '.join(missing)}")
    if data["id"] != plugin_dir.name:
        raise RuntimeError(f"{path}: id must match directory name")
    errors, _ = validate_plugin_directory(plugin_dir)
    if errors:
        raise RuntimeError(f"{path}: invalid plugin contract: {'; '.join(errors)}")
    return data


def resolve_plugin_file(plugin_dir: Path, relative_path: str) -> Path:
    """Resolve a plugin-owned file and reject absolute paths or traversal."""
    relative = Path(relative_path)
    if relative.is_absolute():
        raise ValueError("path must be relative")
    root = plugin_dir.resolve()
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("path escapes the plugin directory")
    return candidate


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
    if manifest.get("schema") not in {1, 2}:
        errors.append(f"{plugin_dir.name}: unsupported schema {manifest.get('schema')!r}")
    if not isinstance(manifest.get("plugin_version"), str) or not manifest.get("plugin_version"):
        errors.append(f"{plugin_dir.name}: plugin_version must be a non-empty string")
    if not isinstance(plugin_id, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", plugin_id):
        errors.append(f"{plugin_dir.name}: id must use lowercase letters, numbers, and hyphens")

    for field in ("name", "description", "category", "homepage",
                  "upstream_license", "upstream_license_url"):
        if field in manifest and not isinstance(manifest[field], str):
            errors.append(f"{plugin_dir.name}: {field} must be a string")

    commands = manifest.get("commands")
    if not isinstance(commands, list) or not commands or not all(
        isinstance(item, str) and item for item in commands
    ):
        errors.append(f"{plugin_dir.name}: commands must be a non-empty string array")

    tags = manifest.get("tags", [])
    if not isinstance(tags, list) or not all(
        isinstance(item, str) and item for item in tags
    ):
        errors.append(f"{plugin_dir.name}: tags must be a string array")

    supports = manifest.get("supports")
    if not isinstance(supports, list) or not all(isinstance(item, str) for item in supports):
        errors.append(f"{plugin_dir.name}: supports must be a string array")
        supports = []
    unknown_targets = sorted(set(supports) - TARGET_TYPES)
    if unknown_targets:
        errors.append(
            f"{plugin_dir.name}: unsupported target types: {', '.join(unknown_targets)}"
        )

    if manifest.get("schema") == 2:
        entity_contract = manifest.get("entities")
        if not isinstance(entity_contract, dict):
            errors.append(f"{plugin_dir.name}: entities must be an object")
            entity_contract = {}
        accepted = entity_contract.get("accepted")
        emitted = entity_contract.get("emitted")
        valid_entity_fields = {}
        for field, values in (("accepted", accepted), ("emitted", emitted)):
            valid = (
                isinstance(values, list)
                and all(isinstance(item, str) for item in values)
                and values == sorted(set(values))
            )
            valid_entity_fields[field] = valid
            if not valid:
                errors.append(
                    f"{plugin_dir.name}: entities.{field} must be a sorted unique string array"
                )
        if valid_entity_fields["accepted"]:
            unknown = sorted(set(accepted) - TARGET_TYPES)
            if unknown:
                errors.append(
                    f"{plugin_dir.name}: unknown accepted entity types: {', '.join(unknown)}"
                )
            if accepted != sorted(set(supports)):
                errors.append(
                    f"{plugin_dir.name}: entities.accepted must match supports"
                )
        if valid_entity_fields["emitted"]:
            unknown = sorted(set(emitted) - TARGET_TYPES)
            if unknown:
                errors.append(
                    f"{plugin_dir.name}: unknown emitted entity types: {', '.join(unknown)}"
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
            try:
                script = resolve_plugin_file(plugin_dir, rel)
            except ValueError as exc:
                errors.append(f"{plugin_dir.name}: invalid lifecycle script {rel!r}: {exc}")
            else:
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
    if manifest.get("batch"):
        missing_adapters = sorted(set(supports) - set(adapters))
        if missing_adapters:
            errors.append(
                f"{plugin_dir.name}: batch plugin is missing adapters for: "
                + ", ".join(missing_adapters)
            )
        normalizer = manifest.get("normalizer")
        if not isinstance(normalizer, str) or not normalizer:
            errors.append(
                f"{plugin_dir.name}: batch plugin must define a normalizer"
            )
        else:
            try:
                normalizer_path = resolve_plugin_file(plugin_dir, normalizer)
            except ValueError as exc:
                errors.append(
                    f"{plugin_dir.name}: invalid normalizer {normalizer!r}: {exc}"
                )
            else:
                if normalizer_path.is_symlink():
                    errors.append(
                        f"{plugin_dir.name}: normalizer cannot be a symbolic link: "
                        f"{normalizer}"
                    )
                elif not normalizer_path.is_file():
                    errors.append(
                        f"{plugin_dir.name}: missing normalizer {normalizer}"
                    )
    return errors, warnings


def record_path(plugin_id: str) -> Path:
    return state_root() / "installed" / f"{plugin_id}.json"


def installed_record(plugin_id: str) -> dict[str, Any] | None:
    path = record_path(plugin_id)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def command_search_path() -> str:
    """Return PATH plus the standard per-user location used by pipx."""
    entries = os.environ.get("PATH", "").split(os.pathsep)
    user_bin = str(Path.home() / ".local/bin")
    if user_bin not in entries:
        entries.append(user_bin)
    return os.pathsep.join(entry for entry in entries if entry)


def command_exists(command: str) -> bool:
    return shutil.which(command, path=command_search_path()) is not None


def is_installed(plugin_id: str) -> bool:
    entry = catalog().get(plugin_id)
    if not entry:
        return False
    _, manifest = entry
    return bool(manifest["commands"]) and all(command_exists(c) for c in manifest["commands"])


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
    write_private_json(path, data)


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
    try:
        path = resolve_plugin_file(plugin_dir, rel)
    except ValueError as exc:
        raise SystemExit(f"Invalid lifecycle script for {manifest['id']}: {exc}") from exc
    if not path.is_file():
        raise SystemExit(f"Missing lifecycle script: {path}")
    if not os.access(path, os.X_OK):
        raise SystemExit(f"Lifecycle script is not executable: {path}")
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
        "PATH": command_search_path(),
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

    print(f"{action.upper():8} {plugin_id}: {shlex.join(cmd)}", flush=True)
    try:
        completed = subprocess.run(cmd, env=env, check=False)
    except OSError as exc:
        print(f"ERROR    {plugin_id}: could not start {action}: {exc}", file=sys.stderr)
        return 127 if isinstance(exc, FileNotFoundError) else 126
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
    return _print_ids(matches)


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
    entity_contract = m.get("entities", {})
    print(f"Accepts:     {', '.join(entity_contract.get('accepted', [])) or '-'}")
    print(f"Emits:       {', '.join(entity_contract.get('emitted', [])) or '-'}")
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
    if target_type == "phone":
        if not PHONE_RE.fullmatch(value):
            return False
        digits = "".join(character for character in value if character.isdigit())
        return 7 <= len(digits) <= 15
    if target_type == "name":
        return 1 <= len(value) <= 256 and not any(
            ord(character) < 32 for character in value
        )
    if target_type == "address":
        return 1 <= len(value) <= 512 and not any(
            ord(character) < 32 for character in value
        )
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


def run_adapter(
    plugin_id: str,
    target_type: str,
    value: str,
    output_dir: Path,
    dry_run: bool,
    timeout_seconds: int | None = None,
) -> int:
    plugin_dir, manifest = require_plugin(plugin_id)
    if not is_installed(plugin_id) and not dry_run:
        print(f"MISS     {plugin_id}: not installed", file=sys.stderr)
        return 127
    if output_dir.is_symlink():
        raise RuntimeError(f"Refusing symbolic-link output directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise RuntimeError(f"Output path is not a safe directory: {output_dir}")
    output_dir.chmod(0o700)
    cmd = adapter_command(plugin_dir, manifest, target_type, value, output_dir)
    if dry_run:
        print(f"DRY      {plugin_id}: {shlex.join(cmd)}")
        return 0
    print(f"RUN      {plugin_id}: {target_type}={value}")
    error = None
    with open_private_log(output_dir / "stdout.log") as out, \
         open_private_log(output_dir / "stderr.log") as err:
        try:
            env = {**os.environ, "PATH": command_search_path()}
            completed = subprocess.run(
                cmd,
                cwd=output_dir,
                stdout=out,
                stderr=err,
                env=env,
                umask=0o077,
                check=False,
                timeout=timeout_seconds,
            )
            exit_code = completed.returncode
        except subprocess.TimeoutExpired:
            error = f"adapter exceeded workflow timeout of {timeout_seconds} seconds"
            exit_code = 124
            print(f"ERROR: {error}", file=err)
        except OSError as exc:
            error = str(exc)
            exit_code = 127 if isinstance(exc, FileNotFoundError) else 126
            print(f"ERROR: could not start command: {exc}", file=err)
    status = {
        "plugin": plugin_id,
        "target_type": target_type,
        "target": value,
        "command": cmd,
        "exit_code": exit_code,
        "completed_at": now(),
    }
    if error is not None:
        status["error"] = error
    write_private_json(output_dir / "status.json", status)
    return exit_code


def cmd_run(args: argparse.Namespace) -> int:
    if not validate_target(args.type, args.target):
        raise SystemExit(f"Invalid {args.type}: {args.target}")
    output = safe_output_directory(args.output, "output")
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
    try:
        content = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError as exc:
        raise SystemExit(f"Batch input does not exist: {path}") from exc
    except UnicodeError as exc:
        raise SystemExit(f"Batch input is not valid UTF-8: {path}") from exc
    except OSError as exc:
        raise SystemExit(f"Could not read batch input {path}: {exc}") from exc
    for lineno, raw in enumerate(content.splitlines(), 1):
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


def create_run_directory(output_root: Path, name: str, stamp: str | None = None) -> Path:
    """Create a unique batch directory, even for runs started simultaneously."""
    output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_root.chmod(0o700)
    timestamp = stamp or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    label = safe_slug(name).rsplit("--", 1)[0]
    base = output_root / f"{timestamp}-{label}"
    for attempt in range(1000):
        candidate = base if attempt == 0 else output_root / f"{base.name}-{attempt}"
        try:
            candidate.mkdir(mode=0o700)
            return candidate
        except FileExistsError:
            continue
    raise RuntimeError(f"Could not allocate a unique batch directory under {output_root}")


def cmd_batch(args: argparse.Namespace) -> int:
    source = args.input.expanduser().resolve()
    targets = parse_batch_file(source)
    cat = catalog()
    unknown_plugins = sorted(set(args.plugins) - set(cat))
    if unknown_plugins:
        raise SystemExit(f"Unknown batch plugin(s): {', '.join(unknown_plugins)}")
    jobs = []
    for target_type, value in targets:
        for pid, (_, manifest) in cat.items():
            if not manifest.get("batch", False) or target_type not in manifest.get("supports", []):
                continue
            if args.plugins and pid not in args.plugins:
                continue
            if not is_installed(pid):
                continue
            jobs.append((pid, target_type, value))
    if not jobs:
        print("No installed batch-capable plugins matched these target sections.", file=sys.stderr)
        return 1
    output_root = safe_output_directory(args.output_root, "batch output")
    run_dir = create_run_directory(output_root, args.name)
    copied_input = run_dir / "targets-input.txt"
    shutil.copy2(source, copied_input)
    copied_input.chmod(0o600)
    scheduled = [
        (pid, target_type, value, run_dir / f"{target_type}s" / safe_slug(value) / pid)
        for pid, target_type, value in jobs
    ]
    for *_, output in scheduled:
        secure_private_directory(output, run_dir, "batch")

    print(f"Run directory: {run_dir}")
    print(f"Targets: {len(targets)} | Jobs: {len(scheduled)} | Concurrency: {args.jobs}")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        future_jobs = {
            pool.submit(run_adapter, pid, typ, value, out, args.dry_run):
                (pid, typ, value)
            for pid, typ, value, out in scheduled
        }
        for future in concurrent.futures.as_completed(future_jobs):
            results.append((*future_jobs[future], future.result()))
    results.sort(key=lambda item: item[:3])

    summary = {
        "created_at": now(),
        "input": str(source),
        "run_directory": str(run_dir),
        "target_count": len(targets),
        "job_count": len(scheduled),
        "results": [
            {"plugin": p, "type": t, "target": v, "exit_code": rc}
            for p, t, v, rc in results
        ],
    }
    write_private_json(run_dir / "summary.json", summary)
    failures = sum(rc != 0 for *_, rc in results)
    print(f"Completed with {failures} failed job(s).")
    return 1 if failures else 0


def cmd_case_create(args: argparse.Namespace) -> int:
    validate_case_id(args.case)
    path = case_path(args.case, must_exist=False)
    if path.exists():
        raise SystemExit(f"Case already exists: {args.case}")
    path.mkdir(mode=0o700)
    for directory in ("runs", "notes", "findings"):
        (path / directory).mkdir(mode=0o700)
    timestamp = now()
    metadata = {
        "schema": CASE_SCHEMA,
        "id": args.case,
        "purpose": args.purpose.strip(),
        "authorization_scope": args.authorization.strip(),
        "created_at": timestamp,
        "updated_at": timestamp,
        "targets": [],
        "jobs": {},
    }
    if not metadata["purpose"] or not metadata["authorization_scope"]:
        shutil.rmtree(path)
        raise SystemExit("Purpose and authorization scope cannot be empty.")
    write_private_json(path / "case.json", metadata)
    append_case_activity(
        path,
        "case_created",
        purpose=metadata["purpose"],
        authorization_scope=metadata["authorization_scope"],
        schema=CASE_SCHEMA,
    )
    print(f"Created case: {args.case}")
    print(f"Location: {path}")
    return 0


def cmd_case_add(args: argparse.Namespace) -> int:
    path, metadata = load_case(args.case)
    value = normalize_case_target(args.type, args.target)
    identifier = target_id(args.type, value)
    if any(target.get("id") == identifier for target in metadata["targets"]):
        print(f"SKIP     {args.type}: target already exists in {args.case}")
        return 0
    target = {
        "id": identifier,
        "type": args.type,
        "value": value,
        "added_at": now(),
    }
    metadata["targets"].append(target)
    save_case(path, metadata)
    append_case_activity(
        path,
        "target_added",
        target_id=identifier,
        target_type=args.type,
    )
    print(f"Added {args.type} target to {args.case}: {value}")
    return 0


def case_jobs(
    metadata: dict[str, Any],
    requested_plugins: list[str],
    *,
    include_uninstalled: bool,
) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    cat = catalog()
    unknown = sorted(set(requested_plugins) - set(cat))
    if unknown:
        raise SystemExit(f"Unknown case plugin(s): {', '.join(unknown)}")
    jobs = []
    for target in metadata["targets"]:
        for plugin_id, (_, manifest) in cat.items():
            if requested_plugins and plugin_id not in requested_plugins:
                continue
            if not manifest.get("batch", False):
                continue
            if target["type"] not in manifest.get("supports", []):
                continue
            if not include_uninstalled and not is_installed(plugin_id):
                continue
            jobs.append((plugin_id, manifest, target))
    return jobs


def cmd_case_run(args: argparse.Namespace) -> int:
    path, metadata = load_case(args.case)
    if not metadata["targets"]:
        raise SystemExit(f"{args.case}: add at least one target before running the case")
    resolved_plan = None
    if getattr(args, "workflow", None):
        if args.plugins:
            raise SystemExit("Use either --workflow or --plugins, not both.")
        workflow_path, workflow = resolve_workflow(args.workflow)
        resolved_plan = workflows.resolve_plan(
            workflow, metadata, catalog(), is_installed
        )
        selected = {
            (job["plugin"], job["entity_id"])
            for job in resolved_plan["scheduled_jobs"]
        }
        jobs = [
            (job[0], {
                **job[1],
                "_workflow": next(
                    item for item in resolved_plan["scheduled_jobs"]
                    if (item["plugin"], item["entity_id"]) == (job[0], job[2]["id"])
                ),
            }, job[2])
            for job in case_jobs(metadata, [], include_uninstalled=False)
            if (job[0], job[2]["id"]) in selected
        ]
    else:
        workflow_path = None
        jobs = case_jobs(metadata, args.plugins, include_uninstalled=args.dry_run)
    if not jobs:
        print("No compatible installed plugins matched the case targets.", file=sys.stderr)
        return 1

    pending = []
    skipped = []
    for plugin_id, manifest, target in jobs:
        identifier = case_job_id(plugin_id, target["type"], target["value"])
        prior = metadata["jobs"].get(identifier, {})
        if (
            not args.rerun
            and prior.get("status") == "completed"
            and prior.get("exit_code") == 0
            and prior.get("plugin_version") == manifest["plugin_version"]
        ):
            skipped.append(identifier)
            continue
        pending.append((identifier, plugin_id, manifest, target))

    if not pending:
        print(f"Case {args.case} is up to date; {len(skipped)} successful job(s) skipped.")
        return 0

    run_dir = create_case_run_directory(path)
    run_id = run_dir.name
    raw_root = run_dir / "raw"
    raw_root.mkdir(mode=0o700)
    started_at = now()
    run_metadata: dict[str, Any] = {
        "schema": 1,
        "id": run_id,
        "case_id": args.case,
        "framework_version": __version__,
        "started_at": started_at,
        "completed_at": None,
        "status": "running",
        "dry_run": args.dry_run,
        "requested_plugins": args.plugins,
        "workflow_source": str(workflow_path) if workflow_path else None,
        "resolved_plan": resolved_plan,
        "skipped_jobs": skipped,
        "planned_jobs": [],
        "results": [],
    }
    for identifier, plugin_id, manifest, target in pending:
        plugin_dir, _ = require_plugin(plugin_id)
        output = (
            raw_root
            / f"{target['type']}s"
            / safe_slug(target["value"])
            / plugin_id
        )
        run_metadata["planned_jobs"].append({
            "job_id": identifier,
            "plugin": plugin_id,
            "plugin_version": manifest["plugin_version"],
            "target_id": target["id"],
            "target_type": target["type"],
            "target": target["value"],
            "command": adapter_command(
                plugin_dir, manifest, target["type"], target["value"], output
            ),
            "output": str(output.relative_to(path)),
            "workflow_stage": manifest.get("_workflow", {}).get("stage"),
            "purpose": manifest.get("_workflow", {}).get("purpose"),
            "expected_information_gain": manifest.get("_workflow", {}).get(
                "expected_information_gain"
            ),
            "timeout_seconds": manifest.get("_workflow", {}).get(
                "timeout_seconds"
            ),
        })
    write_private_json(run_dir / "run.json", run_metadata)
    append_case_activity(
        path,
        "run_started",
        run_id=run_id,
        job_count=len(pending),
        skipped_count=len(skipped),
        dry_run=args.dry_run,
    )
    print(
        f"Case: {args.case} | Run: {run_id} | "
        f"Jobs: {len(pending)} | Skipped: {len(skipped)}"
    )

    def execute(job):
        identifier, plugin_id, manifest, target = job
        output = (
            raw_root
            / f"{target['type']}s"
            / safe_slug(target["value"])
            / plugin_id
        )
        secure_case_directory(output, raw_root)
        began = now()
        if args.dry_run:
            plugin_dir, _ = require_plugin(plugin_id)
            command = adapter_command(
                plugin_dir, manifest, target["type"], target["value"], output
            )
            preview = {
                "plugin": plugin_id,
                "plugin_version": manifest["plugin_version"],
                "framework_version": __version__,
                "target_id": target["id"],
                "target_type": target["type"],
                "target": target["value"],
                "command": command,
                "exit_code": 0,
                "dry_run": True,
                "started_at": began,
                "completed_at": now(),
            }
            write_private_json(output / "status.json", preview)
            print(f"DRY      {plugin_id}: {shlex.join(command)}")
            return identifier, preview, output
        timeout_seconds = manifest.get("_workflow", {}).get("timeout_seconds")
        if timeout_seconds is None:
            rc = run_adapter(
                plugin_id, target["type"], target["value"], output, False
            )
        else:
            rc = run_adapter(
                plugin_id,
                target["type"],
                target["value"],
                output,
                False,
                timeout_seconds,
            )
        status_path = output / "status.json"
        if status_path.is_file():
            result = json.loads(status_path.read_text(encoding="utf-8"))
        else:
            result = {
                "plugin": plugin_id,
                "target_type": target["type"],
                "target": target["value"],
                "exit_code": rc,
                "error": "adapter did not write status.json",
                "completed_at": now(),
            }
        result.update({
            "plugin_version": manifest["plugin_version"],
            "framework_version": __version__,
            "target_id": target["id"],
            "started_at": result.get("started_at", began),
        })
        write_private_json(status_path, result)
        return identifier, result, output

    worker_limit = args.jobs
    if resolved_plan is not None:
        worker_limit = min(worker_limit, resolved_plan["max_concurrency"])
    interrupted = False
    failed_stages: set[str] = set()
    stage_dependencies = {
        stage["id"]: set(stage["depends_on"])
        for stage in (resolved_plan or {}).get("stages", [])
    }
    stage_groups = [(None, pending)]
    if resolved_plan is not None:
        stage_groups = [
            (
                stage_id,
                [
                    job for job in pending
                    if job[2].get("_workflow", {}).get("stage") == stage_id
                ],
            )
            for stage_id in resolved_plan["stage_order"]
        ]

    def record_result(identifier, result, output):
        relative_output = str(output.relative_to(path))
        state = {
            "status": (
                "previewed"
                if args.dry_run
                else ("completed" if result["exit_code"] == 0 else "failed")
            ),
            "exit_code": result["exit_code"],
            "plugin": result["plugin"],
            "plugin_version": result["plugin_version"],
            "target_id": result["target_id"],
            "last_run": run_id,
            "output": relative_output,
            "completed_at": result["completed_at"],
        }
        metadata["jobs"][identifier] = state
        run_metadata["results"].append({"job_id": identifier, **state})

    for stage_id, stage_pending in stage_groups:
        if interrupted or not stage_pending:
            continue
        blocked_by = sorted(stage_dependencies.get(stage_id, set()) & failed_stages)
        if blocked_by:
            for identifier, plugin_id, manifest, target in stage_pending:
                output = raw_root / f"{target['type']}s" / safe_slug(target["value"]) / plugin_id
                secure_case_directory(output, raw_root)
                result = {
                    "plugin": plugin_id,
                    "plugin_version": manifest["plugin_version"],
                    "framework_version": __version__,
                    "target_id": target["id"],
                    "target_type": target["type"],
                    "target": target["value"],
                    "exit_code": 125,
                    "error": f"workflow stage blocked by failed dependencies: {', '.join(blocked_by)}",
                    "completed_at": now(),
                }
                write_private_json(output / "status.json", result)
                record_result(identifier, result, output)
            failed_stages.add(stage_id)
            continue
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=worker_limit)
        future_jobs = {executor.submit(execute, job): job for job in stage_pending}
        try:
            for future in concurrent.futures.as_completed(future_jobs):
                job = future_jobs[future]
                try:
                    identifier, result, output = future.result()
                except Exception as exc:
                    identifier, plugin_id, manifest, target = job
                    output = (
                        raw_root
                        / f"{target['type']}s"
                        / safe_slug(target["value"])
                        / plugin_id
                    )
                    secure_case_directory(output, raw_root)
                    result = {
                        "plugin": plugin_id,
                        "plugin_version": manifest["plugin_version"],
                        "framework_version": __version__,
                        "target_id": target["id"],
                        "target_type": target["type"],
                        "target": target["value"],
                        "exit_code": 70,
                        "error": f"internal execution error: {exc}",
                        "completed_at": now(),
                    }
                    write_private_json(output / "status.json", result)
                record_result(identifier, result, output)
                if result["exit_code"] != 0 and stage_id is not None:
                    failed_stages.add(stage_id)
        except KeyboardInterrupt:
            interrupted = True
            for future in future_jobs:
                future.cancel()
        finally:
            # Running workers cannot be cancelled. Wait before finalizing
            # provenance or starting a dependent workflow stage.
            executor.shutdown(wait=True, cancel_futures=interrupted)

    run_metadata["completed_at"] = now()
    if interrupted:
        run_metadata["status"] = "interrupted"
    else:
        failures = sum(
            result["exit_code"] != 0 for result in run_metadata["results"]
        )
        run_metadata["status"] = "failed" if failures else "completed"
    write_private_json(run_dir / "run.json", run_metadata)
    save_case(path, metadata)
    append_case_activity(
        path,
        "run_finished",
        run_id=run_id,
        status=run_metadata["status"],
        completed_jobs=len(run_metadata["results"]),
    )
    if interrupted:
        print("Run interrupted; completed jobs were saved and pending jobs can be resumed.")
        return 130
    failures = sum(
        result["exit_code"] != 0 for result in run_metadata["results"]
    )
    print(f"Completed with {failures} failed job(s).")
    return 1 if failures else 0


def cmd_case_plan(args: argparse.Namespace) -> int:
    """Resolve a workflow without invoking adapters or making network calls."""
    path, metadata = load_case(args.case)
    if not metadata["targets"]:
        raise SystemExit(f"{args.case}: add at least one target before planning")
    workflow_path, workflow = resolve_workflow(args.workflow)
    plan = workflows.resolve_plan(workflow, metadata, catalog(), is_installed)
    plan["framework_version"] = __version__
    plan["workflow_source"] = str(workflow_path)
    if args.output:
        output = safe_output_directory(args.output, "plan output")
        write_private_json(output, plan)
        print(f"Plan: {output}")
    if args.json:
        print(json.dumps(plan, indent=2, sort_keys=True))
    else:
        print(f"Case: {args.case} | Workflow: {workflow['id']} | Schema: {workflow['schema']}")
        print(f"Identity assumption: none | Max concurrency: {plan['max_concurrency']}")
        for decision in plan["decisions"]:
            entity = decision["entity_type"] or "-"
            print(
                f"{decision['decision'].upper():<8} {decision['stage']:<20} "
                f"{decision['plugin']:<14} {entity:<8} {decision['reason']}"
            )
        for gap in plan["coverage_gaps"]:
            print(f"GAP      {gap['entity_type']}: {gap['reason']}")
        print(
            f"Selected {len(plan['scheduled_jobs'])} job(s); "
            f"{len(plan['coverage_gaps'])} coverage gap(s). No commands executed."
        )
    append_case_activity(
        path,
        "workflow_planned",
        workflow=workflow["id"],
        workflow_sha256=plan["workflow"]["sha256"],
        selected_jobs=len(plan["scheduled_jobs"]),
        coverage_gaps=len(plan["coverage_gaps"]),
    )
    return 0


def case_status_data(metadata: dict[str, Any]) -> dict[str, Any]:
    states = list(metadata["jobs"].values())
    return {
        "schema": metadata["schema"],
        "id": metadata["id"],
        "purpose": metadata["purpose"],
        "authorization_scope": metadata["authorization_scope"],
        "created_at": metadata["created_at"],
        "updated_at": metadata["updated_at"],
        "target_count": len(metadata["targets"]),
        "targets_by_type": {
            target_type: sum(
                target["type"] == target_type for target in metadata["targets"]
            )
            for target_type in sorted(
                {target["type"] for target in metadata["targets"]}
            )
        },
        "job_count": len(states),
        "completed_jobs": sum(state.get("status") == "completed" for state in states),
        "failed_jobs": sum(state.get("status") == "failed" for state in states),
        "previewed_jobs": sum(state.get("status") == "previewed" for state in states),
    }


def cmd_case_status(args: argparse.Namespace) -> int:
    _, metadata = load_case(args.case)
    status = case_status_data(metadata)
    if args.json:
        print(json.dumps(status, indent=2))
        return 0
    print(f"Case:          {status['id']}")
    print(f"Purpose:       {status['purpose']}")
    print(f"Authorization: {status['authorization_scope']}")
    print(f"Targets:       {status['target_count']}")
    for target_type, count in status["targets_by_type"].items():
        print(f"  {target_type}: {count}")
    print(f"Jobs:          {status['job_count']}")
    print(f"Completed:     {status['completed_jobs']}")
    print(f"Failed:        {status['failed_jobs']}")
    print(f"Previewed:     {status['previewed_jobs']}")
    return 0


def cmd_case_entities(args: argparse.Namespace) -> int:
    path, metadata = load_case(args.case)
    report = build_case_report(path, metadata)
    if report["normalization_errors"]:
        raise SystemExit(
            "Cannot project extracted entities: one or more jobs failed normalization."
        )
    projection = entities.build_case_entities(
        metadata, report["candidates"], canonical_entity_value
    )
    if args.json:
        print(json.dumps(projection, indent=2, sort_keys=True))
        return 0
    if not projection["entities"]:
        print("No case entities.")
        return 0
    for entity in projection["entities"]:
        print(
            f"{entity['id']}  {entity['type']:<10} "
            f"{entity['origin']:<6} {entity['value']}"
        )
    return 0


def build_case_report(path: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    return reporting.build_report(path, metadata, catalog(), __version__)


def safe_report_output(path: Path, requested: Path) -> Path:
    expanded = requested.expanduser()
    candidate = expanded if expanded.is_absolute() else path / expanded
    try:
        lexical_relative = candidate.absolute().relative_to(path)
    except ValueError:
        lexical_relative = None
    if lexical_relative is not None:
        current = path
        for part in lexical_relative.parts:
            current /= part
            if current.is_symlink():
                raise SystemExit(
                    f"Report output cannot use a symbolic link: {current}"
                )
    output = (
        expanded.resolve()
        if expanded.is_absolute()
        else (path / expanded).resolve()
    )
    if not output.is_relative_to(path):
        raise SystemExit("Report output must remain inside the case directory.")
    reserved_files = {path / "case.json", path / "activity.jsonl"}
    reserved_directories = (path / "runs", path / "findings")
    if (
        output in reserved_files
        or any(output.is_relative_to(directory) for directory in reserved_directories)
    ):
        raise SystemExit("Report output cannot replace reserved case records.")
    return output


def cmd_case_report(args: argparse.Namespace) -> int:
    path, metadata = load_case(args.case)
    requested_format = getattr(args, "format", "markdown")
    shareable = getattr(args, "shareable", False)
    formats = (
        ["markdown", "json", "html", "csv"]
        if requested_format == "all"
        else [requested_format]
    )
    if args.output and len(formats) != 1:
        raise SystemExit("--output can only be used with one report format.")
    prefix = "shareable-" if shareable else ""
    defaults = {
        "markdown": path / f"{prefix}report.md",
        "json": path / f"{prefix}report.json",
        "html": path / f"{prefix}report.html",
        "csv": path / f"{prefix}findings.csv",
    }
    outputs = {
        report_format: (
            safe_report_output(path, args.output)
            if args.output
            else defaults[report_format]
        )
        for report_format in formats
    }
    for report_format, output in outputs.items():
        is_default = output == defaults[report_format]
        if output.exists() and not is_default and not args.force:
            raise SystemExit(
                f"Report output already exists: {output}; use --force to replace it."
            )

    report = build_case_report(path, metadata)
    if shareable:
        report = reporting.redact_report(report)
    renderers = {
        "markdown": lambda output: reporting.render_markdown(report, output, path),
        "json": lambda output: reporting.render_json(report),
        "html": lambda output: reporting.render_html(report, output, path),
        "csv": lambda output: reporting.render_csv(report),
    }
    for report_format, output in outputs.items():
        write_private_text(output, renderers[report_format](output))
        print(f"Report ({report_format}): {output}")
    append_case_activity(
        path,
        "report_generated",
        formats=formats,
        shareable=shareable,
        outputs=[str(output.relative_to(path)) for output in outputs.values()],
    )
    if report["normalization_errors"]:
        print(
            f"WARNING: report contains "
            f"{len(report['normalization_errors'])} normalization error(s).",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_case_findings(args: argparse.Namespace) -> int:
    path, metadata = load_case(args.case)
    report = build_case_report(path, metadata)
    if args.json:
        print(json.dumps(report["findings"], indent=2, sort_keys=True))
    elif not report["findings"]:
        print("No normalized findings.")
    else:
        for finding in report["findings"]:
            value = f": {finding['value']}" if finding["value"] is not None else ""
            print(
                f"{finding['id']}  {finding['confidence']:<10} "
                f"{finding['title']}{value}"
            )
    return 1 if report["normalization_errors"] else 0


def cmd_case_annotate(args: argparse.Namespace) -> int:
    path, metadata = load_case(args.case)
    report = build_case_report(path, metadata)
    known = {finding["id"] for finding in report["findings"]}
    if args.finding not in known:
        raise SystemExit(f"Unknown finding in {args.case}: {args.finding}")
    if args.confidence is None and args.note is None and not args.clear_note:
        raise SystemExit("Specify --confidence, --note, or --clear-note.")
    reviews_dir = path / "findings"
    secure_case_directory(reviews_dir, path)
    reviews_path = reviews_dir / "reviews.json"
    reviews = reporting.load_reviews(reviews_path)
    review = reviews.get(
        args.finding,
        {"confidence": "unverified", "note": None, "updated_at": now()},
    )
    if args.confidence is not None:
        review["confidence"] = args.confidence
    if args.note is not None:
        review["note"] = args.note
    if args.clear_note:
        review["note"] = None
    review["updated_at"] = now()
    reviews[args.finding] = review
    write_private_json(
        reviews_path,
        {"schema": reporting.REVIEW_SCHEMA, "reviews": reviews},
    )
    save_case(path, metadata)
    append_case_activity(
        path,
        "finding_annotated",
        finding_id=args.finding,
        confidence=review["confidence"],
        note_present=review["note"] is not None,
    )
    print(f"Annotated finding: {args.finding}")
    return 0


def cmd_case_integrity(args: argparse.Namespace) -> int:
    path, metadata = load_case(args.case)
    manifest_path = path / integrity.MANIFEST_NAME
    if args.action == "create":
        manifest = integrity.build_manifest(
            path, case_id=args.case, framework_version=__version__
        )
        write_private_json(manifest_path, manifest)
        print(f"Integrity manifest: {manifest_path}")
        print(f"Hashed {len(manifest['artifacts'])} artifact(s).")
        return 0
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"{args.case}: no integrity manifest; run 'case integrity create' first") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{args.case}: invalid integrity manifest: {exc}") from exc
    result = integrity.verify_manifest(path, manifest)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Integrity: {'PASS' if result['valid'] else 'FAIL'}")
        print(f"Verified: {result['verified']}")
        for field in ("missing", "modified", "unexpected"):
            for item in result[field]:
                print(f"{field.upper():<10} {item}")
    return 0 if result["valid"] else 1


def _full_bundle_members(path: Path, metadata: dict[str, Any]) -> dict[str, bytes]:
    members = {
        artifact.relative_to(path).as_posix(): artifact.read_bytes()
        for artifact in integrity._case_files(path)
    }
    report = build_case_report(path, metadata)
    projection = entities.build_case_entities(
        metadata, report["candidates"], canonical_entity_value
    )
    artifact_digests = {
        name: hashlib.sha256(content).hexdigest()
        for name, content in members.items()
    }
    for entity in projection["entities"]:
        for source in entity["sources"]:
            source_file = source.get("source_file")
            if source_file in artifact_digests:
                source["artifact"] = {
                    "path": source_file,
                    "sha256": artifact_digests[source_file],
                    "algorithm": "sha256",
                }
    projection["integrity_binding"] = {
        "schema": 1,
        "policy": "source paths bind to verified bundle artifacts when available",
    }
    members["intelligence/entities.json"] = (
        json.dumps(projection, indent=2, sort_keys=True).encode() + b"\n"
    )
    manifest = {
        "schema": integrity.INTEGRITY_SCHEMA,
        "algorithm": "sha256",
        "case_id": metadata["id"],
        "framework_version": __version__,
        "artifacts": [
            {
                "path": name,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
            for name, content in sorted(members.items())
        ],
    }
    members[integrity.MANIFEST_NAME] = (
        json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    )
    return members


def _redacted_bundle_members(path: Path, metadata: dict[str, Any]) -> dict[str, bytes]:
    report = reporting.redact_report(build_case_report(path, metadata))
    projection = entities.build_case_entities(
        metadata, build_case_report(path, metadata)["candidates"], canonical_entity_value
    )
    redacted_entities = {
        "schema": projection["schema"],
        "case_id": "shared-case",
        "entity_count": projection["entity_count"],
        "entities": [
            {
                "id": f"entity-{index:03d}", "type": item["type"],
                "origin": item["origin"], "value": "[REDACTED]",
                "canonical_value": "[REDACTED]",
                "confidence": item["confidence"],
                "source_count": len(item["sources"]),
            }
            for index, item in enumerate(projection["entities"], 1)
        ],
        "relationship_count": len(projection["relationships"]),
        "relationships": [],
    }
    summary = {
        "schema": 1,
        "id": "shared-case",
        "purpose": "[REDACTED]",
        "authorization_scope": "[REDACTED]",
        "created_at": metadata["created_at"],
        "updated_at": metadata["updated_at"],
        "target_count": len(metadata["targets"]),
        "job_count": len(metadata["jobs"]),
        "redaction": "conservative; raw evidence, targets, commands, paths, and analyst notes excluded",
    }
    return {
        "case-summary.json": json.dumps(summary, indent=2, sort_keys=True).encode() + b"\n",
        "entities.json": json.dumps(redacted_entities, indent=2, sort_keys=True).encode() + b"\n",
        "report.json": json.dumps(report, indent=2, sort_keys=True).encode() + b"\n",
    }


def cmd_case_export(args: argparse.Namespace) -> int:
    path, metadata = load_case(args.case)
    output = args.output.expanduser().resolve()
    if output.exists() and not args.force:
        raise SystemExit(f"Export already exists: {output}; use --force to replace it.")
    members = (
        _redacted_bundle_members(path, metadata)
        if args.mode == "redacted" else _full_bundle_members(path, metadata)
    )
    bundle_case_id = "shared-case" if args.mode == "redacted" else args.case
    manifest = integrity.bundle_manifest(
        bundle_case_id, __version__, args.mode, members
    )
    integrity.write_bundle(output, manifest, members)
    verified, _ = integrity.inspect_bundle(output)
    print(f"Export ({verified['mode']}): {output}")
    print(f"Artifacts: {len(verified['artifacts'])} | SHA-256 verified")
    return 0


def cmd_case_bundle_inspect(args: argparse.Namespace) -> int:
    manifest, _ = integrity.inspect_bundle(args.bundle.expanduser().resolve())
    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print("Bundle: PASS")
        print(f"Case: {manifest['case_id']} | Mode: {manifest['mode']}")
        print(f"Artifacts: {len(manifest['artifacts'])}")
    return 0


def cmd_case_import(args: argparse.Namespace) -> int:
    bundle = args.bundle.expanduser().resolve()
    manifest, members = integrity.inspect_bundle(bundle)
    if manifest.get("mode") != "full":
        raise SystemExit("Redacted bundles are inspection-only and cannot become live cases.")
    imported_id = manifest.get("case_id")
    if not isinstance(imported_id, str):
        raise SystemExit("Bundle does not contain a valid case ID.")
    if args.case and args.case != imported_id:
        raise SystemExit("Imported case ID must match the bundle; renaming would invalidate provenance.")
    validate_case_id(imported_id)
    destination = case_path(imported_id, must_exist=False)
    if destination.exists():
        raise SystemExit(f"Case already exists: {imported_id}")
    destination.mkdir(mode=0o700)
    try:
        for name, content in sorted(members.items()):
            relative = Path(integrity.safe_member(name))
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.parent.chmod(0o700)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
        _, loaded = load_case(imported_id)
        case_manifest = json.loads((destination / integrity.MANIFEST_NAME).read_text(encoding="utf-8"))
        result = integrity.verify_manifest(destination, case_manifest)
        if not result["valid"] or loaded["id"] != imported_id:
            raise integrity.IntegrityError("imported case failed independent verification")
    except BaseException:
        shutil.rmtree(destination)
        raise
    print(f"Imported verified case: {imported_id}")
    print(f"Location: {destination}")
    return 0


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

    workflow_files = sorted(workflow_root().glob("*.json")) if workflow_root().exists() else []
    if not workflow_files:
        errors.append("no workflow profiles found")
    workflow_ids: set[str] = set()
    for workflow_file in workflow_files:
        try:
            workflow = workflows.load_workflow(workflow_file)
            if workflow["id"] in workflow_ids:
                errors.append(f"duplicate workflow id: {workflow['id']}")
            workflow_ids.add(workflow["id"])
            declared_plugins = {
                plugin_id
                for stage in workflow["stages"]
                for plugin_id in stage["plugins"]
            }
            unknown = sorted(declared_plugins - {directory.name for directory in directories})
            if unknown:
                errors.append(
                    f"{workflow_file.name}: unknown plugins: {', '.join(unknown)}"
                )
        except workflows.WorkflowError as exc:
            errors.append(f"{workflow_file.name}: {exc}")

    payload = {
        "plugin_count": len(directories),
        "workflow_count": len(workflow_files),
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
            f"{len(workflow_files)} workflow(s), {len(errors)} error(s), "
            f"{len(warnings)} warning(s) — {status}"
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
    status_filter = p.add_mutually_exclusive_group()
    status_filter.add_argument("--installed", action="store_true")
    status_filter.add_argument("--available", action="store_true")
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

    case = sub.add_parser("case", help="manage durable, private investigation cases")
    cs = case.add_subparsers(dest="case_command", required=True)

    p = cs.add_parser("create", help="create a versioned case workspace")
    p.add_argument("case")
    p.add_argument("--purpose", required=True)
    p.add_argument(
        "--authorization",
        required=True,
        help="document the legal or organizational authorization scope",
    )
    p.set_defaults(func=cmd_case_create)

    p = cs.add_parser("add", help="add a validated target to a case")
    p.add_argument("case")
    p.add_argument("type", choices=sorted(TARGET_TYPES))
    p.add_argument("target")
    p.set_defaults(func=cmd_case_add)

    p = cs.add_parser("run", help="run or resume compatible case jobs")
    p.add_argument("case")
    p.add_argument("--plugins", nargs="*", default=[])
    p.add_argument("--jobs", type=int, default=2, choices=range(1, 9), metavar="1-8")
    p.add_argument("--rerun", action="store_true", help="rerun successful jobs")
    p.add_argument(
        "--workflow",
        help="named built-in workflow or explicit JSON workflow path",
    )
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_case_run)

    p = cs.add_parser("plan", help="preview a resolved workflow without network activity")
    p.add_argument("case")
    p.add_argument("--workflow", default="public-identity")
    p.add_argument("--json", action="store_true")
    p.add_argument("-o", "--output", type=Path)
    p.set_defaults(func=cmd_case_plan)

    p = cs.add_parser("status", help="show case target and execution status")
    p.add_argument("case")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_case_status)

    p = cs.add_parser(
        "entities",
        help="list canonical seed and extracted candidate entities",
    )
    p.add_argument("case")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_case_entities)

    p = cs.add_parser("report", help="write normalized provenance-linked reports")
    p.add_argument("case")
    p.add_argument(
        "--format",
        choices=("markdown", "json", "html", "csv", "all"),
        default="markdown",
    )
    p.add_argument(
        "--shareable",
        action="store_true",
        help="redact targets, raw paths, commands, values, and analyst notes",
    )
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--force", action="store_true", help="replace a custom report file")
    p.set_defaults(func=cmd_case_report)

    p = cs.add_parser("findings", help="list normalized findings for a case")
    p.add_argument("case")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_case_findings)

    p = cs.add_parser("annotate", help="set confidence or an analyst note")
    p.add_argument("case")
    p.add_argument("finding")
    p.add_argument(
        "--confidence",
        choices=sorted(reporting.CONFIDENCE_LEVELS),
    )
    note_group = p.add_mutually_exclusive_group()
    note_group.add_argument("--note")
    note_group.add_argument("--clear-note", action="store_true")
    p.set_defaults(func=cmd_case_annotate)

    p = cs.add_parser("integrity", help="create or verify a case integrity manifest")
    p.add_argument("action", choices=("create", "verify"))
    p.add_argument("case")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_case_integrity)

    p = cs.add_parser("export", help="create a deterministic verified case bundle")
    p.add_argument("case")
    p.add_argument("--mode", choices=("full", "redacted"), default="full")
    p.add_argument("-o", "--output", type=Path, required=True)
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_case_export)

    p = cs.add_parser("inspect", help="verify and inspect a case bundle without importing it")
    p.add_argument("bundle", type=Path)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_case_bundle_inspect)

    p = cs.add_parser("import", help="safely import a verified full-fidelity bundle")
    p.add_argument("bundle", type=Path)
    p.add_argument("--case", help="require this case ID")
    p.set_defaults(func=cmd_case_import)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return int(args.func(args))
    except (OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
