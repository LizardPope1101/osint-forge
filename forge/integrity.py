#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tamper-evident case manifests and deterministic, safe case bundles."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
from typing import Any, Iterable
import zipfile

INTEGRITY_SCHEMA = 1
BUNDLE_SCHEMA = 1
MANIFEST_NAME = "integrity.json"
BUNDLE_MANIFEST = "bundle-manifest.json"
EXCLUDED_NAMES = {MANIFEST_NAME, BUNDLE_MANIFEST}


class IntegrityError(RuntimeError):
    """Evidence cannot be safely verified or transported."""


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _case_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.is_symlink():
            raise IntegrityError(f"refusing symbolic link: {relative}")
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise IntegrityError(f"refusing non-regular artifact: {relative}")
        if path.name not in EXCLUDED_NAMES:
            files.append(path)
    return files


def build_manifest(root: Path, *, case_id: str, framework_version: str) -> dict[str, Any]:
    artifacts = []
    for path in _case_files(root):
        relative = path.relative_to(root).as_posix()
        artifacts.append({
            "path": relative,
            "sha256": _digest(path),
            "size": path.stat().st_size,
        })
    return {
        "schema": INTEGRITY_SCHEMA,
        "algorithm": "sha256",
        "case_id": case_id,
        "framework_version": framework_version,
        "artifacts": artifacts,
    }


def verify_manifest(root: Path, manifest: dict[str, Any], *, allow_unexpected: Iterable[str] = ()) -> dict[str, Any]:
    if not isinstance(manifest, dict) or manifest.get("schema") != INTEGRITY_SCHEMA:
        raise IntegrityError("unsupported integrity manifest")
    if manifest.get("algorithm") != "sha256" or not isinstance(manifest.get("artifacts"), list):
        raise IntegrityError("invalid integrity manifest")
    expected: dict[str, dict[str, Any]] = {}
    for item in manifest["artifacts"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise IntegrityError("invalid integrity artifact record")
        relative = safe_member(item["path"])
        if relative in expected:
            raise IntegrityError(f"duplicate integrity path: {relative}")
        if not isinstance(item["sha256"], str) or len(item["sha256"]) != 64 or not isinstance(item["size"], int):
            raise IntegrityError(f"invalid integrity metadata: {relative}")
        expected[relative] = item
    actual = {path.relative_to(root).as_posix(): path for path in _case_files(root)}
    allowed = set(allow_unexpected)
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected) - allowed)
    modified = sorted(
        relative for relative in set(expected) & set(actual)
        if actual[relative].stat().st_size != expected[relative]["size"]
        or _digest(actual[relative]) != expected[relative]["sha256"]
    )
    return {"valid": not (missing or modified or unexpected), "missing": missing, "modified": modified, "unexpected": unexpected, "verified": len(expected) - len(missing) - len(modified)}


def safe_member(name: Any) -> str:
    if not isinstance(name, str) or not name or "\\" in name or "\x00" in name:
        raise IntegrityError("unsafe bundle member name")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise IntegrityError(f"unsafe bundle member: {name!r}")
    if path.as_posix() != name:
        raise IntegrityError(f"non-canonical bundle member: {name!r}")
    return path.as_posix()


def inspect_bundle(bundle: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    try:
        archive = zipfile.ZipFile(bundle)
    except (OSError, zipfile.BadZipFile) as exc:
        raise IntegrityError(f"invalid bundle: {exc}") from exc
    with archive:
        members: dict[str, bytes] = {}
        for info in archive.infolist():
            name = safe_member(info.filename)
            if name in members:
                raise IntegrityError(f"duplicate bundle member: {name}")
            mode = info.external_attr >> 16
            if info.is_dir() or stat.S_ISLNK(mode) or (mode and not stat.S_ISREG(mode)):
                raise IntegrityError(f"unsafe bundle member type: {name}")
            members[name] = archive.read(info)
    try:
        manifest = json.loads(members.pop(BUNDLE_MANIFEST).decode("utf-8"))
    except (KeyError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError("bundle manifest is missing or invalid") from exc
    if manifest.get("schema") != BUNDLE_SCHEMA or manifest.get("algorithm") != "sha256":
        raise IntegrityError("unsupported bundle manifest")
    if manifest.get("mode") not in {"full", "redacted"}:
        raise IntegrityError("unsupported bundle mode")
    if not isinstance(manifest.get("case_id"), str) or not isinstance(
        manifest.get("framework_version"), str
    ):
        raise IntegrityError("invalid bundle identity metadata")
    expected = manifest.get("artifacts")
    if not isinstance(expected, list):
        raise IntegrityError("invalid bundle artifact list")
    by_path = {item.get("path"): item for item in expected if isinstance(item, dict)}
    if len(by_path) != len(expected) or set(by_path) != set(members):
        raise IntegrityError("bundle contents do not match manifest")
    for name, content in members.items():
        item = by_path[name]
        if item.get("size") != len(content) or item.get("sha256") != hashlib.sha256(content).hexdigest():
            raise IntegrityError(f"bundle artifact failed verification: {name}")
    return manifest, members


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


def write_bundle(output: Path, manifest: dict[str, Any], members: dict[str, bytes]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w") as archive:
            encoded = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
            archive.writestr(_zip_info(BUNDLE_MANIFEST), encoded)
            for name in sorted(members):
                archive.writestr(_zip_info(name), members[name])
        os.chmod(temporary, 0o600)
        temporary.replace(output)
        output.chmod(0o600)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def bundle_manifest(case_id: str, framework_version: str, mode: str, members: dict[str, bytes]) -> dict[str, Any]:
    return {
        "schema": BUNDLE_SCHEMA,
        "algorithm": "sha256",
        "case_id": case_id,
        "framework_version": framework_version,
        "mode": mode,
        "artifacts": [
            {"path": name, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
            for name, content in sorted(members.items())
        ],
    }
