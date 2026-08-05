#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict argv-based search-provider execution contracts."""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

PROVIDER_ADAPTER_SCHEMA = 1
ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ENTITY_TYPES = {
    "address", "domain", "email", "file", "image", "ip", "name", "phone",
    "username",
}
FIELDS = {"schema", "id", "name", "provider_version", "accepts", "command", "timeout_seconds", "environment"}
REQUIRED_FIELDS = FIELDS - {"environment"}
ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
RESERVED_ENVIRONMENT = {"HOME", "PATH", "LANG", "PYTHONIOENCODING"}
PLACEHOLDERS = {"{query_type}", "{query_value}", "{output_dir}"}


class ProviderError(ValueError):
    """A search-provider adapter contract is malformed or unsafe."""


def validate_adapter(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderError("provider adapter must be an object")
    unknown = sorted(set(value) - FIELDS)
    missing = sorted(REQUIRED_FIELDS - set(value))
    if unknown or missing:
        detail = f"unknown fields: {', '.join(unknown)}" if unknown else f"missing fields: {', '.join(missing)}"
        raise ProviderError(f"provider adapter has {detail}")
    if value["schema"] != PROVIDER_ADAPTER_SCHEMA:
        if isinstance(value["schema"], int) and value["schema"] > PROVIDER_ADAPTER_SCHEMA:
            raise ProviderError(f"provider adapter schema {value['schema']} is newer than supported schema {PROVIDER_ADAPTER_SCHEMA}")
        raise ProviderError(f"unsupported provider adapter schema {value['schema']!r}")
    if not isinstance(value["id"], str) or not ID_RE.fullmatch(value["id"]):
        raise ProviderError("provider adapter id is invalid")
    for field in ("name", "provider_version"):
        if not isinstance(value[field], str) or not value[field].strip():
            raise ProviderError(f"provider adapter {field} must be non-empty text")
    accepts = value["accepts"]
    if not isinstance(accepts, list) or not accepts or not all(item in ENTITY_TYPES for item in accepts):
        raise ProviderError("provider adapter accepts must contain supported entity types")
    if len(accepts) != len(set(accepts)):
        raise ProviderError("provider adapter accepts contains duplicates")
    command = value["command"]
    if not isinstance(command, list) or not command or not all(
        isinstance(item, str) and item and "\x00" not in item for item in command
    ):
        raise ProviderError("provider adapter command must be a non-empty argv array")
    used = {placeholder for item in command for placeholder in PLACEHOLDERS if placeholder in item}
    if used != PLACEHOLDERS:
        raise ProviderError("provider adapter command must use query_type, query_value, and output_dir placeholders")
    for item in command:
        residual = re.findall(r"\{[^{}]+\}", item)
        if any(token not in PLACEHOLDERS for token in residual):
            raise ProviderError("provider adapter command contains an unknown placeholder")
    timeout = value["timeout_seconds"]
    if not isinstance(timeout, int) or not 1 <= timeout <= 3600:
        raise ProviderError("provider adapter timeout_seconds must be from 1 to 3600")
    environment = value.get("environment", [])
    if not isinstance(environment, list) or not all(
        isinstance(name, str) and ENV_RE.fullmatch(name) for name in environment
    ) or len(environment) != len(set(environment)) or set(environment) & RESERVED_ENVIRONMENT:
        raise ProviderError("provider adapter environment must be unique uppercase variable names")
    return {
        "schema": PROVIDER_ADAPTER_SCHEMA,
        "id": value["id"],
        "name": value["name"].strip(),
        "provider_version": value["provider_version"].strip(),
        "accepts": sorted(accepts),
        "command": list(command),
        "timeout_seconds": timeout,
        "environment": sorted(environment),
    }


def load_adapter(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ProviderError(f"refusing symbolic-link provider adapter: {path}")
    try:
        if not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise OSError("adapter is not a bounded regular file")
        return validate_adapter(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProviderError(f"invalid provider adapter: {exc}") from exc


def resolve_command(adapter: dict[str, Any], query_type: str, query_value: str, output_dir: Path) -> list[str]:
    replacements = {
        "{query_type}": query_type,
        "{query_value}": query_value,
        "{output_dir}": str(output_dir),
    }
    return [
        _replace(argument, replacements)
        for argument in adapter["command"]
    ]


def _replace(argument: str, replacements: dict[str, str]) -> str:
    for placeholder, replacement in replacements.items():
        argument = argument.replace(placeholder, replacement)
    return argument
