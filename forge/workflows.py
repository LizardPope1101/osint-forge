#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict, deterministic investigation workflow planning."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable

WORKFLOW_SCHEMA = 1
PLAN_SCHEMA = 1
ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ALLOWED_FIELDS = {
    "schema", "id", "name", "description", "max_concurrency", "stages",
}
STAGE_FIELDS = {
    "id", "purpose", "expected_information_gain", "plugins", "depends_on",
    "timeout_seconds",
}


class WorkflowError(ValueError):
    """A workflow is unsafe, unsupported, or internally inconsistent."""


def _strings(value: Any, field: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise WorkflowError(f"{field} must be a string array")
    if len(value) != len(set(value)):
        raise WorkflowError(f"{field} contains duplicate values")
    return value


def validate_workflow(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise WorkflowError("workflow root must be an object")
    unknown = sorted(set(data) - ALLOWED_FIELDS)
    if unknown:
        raise WorkflowError(f"unknown workflow fields: {', '.join(unknown)}")
    missing = sorted(ALLOWED_FIELDS - set(data))
    if missing:
        raise WorkflowError(f"missing workflow fields: {', '.join(missing)}")
    if data["schema"] != WORKFLOW_SCHEMA:
        if isinstance(data["schema"], int) and data["schema"] > WORKFLOW_SCHEMA:
            raise WorkflowError(f"workflow schema {data['schema']} is newer than supported schema {WORKFLOW_SCHEMA}")
        raise WorkflowError(f"unsupported workflow schema {data['schema']!r}")
    if not isinstance(data["id"], str) or not ID_RE.fullmatch(data["id"]):
        raise WorkflowError("workflow id must use lowercase letters, numbers, and hyphens")
    for field in ("name", "description"):
        if not isinstance(data[field], str) or not data[field].strip():
            raise WorkflowError(f"{field} must be non-empty text")
    if not isinstance(data["max_concurrency"], int) or not 1 <= data["max_concurrency"] <= 8:
        raise WorkflowError("max_concurrency must be an integer from 1 to 8")
    stages = data["stages"]
    if not isinstance(stages, list) or not stages:
        raise WorkflowError("stages must be a non-empty array")
    known: set[str] = set()
    graph: dict[str, list[str]] = {}
    for index, stage in enumerate(stages):
        label = f"stages[{index}]"
        if not isinstance(stage, dict):
            raise WorkflowError(f"{label} must be an object")
        unknown = sorted(set(stage) - STAGE_FIELDS)
        if unknown:
            raise WorkflowError(f"{label} has unknown fields: {', '.join(unknown)}")
        missing = sorted(STAGE_FIELDS - set(stage))
        if missing:
            raise WorkflowError(f"{label} missing fields: {', '.join(missing)}")
        stage_id = stage["id"]
        if not isinstance(stage_id, str) or not ID_RE.fullmatch(stage_id):
            raise WorkflowError(f"{label}.id is invalid")
        if stage_id in known:
            raise WorkflowError(f"duplicate stage id: {stage_id}")
        known.add(stage_id)
        for field in ("purpose", "expected_information_gain"):
            if not isinstance(stage[field], str) or not stage[field].strip():
                raise WorkflowError(f"{label}.{field} must be non-empty text")
        _strings(stage["plugins"], f"{label}.plugins")
        graph[stage_id] = _strings(stage["depends_on"], f"{label}.depends_on", allow_empty=True)
        if not isinstance(stage["timeout_seconds"], int) or not 1 <= stage["timeout_seconds"] <= 86400:
            raise WorkflowError(f"{label}.timeout_seconds must be an integer from 1 to 86400")
    for stage_id, dependencies in graph.items():
        unknown = sorted(set(dependencies) - known)
        if unknown:
            raise WorkflowError(f"stage {stage_id} has unknown dependencies: {', '.join(unknown)}")
        if stage_id in dependencies:
            raise WorkflowError(f"stage {stage_id} depends on itself")
    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(stage_id: str) -> None:
        if stage_id in visiting:
            raise WorkflowError("workflow stage dependency cycle detected")
        if stage_id in visited:
            return
        visiting.add(stage_id)
        for dependency in graph[stage_id]:
            visit(dependency)
        visiting.remove(stage_id)
        visited.add(stage_id)
    for stage_id in graph:
        visit(stage_id)
    return data


def load_workflow(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise WorkflowError(f"refusing symbolic-link workflow: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WorkflowError(f"workflow does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise WorkflowError(f"invalid workflow JSON in {path}: {exc}") from exc
    return validate_workflow(data)


def workflow_digest(workflow: dict[str, Any]) -> str:
    encoded = json.dumps(workflow, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def stage_order(workflow: dict[str, Any]) -> list[str]:
    """Return a stable topological order, retaining declaration order on ties."""
    remaining = {stage["id"]: list(stage["depends_on"]) for stage in workflow["stages"]}
    ordered: list[str] = []
    while remaining:
        ready = [
            stage["id"] for stage in workflow["stages"]
            if stage["id"] in remaining
            and all(dependency in ordered for dependency in remaining[stage["id"]])
        ]
        if not ready:
            raise WorkflowError("workflow stage dependency cycle detected")
        for stage_id in ready:
            ordered.append(stage_id)
            del remaining[stage_id]
    return ordered


def resolve_plan(
    workflow: dict[str, Any],
    metadata: dict[str, Any],
    catalog: dict[str, tuple[Path, dict[str, Any]]],
    installed: Callable[[str], bool],
) -> dict[str, Any]:
    """Resolve every declared plugin/seed pair without performing I/O."""
    validate_workflow(workflow)
    decisions: list[dict[str, Any]] = []
    scheduled: list[dict[str, Any]] = []
    covered: set[str] = set()
    for stage in workflow["stages"]:
        for plugin_id in stage["plugins"]:
            entry = catalog.get(plugin_id)
            if entry is None:
                decisions.append({
                    "stage": stage["id"], "plugin": plugin_id, "entity_id": None,
                    "entity_type": None, "decision": "rejected",
                    "reason": "plugin is not present in this framework catalog",
                })
                continue
            _, manifest = entry
            available = installed(plugin_id)
            for target in metadata["targets"]:
                compatible = (
                    manifest.get("batch", False)
                    and target["type"] in manifest.get("entities", {}).get("accepted", manifest.get("supports", []))
                    and target["type"] in manifest.get("adapters", {})
                )
                base = {
                    "stage": stage["id"], "plugin": plugin_id,
                    "plugin_version": manifest["plugin_version"],
                    "entity_id": target["id"], "entity_type": target["type"],
                    "target": target["value"],
                }
                if not compatible:
                    decisions.append({**base, "decision": "skipped", "reason": "plugin does not accept this entity type through a safe adapter"})
                elif not available:
                    decisions.append({**base, "decision": "skipped", "reason": "compatible plugin is not installed"})
                else:
                    decision = {
                        **base, "decision": "selected",
                        "reason": f"installed plugin accepts {target['type']} entities",
                        "purpose": stage["purpose"],
                        "expected_information_gain": stage["expected_information_gain"],
                        "timeout_seconds": stage["timeout_seconds"],
                        "depends_on": stage["depends_on"],
                    }
                    decisions.append(decision)
                    scheduled.append(decision)
                    covered.add(target["id"])
    decisions.sort(key=lambda item: (item["stage"], item["plugin"], item.get("entity_type") or "", item.get("entity_id") or ""))
    scheduled.sort(key=lambda item: (item["stage"], item["plugin"], item["entity_type"], item["entity_id"]))
    gaps = [
        {"entity_id": target["id"], "entity_type": target["type"], "reason": "no installed workflow plugin can collect this seed"}
        for target in sorted(metadata["targets"], key=lambda item: (item["type"], item["id"]))
        if target["id"] not in covered
    ]
    return {
        "schema": PLAN_SCHEMA,
        "workflow": {"id": workflow["id"], "schema": workflow["schema"], "sha256": workflow_digest(workflow)},
        "case_id": metadata["id"],
        "seed_identity_assumption": "none",
        "max_concurrency": workflow["max_concurrency"],
        "stage_order": stage_order(workflow),
        "stages": workflow["stages"],
        "scheduled_jobs": scheduled,
        "decisions": decisions,
        "coverage_gaps": gaps,
    }
