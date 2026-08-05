# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Normalized, provenance-preserving case reports."""

from __future__ import annotations

import copy
import csv
import hashlib
import html
import io
import json
import math
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

REPORT_SCHEMA = 3
NORMALIZER_SCHEMAS = {1, 2}
REVIEW_SCHEMA = 1
CONFIDENCE_LEVELS = {"unverified", "low", "medium", "high"}
MAX_NORMALIZER_OUTPUT = 16 * 1024 * 1024


class NormalizationError(RuntimeError):
    """A plugin output could not be normalized safely."""


def _json_value(value: Any, *, depth: int = 0) -> bool:
    if depth > 12:
        return False
    if value is None or isinstance(value, (str, int, bool)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_json_value(item, depth=depth + 1) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _json_value(item, depth=depth + 1)
            for key, item in value.items()
        )
    return False


def _case_child(case_path: Path, relative: str, context: str) -> Path:
    child = Path(relative)
    if child.is_absolute() or not relative or child in {Path("."), Path("..")}:
        raise NormalizationError(f"invalid {context}: {relative!r}")
    candidate = case_path
    for part in child.parts:
        candidate /= part
        if candidate.is_symlink():
            raise NormalizationError(f"refusing symbolic-link {context}: {relative}")
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise NormalizationError(f"cannot resolve {context} {relative}: {exc}") from exc
    if not resolved.is_relative_to(case_path):
        raise NormalizationError(f"{context} escapes the case directory: {relative}")
    return resolved


def _source_file(output_dir: Path, relative: str) -> Path:
    source = Path(relative)
    if source.is_absolute() or not relative or relative in {".", ".."}:
        raise NormalizationError(f"invalid normalizer source file: {relative!r}")
    candidate = output_dir
    for part in source.parts:
        candidate /= part
        if candidate.is_symlink():
            raise NormalizationError(
                f"refusing symbolic-link normalizer source file: {relative}"
            )
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(output_dir):
        raise NormalizationError(f"normalizer source file escapes raw output: {relative}")
    if not resolved.is_file():
        raise NormalizationError(f"normalizer source file does not exist: {relative}")
    return resolved


def _finding_id(
    plugin: str,
    target_id: str,
    source_file: str,
    finding: dict[str, Any],
) -> str:
    identity = {
        "plugin": plugin,
        "target_id": target_id,
        "source_file": source_file,
        "kind": finding["kind"],
        "title": finding["title"],
        "value": finding.get("value"),
        "attributes": finding.get("attributes", {}),
    }
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return f"finding-{hashlib.sha256(encoded).hexdigest()[:24]}"


def _candidate_id(
    plugin: str,
    target_id: str,
    source_file: str,
    entity_type: str,
    value: str,
) -> str:
    encoded = json.dumps(
        {
            "plugin": plugin,
            "target_id": target_id,
            "source_file": source_file,
            "type": entity_type,
            "value": value,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return f"candidate-{hashlib.sha256(encoded).hexdigest()[:24]}"


def load_reviews(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    if path.is_symlink():
        raise NormalizationError(f"refusing symbolic-link review file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NormalizationError(f"invalid analyst review file: {exc}") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != REVIEW_SCHEMA
        or not isinstance(payload.get("reviews"), dict)
    ):
        raise NormalizationError("analyst review file has an unsupported contract")
    reviews: dict[str, dict[str, Any]] = {}
    for finding_id, review in payload["reviews"].items():
        if (
            not isinstance(finding_id, str)
            or not finding_id.startswith("finding-")
            or not isinstance(review, dict)
        ):
            raise NormalizationError("analyst review file contains an invalid record")
        confidence = review.get("confidence", "unverified")
        note = review.get("note")
        updated_at = review.get("updated_at")
        if confidence not in CONFIDENCE_LEVELS:
            raise NormalizationError(f"invalid confidence for {finding_id}")
        if note is not None and not isinstance(note, str):
            raise NormalizationError(f"invalid analyst note for {finding_id}")
        if not isinstance(updated_at, str) or not updated_at:
            raise NormalizationError(f"invalid review timestamp for {finding_id}")
        reviews[finding_id] = {
            "confidence": confidence,
            "note": note,
            "updated_at": updated_at,
        }
    return reviews


def normalize_job(
    case_path: Path,
    plugin_dir: Path,
    manifest: dict[str, Any],
    state: dict[str, Any],
    status: dict[str, Any],
    reviews: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    normalizer_name = manifest.get("normalizer")
    if not normalizer_name:
        return [], []
    output_relative = state.get("output")
    if not isinstance(output_relative, str) or not output_relative:
        return [], []
    output_dir = _case_child(case_path, output_relative, "raw-output path")
    if not output_dir.is_dir():
        return [], []
    normalizer = (plugin_dir / normalizer_name).resolve()
    if not normalizer.is_relative_to(plugin_dir.resolve()) or not normalizer.is_file():
        raise NormalizationError(
            f"{manifest['id']}: configured normalizer is unavailable"
        )
    command = [sys.executable, str(normalizer), str(output_dir)]
    try:
        completed = subprocess.run(
            command,
            cwd=output_dir,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            text=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NormalizationError(f"{manifest['id']}: normalizer failed: {exc}") from exc
    if len(completed.stdout) > MAX_NORMALIZER_OUTPUT:
        raise NormalizationError(f"{manifest['id']}: normalizer output exceeded limit")
    stderr = completed.stderr.decode("utf-8", "replace").strip()
    if completed.returncode != 0:
        detail = f": {stderr}" if stderr else ""
        raise NormalizationError(
            f"{manifest['id']}: normalizer exited {completed.returncode}{detail}"
        )
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise NormalizationError(
            f"{manifest['id']}: normalizer returned invalid JSON"
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema") not in NORMALIZER_SCHEMAS
        or not isinstance(payload.get("findings"), list)
    ):
        raise NormalizationError(
            f"{manifest['id']}: normalizer returned an unsupported contract"
        )

    normalized = []
    for index, finding in enumerate(payload["findings"]):
        if not isinstance(finding, dict):
            raise NormalizationError(
                f"{manifest['id']}: finding {index} must be an object"
            )
        required = ("kind", "title", "source_file")
        if any(
            not isinstance(finding.get(field), str) or not finding[field].strip()
            for field in required
        ):
            raise NormalizationError(
                f"{manifest['id']}: finding {index} is missing required text"
            )
        value = finding.get("value")
        attributes = finding.get("attributes", {})
        if value is not None and not isinstance(value, str):
            raise NormalizationError(
                f"{manifest['id']}: finding {index} value must be text or null"
            )
        if not isinstance(attributes, dict) or not _json_value(attributes):
            raise NormalizationError(
                f"{manifest['id']}: finding {index} attributes are not JSON-safe"
            )
        source = _source_file(output_dir, finding["source_file"])
        source_relative = str(source.relative_to(case_path))
        finding_id = _finding_id(
            manifest["id"],
            state.get("target_id", ""),
            finding["source_file"],
            finding,
        )
        review = reviews.get(finding_id, {})
        normalized.append({
            "id": finding_id,
            "kind": finding["kind"].strip(),
            "category": str(finding.get("category", manifest["category"])).strip(),
            "title": finding["title"].strip(),
            "value": value,
            "confidence": review.get("confidence", "unverified"),
            "analyst_note": review.get("note"),
            "attributes": attributes,
            "target": {
                "id": state.get("target_id"),
                "type": status.get("target_type"),
                "value": status.get("target"),
            },
            "source": {
                "plugin": manifest["id"],
                "plugin_version": state.get("plugin_version"),
                "framework_version": status.get("framework_version"),
                "run_id": state.get("last_run"),
                "job_status": state.get("status"),
                "exit_code": state.get("exit_code"),
                "command": status.get("command", []),
                "started_at": status.get("started_at"),
                "completed_at": state.get("completed_at"),
                "source_file": source_relative,
                "raw_output": output_relative,
            },
        })
    candidates = []
    raw_candidates = payload.get("candidates", [])
    if payload.get("schema") == 1 and raw_candidates:
        raise NormalizationError(
            f"{manifest['id']}: schema 1 normalizer cannot emit candidates"
        )
    if not isinstance(raw_candidates, list):
        raise NormalizationError(
            f"{manifest['id']}: candidates must be an array"
        )
    emitted = set(manifest.get("entities", {}).get("emitted", []))
    for index, candidate in enumerate(raw_candidates):
        if not isinstance(candidate, dict):
            raise NormalizationError(
                f"{manifest['id']}: candidate {index} must be an object"
            )
        entity_type = candidate.get("type")
        value = candidate.get("value")
        source_file = candidate.get("source_file")
        if (
            not isinstance(entity_type, str)
            or entity_type not in emitted
            or not isinstance(value, str)
            or not value.strip()
            or not isinstance(source_file, str)
            or not source_file.strip()
        ):
            raise NormalizationError(
                f"{manifest['id']}: candidate {index} violates emitted entity contract"
            )
        source = _source_file(output_dir, source_file)
        source_relative = str(source.relative_to(case_path))
        clean_value = value.strip()
        candidates.append({
            "id": _candidate_id(
                manifest["id"],
                state.get("target_id", ""),
                source_file,
                entity_type,
                clean_value,
            ),
            "type": entity_type,
            "value": clean_value,
            "classification": "extracted_observation",
            "target": {
                "id": state.get("target_id"),
                "type": status.get("target_type"),
                "value": status.get("target"),
            },
            "source": {
                "plugin": manifest["id"],
                "plugin_version": state.get("plugin_version"),
                "framework_version": status.get("framework_version"),
                "run_id": state.get("last_run"),
                "command": status.get("command", []),
                "started_at": status.get("started_at"),
                "completed_at": state.get("completed_at"),
                "source_file": source_relative,
                "raw_output": output_relative,
            },
        })
    return normalized, candidates


def build_report(
    case_path: Path,
    metadata: dict[str, Any],
    catalog: dict[str, tuple[Path, dict[str, Any]]],
    framework_version: str,
    *,
    intelligence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reviews_path = _case_child(
        case_path, "findings/reviews.json", "analyst-review path"
    )
    reviews = load_reviews(reviews_path)
    outcomes = []
    findings = []
    candidates = []
    errors = []
    targets_by_id = {
        target["id"]: target for target in metadata["targets"]
    }
    for job_id, state in sorted(metadata["jobs"].items()):
        output_relative = state.get("output")
        status: dict[str, Any] = {}
        if isinstance(output_relative, str) and output_relative:
            try:
                output_dir = _case_child(case_path, output_relative, "raw-output path")
                status_path = output_dir / "status.json"
                if status_path.is_symlink():
                    raise NormalizationError(
                        f"refusing symbolic-link status record: {output_relative}"
                    )
                if status_path.is_file():
                    status = json.loads(status_path.read_text(encoding="utf-8"))
                    if not isinstance(status, dict):
                        raise ValueError("status root is not an object")
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError,
                    NormalizationError) as exc:
                errors.append({
                    "job_id": job_id,
                    "plugin": state.get("plugin"),
                    "error": f"invalid status record: {exc}",
                })
        if status:
            target = targets_by_id.get(state.get("target_id"))
            mismatches = []
            if status.get("plugin") != state.get("plugin"):
                mismatches.append("plugin")
            if status.get("target_id") != state.get("target_id"):
                mismatches.append("target ID")
            if status.get("plugin_version") != state.get("plugin_version"):
                mismatches.append("plugin version")
            if status.get("exit_code") != state.get("exit_code"):
                mismatches.append("exit code")
            if target and (
                status.get("target_type") != target["type"]
                or status.get("target") != target["value"]
            ):
                mismatches.append("target")
            if mismatches:
                errors.append({
                    "job_id": job_id,
                    "plugin": state.get("plugin"),
                    "error": (
                        "status provenance does not match case state: "
                        + ", ".join(mismatches)
                    ),
                })
                status = {}
        outcome = {
            "job_id": job_id,
            "plugin": state.get("plugin"),
            "plugin_version": state.get("plugin_version"),
            "target_id": state.get("target_id"),
            "status": state.get("status"),
            "exit_code": state.get("exit_code"),
            "run_id": state.get("last_run"),
            "started_at": status.get("started_at"),
            "completed_at": state.get("completed_at"),
            "command": status.get("command", []),
            "raw_output": output_relative,
            "error": status.get("error"),
        }
        outcomes.append(outcome)
        plugin_id = state.get("plugin")
        plugin = catalog.get(plugin_id)
        if not plugin or not status or state.get("status") != "completed":
            continue
        plugin_dir, manifest = plugin
        try:
            normalized_findings, normalized_candidates = normalize_job(
                case_path, plugin_dir, manifest, state, status, reviews
            )
            findings.extend(normalized_findings)
            candidates.extend(normalized_candidates)
        except NormalizationError as exc:
            errors.append({
                "job_id": job_id,
                "plugin": plugin_id,
                "error": str(exc),
            })

    findings.sort(key=lambda item: (
        item["category"], item["kind"], item["title"], item["id"]
    ))
    candidates.sort(key=lambda item: (item["type"], item["value"], item["id"]))
    target_ids = {target["id"] for target in metadata["targets"]}
    current_finding_ids = {finding["id"] for finding in findings}
    orphaned_reviews = sorted(set(reviews) - current_finding_ids)
    has_intelligence = intelligence is not None
    graph = copy.deepcopy(intelligence) if has_intelligence else {
        "schema": 1, "case_id": metadata["id"], "entities": [],
        "observations": [], "relationships": [], "contradictions": [],
        "source_groups": [],
    }
    report = {
        "schema": REPORT_SCHEMA if has_intelligence else 2,
        "report_type": "osint-forge.normalized-case-report",
        "framework_version": framework_version,
        "generated_at": metadata["updated_at"],
        "redaction": {"shareable": False, "policy": None},
        "case": {
            "id": metadata["id"],
            "schema": metadata["schema"],
            "purpose": metadata["purpose"],
            "authorization_scope": metadata["authorization_scope"],
            "created_at": metadata["created_at"],
            "updated_at": metadata["updated_at"],
        },
        "summary": {
            "target_count": len(metadata["targets"]),
            "job_count": len(outcomes),
            "completed_jobs": sum(item["status"] == "completed" for item in outcomes),
            "failed_jobs": sum(item["status"] == "failed" for item in outcomes),
            "previewed_jobs": sum(item["status"] == "previewed" for item in outcomes),
            "finding_count": len(findings),
            "candidate_count": len(candidates),
            "normalization_error_count": len(errors),
        },
        "targets": sorted(
            (copy.deepcopy(target) for target in metadata["targets"]),
            key=lambda item: (item["type"], item["id"]),
        ),
        "outcomes": outcomes,
        "findings": findings,
        "candidates": candidates,
        "normalization_errors": errors,
        "orphaned_review_ids": orphaned_reviews,
        "integrity": {
            "all_finding_targets_known": all(
                finding["target"]["id"] in target_ids for finding in findings
            ),
            "all_findings_traceable": all(
                finding["source"]["source_file"]
                and finding["source"]["raw_output"]
                for finding in findings
            ),
            "all_candidates_traceable": all(
                candidate["target"]["id"] in target_ids
                and candidate["source"]["source_file"]
                and candidate["source"]["raw_output"]
                for candidate in candidates
            ),
        },
    }
    if has_intelligence:
        report["summary"].update({
            "provider_observation_count": len(graph["observations"]),
            "relationship_count": len(graph["relationships"]),
            "contradiction_count": len(graph["contradictions"]),
        })
        report["intelligence"] = graph
    return report


def redact_report(report: dict[str, Any]) -> dict[str, Any]:
    redacted = copy.deepcopy(report)
    redacted["redaction"] = {
        "shareable": True,
        "policy": "structure-only-v1",
    }
    redacted["case"]["id"] = "shared-case"
    redacted["case"]["purpose"] = "[redacted]"
    redacted["case"]["authorization_scope"] = "[redacted]"
    target_map = {
        target["id"]: f"target-{index:03d}"
        for index, target in enumerate(redacted["targets"], 1)
    }
    for target in redacted["targets"]:
        target["id"] = target_map[target["id"]]
        target["value"] = "[redacted]"
    finding_map = {
        finding["id"]: f"finding-{index:03d}"
        for index, finding in enumerate(redacted["findings"], 1)
    }
    job_map = {
        outcome["job_id"]: f"job-{index:03d}"
        for index, outcome in enumerate(redacted["outcomes"], 1)
    }
    run_map = {
        run_id: f"run-{index:03d}"
        for index, run_id in enumerate(
            sorted({
                outcome["run_id"]
                for outcome in redacted["outcomes"]
                if outcome["run_id"]
            }),
            1,
        )
    }
    for outcome in redacted["outcomes"]:
        outcome["job_id"] = job_map[outcome["job_id"]]
        outcome["target_id"] = target_map.get(outcome["target_id"], "[redacted]")
        outcome["run_id"] = run_map.get(outcome["run_id"])
        outcome["command"] = ["[redacted]"] if outcome["command"] else []
        outcome["raw_output"] = None
        outcome["error"] = "[redacted]" if outcome["error"] else None
    for finding in redacted["findings"]:
        finding["id"] = finding_map[finding["id"]]
        finding["value"] = "[redacted]" if finding["value"] is not None else None
        finding["attributes"] = {"redacted": True}
        finding["analyst_note"] = None
        finding["target"]["id"] = target_map.get(
            finding["target"]["id"], "[redacted]"
        )
        finding["target"]["value"] = "[redacted]"
        finding["source"]["command"] = (
            ["[redacted]"] if finding["source"]["command"] else []
        )
        finding["source"]["run_id"] = run_map.get(finding["source"]["run_id"])
        finding["source"]["source_file"] = None
        finding["source"]["raw_output"] = None
    for index, candidate in enumerate(redacted["candidates"], 1):
        candidate["id"] = f"candidate-{index:03d}"
        candidate["value"] = "[redacted]"
        candidate["target"]["id"] = target_map.get(
            candidate["target"]["id"], "[redacted]"
        )
        candidate["target"]["value"] = "[redacted]"
        candidate["source"]["command"] = (
            ["[redacted]"] if candidate["source"]["command"] else []
        )
        candidate["source"]["run_id"] = run_map.get(candidate["source"]["run_id"])
        candidate["source"]["source_file"] = None
        candidate["source"]["raw_output"] = None
    redacted["normalization_errors"] = [
        {
            "job_id": job_map.get(item.get("job_id"), "[redacted]"),
            "plugin": item.get("plugin"),
            "error": "[redacted]",
        }
        for item in redacted["normalization_errors"]
    ]
    redacted["orphaned_review_ids"] = []
    graph = redacted.get("intelligence")
    def redacted_confidence(value: dict[str, Any] | None) -> dict[str, Any] | None:
        if not value:
            return value
        return {
            "scope": value.get("scope"),
            "score": value.get("score"),
            "method": value.get("method"),
            "assessed_at": value.get("assessed_at"),
            "independent_source_count": len(
                value.get("independent_source_groups", [])
            ),
            "dependent_observation_count": value.get(
                "dependent_observation_count", 0
            ),
            "contradiction_count": len(value.get("contradictions", [])),
            "verification_status": value.get("verification_status"),
        }
    if graph is not None:
        graph["case_id"] = "shared-case"
        graph["entities"] = [
        {
            "id": f"entity-{index:03d}", "type": item["type"],
            "value": "[redacted]", "canonical_value": "[redacted]",
            "observation_count": len(item.get("observations", [])),
            "confidence": redacted_confidence(item.get("confidence")),
        }
            for index, item in enumerate(graph.get("entities", []), 1)
        ]
        graph["observations"] = []
        graph["relationships"] = []
        graph["contradictions"] = []
        graph["source_groups"] = []
    redacted["integrity"]["all_findings_traceable"] = False
    redacted["integrity"]["all_candidates_traceable"] = False
    return redacted


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(
        report, indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"


def _markdown(value: Any) -> str:
    return (
        str(value if value is not None else "")
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "&#96;")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _relative_link(report_path: Path, case_path: Path, raw: str | None) -> str:
    if not raw:
        return ""
    return Path(os.path.relpath(case_path / raw, report_path.parent)).as_posix()


def render_markdown(
    report: dict[str, Any], report_path: Path, case_path: Path
) -> str:
    case = report["case"]
    summary = report["summary"]
    lines = [
        f"# OSINT Forge Case: {_markdown(case['id'])}",
        "",
        f"- **Report schema:** {report['schema']}",
        f"- **Case schema:** {case['schema']}",
        f"- **Purpose:** {_markdown(case['purpose'])}",
        f"- **Authorization scope:** {_markdown(case['authorization_scope'])}",
        f"- **Created:** {_markdown(case['created_at'])}",
        f"- **Updated:** {_markdown(case['updated_at'])}",
        f"- **Shareable redaction:** "
        f"{'yes' if report['redaction']['shareable'] else 'no'}",
        "",
        "## Summary",
        "",
        f"- Targets: {summary['target_count']}",
        f"- Jobs: {summary['job_count']}",
        f"- Completed jobs: {summary['completed_jobs']}",
        f"- Failed jobs: {summary['failed_jobs']}",
        f"- Previewed jobs: {summary['previewed_jobs']}",
        f"- Normalized findings: {summary['finding_count']}",
        f"- Candidate observations: {summary['candidate_count']}",
        f"- Normalization errors: {summary['normalization_error_count']}",
        "",
        "## Targets",
        "",
        "| ID | Type | Target | Added |",
        "|---|---|---|---|",
    ]
    for target in report["targets"]:
        lines.append(
            f"| `{_markdown(target['id'])}` | {_markdown(target['type'])} | "
            f"`{_markdown(target['value'])}` | {_markdown(target['added_at'])} |"
        )
    lines.extend([
        "",
        "## Execution outcomes",
        "",
        "| Plugin | Target ID | Status | Exit | Raw output |",
        "|---|---|---|---:|---|",
    ])
    for outcome in report["outcomes"]:
        link = _relative_link(report_path, case_path, outcome["raw_output"])
        raw = f"[preserved output]({link})" if link else "redacted or unavailable"
        lines.append(
            f"| {_markdown(outcome['plugin'])} | "
            f"`{_markdown(outcome['target_id'])}` | "
            f"{_markdown(outcome['status'])} | "
            f"{_markdown(outcome['exit_code'])} | {raw} |"
        )
    lines.extend(["", "## Normalized findings", ""])
    if not report["findings"]:
        lines.append("No normalized findings were produced.")
    for finding in report["findings"]:
        source = finding["source"]
        source_link = _relative_link(
            report_path, case_path, source["source_file"]
        )
        lines.extend([
            f"### {_markdown(finding['title'])}",
            "",
            f"- **Finding ID:** `{_markdown(finding['id'])}`",
            f"- **Kind:** {_markdown(finding['kind'])}",
            f"- **Category:** {_markdown(finding['category'])}",
            f"- **Value:** `{_markdown(finding['value'])}`",
            f"- **Confidence:** {_markdown(finding['confidence'])}",
            f"- **Analyst note:** {_markdown(finding['analyst_note']) or 'None'}",
            f"- **Target:** `{_markdown(finding['target']['id'])}`",
            f"- **Source plugin:** {_markdown(source['plugin'])}",
            f"- **Job outcome:** {_markdown(source['job_status'])} "
            f"(exit {_markdown(source['exit_code'])})",
            (
                f"- **Raw source:** [preserved source]({source_link})"
                if source_link else "- **Raw source:** redacted or unavailable"
            ),
            "",
        ])
    lines.extend(["## Candidate observations", ""])
    if not report["candidates"]:
        lines.append("No candidate entities were extracted.")
    else:
        lines.extend([
            "| ID | Type | Value | Source plugin | Target | Raw source |",
            "|---|---|---|---|---|---|",
        ])
        for candidate in report["candidates"]:
            source = candidate["source"]
            source_link = _relative_link(
                report_path, case_path, source["source_file"]
            )
            raw = (
                f"[preserved source]({source_link})"
                if source_link else "redacted or unavailable"
            )
            lines.append(
                f"| `{_markdown(candidate['id'])}` | "
                f"{_markdown(candidate['type'])} | "
                f"`{_markdown(candidate['value'])}` | "
                f"{_markdown(source['plugin'])} | "
                f"`{_markdown(candidate['target']['id'])}` | {raw} |"
            )
    lines.append("")
    intelligence = report.get("intelligence")
    if intelligence is not None:
        lines[lines.index("## Targets"):lines.index("## Targets")] = [
            f"- Provider observations: {summary['provider_observation_count']}",
            f"- Evidence-backed relationships: {summary['relationship_count']}",
            f"- Contradictions: {summary['contradiction_count']}",
            "",
        ]
        lines.extend(["## Correlation and confidence", ""])
    if intelligence is None:
        intelligence = {"observations": [], "relationships": []}
    elif not intelligence["relationships"]:
        lines.append("No provider relationships were correlated.")
    for relationship in intelligence["relationships"]:
        confidence = relationship["confidence"]
        lines.extend([
            f"### `{_markdown(relationship['id'])}`",
            "",
            f"- **Relationship:** `{_markdown(relationship['source_entity_id'])}` "
            f"{_markdown(relationship['type'])} `{_markdown(relationship['target_entity_id'])}`",
            f"- **Inference:** {_markdown(relationship['inference_state'])}",
            f"- **Verification:** {_markdown(relationship['verification_status'])}",
            f"- **Temporal status:** {_markdown(relationship['temporal_status'])}",
            f"- **Relationship confidence:** {_markdown(confidence['score'])} "
            f"({_markdown(confidence['method'])})",
            f"- **Independent sources:** {len(confidence['independent_source_groups'])}",
            f"- **Contradictions:** {len(relationship['contradictions'])}",
            "",
        ])
    if any(
        item["verification_status"] in {"tool_unavailable", "tool_failed", "not_attempted"}
        for item in intelligence["observations"] + intelligence["relationships"]
    ):
        lines.extend([
            "> Some provider evidence is tool-unverified. Tool failure, unavailability, "
            "or no attempt is neither confirmation nor contradiction; confidence uses "
            "the remaining source evidence.", "",
        ])
    if report["normalization_errors"]:
        lines.extend(["## Normalization errors", ""])
        for error in report["normalization_errors"]:
            lines.append(
                f"- `{_markdown(error.get('job_id'))}` "
                f"({_markdown(error.get('plugin'))}): "
                f"{_markdown(error.get('error'))}"
            )
        lines.append("")
    lines.extend([
        "> Raw tool output is not a verified finding. Normalized findings are "
        "unverified leads, not established facts. Validate every lead "
        "independently against preserved raw evidence.",
        "",
    ])
    return "\n".join(lines)


def render_html(
    report: dict[str, Any], report_path: Path, case_path: Path
) -> str:
    esc = lambda value: html.escape(str(value if value is not None else ""))
    outcome_rows = []
    for outcome in report["outcomes"]:
        raw_link = _relative_link(
            report_path, case_path, outcome["raw_output"]
        )
        raw = (
            f'<a href="{html.escape(raw_link, quote=True)}">preserved output</a>'
            if raw_link else "redacted or unavailable"
        )
        outcome_rows.append(
            "<tr>"
            f"<td>{esc(outcome['plugin'])}</td>"
            f"<td><code>{esc(outcome['target_id'])}</code></td>"
            f"<td>{esc(outcome['status'])}</td>"
            f"<td>{esc(outcome['exit_code'])}</td>"
            f"<td>{esc(outcome['error'])}</td>"
            f"<td>{raw}</td>"
            "</tr>"
        )
    candidate_rows = []
    for candidate in report["candidates"]:
        source_link = _relative_link(
            report_path, case_path, candidate["source"]["source_file"]
        )
        raw = (
            f'<a href="{html.escape(source_link, quote=True)}">preserved source</a>'
            if source_link else "redacted or unavailable"
        )
        candidate_rows.append(
            "<tr>"
            f"<td><code>{esc(candidate['id'])}</code></td>"
            f"<td>{esc(candidate['type'])}</td>"
            f"<td><code>{esc(candidate['value'])}</code></td>"
            f"<td>{esc(candidate['source']['plugin'])}</td>"
            f"<td><code>{esc(candidate['target']['id'])}</code></td>"
            f"<td>{raw}</td>"
            "</tr>"
        )
    rows = []
    for finding in report["findings"]:
        source_link = _relative_link(
            report_path, case_path, finding["source"]["source_file"]
        )
        raw = (
            f'<a href="{html.escape(source_link, quote=True)}">preserved source</a>'
            if source_link else "redacted or unavailable"
        )
        rows.append(
            "<tr>"
            f"<td><code>{esc(finding['id'])}</code></td>"
            f"<td>{esc(finding['category'])}</td>"
            f"<td>{esc(finding['kind'])}</td>"
            f"<td>{esc(finding['title'])}</td>"
            f"<td><code>{esc(finding['value'])}</code></td>"
            f"<td>{esc(finding['confidence'])}</td>"
            f"<td>{esc(finding['analyst_note'])}</td>"
            f"<td>{esc(finding['source']['plugin'])}</td>"
            f"<td>{raw}</td>"
            "</tr>"
        )
    errors = "".join(
        f"<li><code>{esc(item.get('job_id'))}</code> "
        f"({esc(item.get('plugin'))}): {esc(item.get('error'))}</li>"
        for item in report["normalization_errors"]
    )
    intelligence = report.get("intelligence", {"observations": [], "relationships": []})
    relationship_rows = "".join(
        "<tr>"
        f"<td><code>{esc(item['id'])}</code></td>"
        f"<td>{esc(item['type'])}</td>"
        f"<td>{esc(item['verification_status'])}</td>"
        f"<td>{esc(item['temporal_status'])}</td>"
        f"<td>{esc(item['confidence']['score'])}</td>"
        f"<td>{len(item['confidence']['independent_source_groups'])}</td>"
        f"<td>{len(item['contradictions'])}</td>"
        "</tr>"
        for item in intelligence["relationships"]
    )
    tool_unverified = any(
        item["verification_status"] in {
            "tool_unavailable", "tool_failed", "not_attempted"
        }
        for item in (
            intelligence["observations"] + intelligence["relationships"]
        )
    )
    summary = report["summary"]
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSINT Forge Case: {esc(report['case']['id'])}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.45; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #bbb; padding: .45rem; text-align: left; }}
th {{ background: #eee; }}
code {{ overflow-wrap: anywhere; }}
.warning {{ border-left: .3rem solid #b45309; padding: .75rem; background: #fff7ed; }}
</style>
</head>
<body>
<h1>OSINT Forge Case: {esc(report['case']['id'])}</h1>
<p><strong>Purpose:</strong> {esc(report['case']['purpose'])}<br>
<strong>Authorization scope:</strong> {esc(report['case']['authorization_scope'])}<br>
<strong>Shareable redaction:</strong> {'yes' if report['redaction']['shareable'] else 'no'}</p>
<h2>Summary</h2>
<ul>
<li>Targets: {summary['target_count']}</li>
<li>Jobs: {summary['job_count']}</li>
<li>Completed: {summary['completed_jobs']}</li>
<li>Failed: {summary['failed_jobs']}</li>
<li>Findings: {summary['finding_count']}</li>
<li>Candidate observations: {summary['candidate_count']}</li>
<li>Normalization errors: {summary['normalization_error_count']}</li>
{f"<li>Provider observations: {summary['provider_observation_count']}</li>" if 'intelligence' in report else ''}
{f"<li>Evidence-backed relationships: {summary['relationship_count']}</li>" if 'intelligence' in report else ''}
{f"<li>Contradictions: {summary['contradiction_count']}</li>" if 'intelligence' in report else ''}
</ul>
<h2>Execution outcomes</h2>
<table>
<thead><tr><th>Plugin</th><th>Target</th><th>Status</th><th>Exit</th>
<th>Error</th><th>Raw output</th></tr></thead>
<tbody>{''.join(outcome_rows)}</tbody>
</table>
<h2>Normalized findings</h2>
<table>
<thead><tr><th>ID</th><th>Category</th><th>Kind</th><th>Title</th>
<th>Value</th><th>Confidence</th><th>Analyst note</th><th>Plugin</th>
<th>Raw source</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
<h2>Candidate observations</h2>
<table>
<thead><tr><th>ID</th><th>Type</th><th>Value</th><th>Plugin</th>
<th>Target</th><th>Raw source</th></tr></thead>
<tbody>{''.join(candidate_rows)}</tbody>
</table>
{'<h2>Correlation and confidence</h2>' if 'intelligence' in report else ''}
<table>
<thead><tr><th>ID</th><th>Relationship</th><th>Verification</th>
<th>Temporal status</th><th>Confidence</th><th>Independent sources</th>
<th>Contradictions</th></tr></thead>
<tbody>{relationship_rows}</tbody>
</table>
{('<p class="warning">Some provider evidence is tool-unverified. Tool failure, '
  'unavailability, or no attempt is neither confirmation nor contradiction.</p>')
 if tool_unverified else ''}
{f'<h2>Normalization errors</h2><ul>{errors}</ul>' if errors else ''}
<p class="warning">Normalized findings are unverified leads, not established facts.
Validate every lead independently against preserved raw evidence.</p>
</body>
</html>
"""


def render_csv(report: dict[str, Any]) -> str:
    output = io.StringIO(newline="")
    legacy_fields = [
        "finding_id", "category", "kind", "title", "value", "confidence",
        "analyst_note", "target_id", "target_type", "target_value", "plugin",
        "job_status", "exit_code", "source_file", "raw_output", "attributes_json",
    ]
    fields = [
        "record_type", "finding_id", "relationship_id", "category", "kind",
        "title", "value", "confidence",
        "analyst_note", "target_id", "target_type", "target_value", "plugin",
        "job_status", "exit_code", "source_file", "raw_output",
        "attributes_json", "verification_status", "temporal_status",
        "independent_source_count", "contradiction_count",
    ] if "intelligence" in report else legacy_fields
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for finding in report["findings"]:
        writer.writerow({
            **({"record_type": "finding"} if "intelligence" in report else {}),
            "finding_id": finding["id"],
            "category": finding["category"],
            "kind": finding["kind"],
            "title": finding["title"],
            "value": finding["value"],
            "confidence": finding["confidence"],
            "analyst_note": finding["analyst_note"],
            "target_id": finding["target"]["id"],
            "target_type": finding["target"]["type"],
            "target_value": finding["target"]["value"],
            "plugin": finding["source"]["plugin"],
            "job_status": finding["source"]["job_status"],
            "exit_code": finding["source"]["exit_code"],
            "source_file": finding["source"]["source_file"],
            "raw_output": finding["source"]["raw_output"],
            "attributes_json": json.dumps(
                finding["attributes"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ),
        })
    for relationship in report.get("intelligence", {}).get("relationships", []):
        writer.writerow({
            "record_type": "relationship",
            "relationship_id": relationship["id"],
            "kind": relationship["type"],
            "confidence": relationship["confidence"]["score"],
            "verification_status": relationship["verification_status"],
            "temporal_status": relationship["temporal_status"],
            "independent_source_count": len(
                relationship["confidence"]["independent_source_groups"]
            ),
            "contradiction_count": len(relationship["contradictions"]),
        })
    return output.getvalue()
