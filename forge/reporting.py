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

REPORT_SCHEMA = 1
NORMALIZER_SCHEMA = 1
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
) -> list[dict[str, Any]]:
    normalizer_name = manifest.get("normalizer")
    if not normalizer_name:
        return []
    output_relative = state.get("output")
    if not isinstance(output_relative, str) or not output_relative:
        return []
    output_dir = _case_child(case_path, output_relative, "raw-output path")
    if not output_dir.is_dir():
        return []
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
        or payload.get("schema") != NORMALIZER_SCHEMA
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
    return normalized


def build_report(
    case_path: Path,
    metadata: dict[str, Any],
    catalog: dict[str, tuple[Path, dict[str, Any]]],
    framework_version: str,
) -> dict[str, Any]:
    reviews_path = _case_child(
        case_path, "findings/reviews.json", "analyst-review path"
    )
    reviews = load_reviews(reviews_path)
    outcomes = []
    findings = []
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
            findings.extend(
                normalize_job(
                    case_path, plugin_dir, manifest, state, status, reviews
                )
            )
        except NormalizationError as exc:
            errors.append({
                "job_id": job_id,
                "plugin": plugin_id,
                "error": str(exc),
            })

    findings.sort(key=lambda item: (
        item["category"], item["kind"], item["title"], item["id"]
    ))
    target_ids = {target["id"] for target in metadata["targets"]}
    current_finding_ids = {finding["id"] for finding in findings}
    orphaned_reviews = sorted(set(reviews) - current_finding_ids)
    return {
        "schema": REPORT_SCHEMA,
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
            "normalization_error_count": len(errors),
        },
        "targets": sorted(
            (copy.deepcopy(target) for target in metadata["targets"]),
            key=lambda item: (item["type"], item["id"]),
        ),
        "outcomes": outcomes,
        "findings": findings,
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
        },
    }


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
    redacted["normalization_errors"] = [
        {
            "job_id": job_map.get(item.get("job_id"), "[redacted]"),
            "plugin": item.get("plugin"),
            "error": "[redacted]",
        }
        for item in redacted["normalization_errors"]
    ]
    redacted["orphaned_review_ids"] = []
    redacted["integrity"]["all_findings_traceable"] = False
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
<li>Normalization errors: {summary['normalization_error_count']}</li>
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
{f'<h2>Normalization errors</h2><ul>{errors}</ul>' if errors else ''}
<p class="warning">Normalized findings are unverified leads, not established facts.
Validate every lead independently against preserved raw evidence.</p>
</body>
</html>
"""


def render_csv(report: dict[str, Any]) -> str:
    output = io.StringIO(newline="")
    fields = [
        "finding_id", "category", "kind", "title", "value", "confidence",
        "analyst_note", "target_id", "target_type", "target_value", "plugin",
        "job_status", "exit_code", "source_file", "raw_output",
        "attributes_json",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for finding in report["findings"]:
        writer.writerow({
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
    return output.getvalue()
