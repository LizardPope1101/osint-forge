#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Deterministic, provenance-preserving correlation contracts for v0.8."""
from __future__ import annotations

import hashlib
import json
import math
import datetime as dt
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit, urlunsplit

PROVIDER_SCHEMA = 1
GRAPH_SCHEMA = 1
VERIFICATION_STATES = {
    "verified", "contradicted", "inconclusive", "tool_unavailable",
    "tool_failed", "not_applicable", "not_attempted",
}
TEMPORAL_STATES = {
    "current_high_confidence", "current_probable",
    "historical_high_confidence", "conflicting", "unresolved", "rejected",
}
CONFIDENCE_SCOPES = {
    "observation", "relationship", "identity", "currentness",
}
INFERENCE_STATES = {"automated", "rejected"}
PAYLOAD_FIELDS = {"schema", "provider", "query", "results"}
QUERY_FIELDS = {"type", "value"}
RESULT_FIELDS = {
    "url", "title", "snippet", "source_file", "observed_at",
    "published_at", "entities", "relationships", "source_identity",
    "verification_status", "verification", "temporal_status",
}
ENTITY_FIELDS = {"type", "value"}
RELATIONSHIP_FIELDS = {
    "source", "target", "type", "inference_state", "verification_status",
    "verification", "temporal_status",
}
VERIFICATION_FIELDS = {"sensor", "sensor_version", "method", "evidence"}
SOURCE_IDENTITY_FIELDS = {
    "canonical_url", "publisher", "content_fingerprint", "syndication_group",
}
MAX_RESULTS = 10_000
MAX_TEXT = 1_000_000
ENTITY_TYPES = {
    "address", "domain", "email", "file", "image", "ip", "name", "phone",
    "username",
}


class CorrelationError(ValueError):
    """Provider evidence or a correlation contract is unsafe or invalid."""


def _stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:24]}"


def _object(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CorrelationError(f"{context} must be an object")
    unknown = sorted(set(value) - fields)
    if unknown:
        raise CorrelationError(f"{context} has unknown fields: {', '.join(unknown)}")
    return value


def _text(value: Any, context: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise CorrelationError(f"{context} must be non-empty bounded text")
    if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
        raise CorrelationError(f"{context} contains control characters")
    return value.strip()


def canonical_url(value: str) -> str:
    """Return a conservative URL identity without fetching or resolving it."""
    raw = _text(value, "URL")
    assert raw is not None
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise CorrelationError(f"invalid URL: {exc}") from exc
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        raise CorrelationError("URL must use http or https with a host")
    if parsed.username is not None or parsed.password is not None:
        raise CorrelationError("URL credentials are not permitted")
    host = parsed.hostname.casefold().rstrip(".")
    if not host:
        raise CorrelationError("URL host is empty")
    default_port = (parsed.scheme.casefold() == "http" and port == 80) or (
        parsed.scheme.casefold() == "https" and port == 443
    )
    authority = host if port is None or default_port else f"{host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.casefold(), authority, path, parsed.query, ""))


def _case_file(case_path: Path, relative: str) -> Path:
    candidate_relative = Path(relative)
    if candidate_relative.is_absolute() or not relative or candidate_relative in {Path("."), Path("..")}:
        raise CorrelationError(f"invalid provider source file: {relative!r}")
    candidate = case_path
    for part in candidate_relative.parts:
        candidate /= part
        if candidate.is_symlink():
            raise CorrelationError(f"refusing symbolic-link provider source: {relative}")
    resolved_case = case_path.resolve()
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(resolved_case):
        raise CorrelationError(f"provider source escapes case directory: {relative}")
    if not resolved.is_file():
        raise CorrelationError(f"provider source does not exist: {relative}")
    return resolved


def load_provider_payload(case_path: Path, relative: str) -> dict[str, Any]:
    """Load and validate a provider payload from a regular case-bounded file."""
    source = _case_file(case_path, relative)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CorrelationError(f"invalid provider payload: {exc}") from exc
    clean = validate_provider_payload(payload)
    for result in clean["results"]:
        _case_file(case_path, result["source_file"])
    return clean


def _entity(value: Any, context: str) -> dict[str, str]:
    item = _object(value, ENTITY_FIELDS, context)
    if set(item) != ENTITY_FIELDS:
        raise CorrelationError(f"{context} requires type and value")
    entity_type = _text(item["type"], f"{context}.type")
    if entity_type not in ENTITY_TYPES:
        raise CorrelationError(f"{context}.type is unsupported")
    return {
        "type": entity_type,
        "value": _text(item["value"], f"{context}.value"),
    }


def _verification(value: Any, status: str, context: str) -> dict[str, Any] | None:
    if status in {"not_attempted", "not_applicable"} and value is None:
        return None
    record = _object(value, VERIFICATION_FIELDS, context)
    if set(record) != VERIFICATION_FIELDS:
        raise CorrelationError(
            f"{context} requires sensor, sensor_version, method, and evidence"
        )
    evidence = record["evidence"]
    if not isinstance(evidence, list) or not all(
        isinstance(item, str) and item.strip() for item in evidence
    ):
        raise CorrelationError(f"{context}.evidence must be a string array")
    if status in {"verified", "contradicted", "inconclusive", "tool_failed"} and not evidence:
        raise CorrelationError(f"{context}.evidence is required for {status}")
    return {
        "sensor": _text(record["sensor"], f"{context}.sensor"),
        "sensor_version": _text(record["sensor_version"], f"{context}.sensor_version"),
        "method": _text(record["method"], f"{context}.method"),
        "evidence": sorted(set(item.strip() for item in evidence)),
    }


def validate_provider_payload(payload: Any) -> dict[str, Any]:
    """Strictly validate a versioned normalized search-provider payload."""
    data = _object(payload, PAYLOAD_FIELDS, "provider payload")
    if set(data) != PAYLOAD_FIELDS:
        raise CorrelationError("provider payload requires schema, provider, query, and results")
    if data["schema"] != PROVIDER_SCHEMA:
        if isinstance(data["schema"], int) and data["schema"] > PROVIDER_SCHEMA:
            raise CorrelationError(f"provider schema {data['schema']} is newer than supported schema {PROVIDER_SCHEMA}")
        raise CorrelationError(f"unsupported provider schema {data['schema']!r}")
    provider = _text(data["provider"], "provider")
    query = _object(data["query"], QUERY_FIELDS, "query")
    if set(query) != QUERY_FIELDS:
        raise CorrelationError("query requires type and value")
    clean_query = {
        "type": _text(query["type"], "query.type"),
        "value": _text(query["value"], "query.value"),
    }
    if clean_query["type"] not in ENTITY_TYPES:
        raise CorrelationError("query.type is unsupported")
    if not isinstance(data["results"], list) or len(data["results"]) > MAX_RESULTS:
        raise CorrelationError("results must be a bounded array")
    results = []
    required = {"url", "title", "snippet", "source_file", "observed_at", "entities", "relationships", "source_identity"}
    for index, raw in enumerate(data["results"]):
        context = f"results[{index}]"
        item = _object(raw, RESULT_FIELDS, context)
        if not required <= set(item):
            raise CorrelationError(f"{context} is missing required fields")
        source_identity = _object(item["source_identity"], SOURCE_IDENTITY_FIELDS, f"{context}.source_identity")
        canonical = canonical_url(source_identity.get("canonical_url", item["url"]))
        fingerprint = source_identity.get("content_fingerprint")
        if fingerprint is not None and (
            not isinstance(fingerprint, str) or len(fingerprint) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in fingerprint)
        ):
            raise CorrelationError(f"{context}.source_identity.content_fingerprint must be a SHA-256 hex digest")
        entities = item["entities"]
        relationships = item["relationships"]
        if not isinstance(entities, list) or not isinstance(relationships, list):
            raise CorrelationError(f"{context} entities and relationships must be arrays")
        clean_relationships = []
        for rel_index, raw_relationship in enumerate(relationships):
            rel_context = f"{context}.relationships[{rel_index}]"
            relationship = _object(raw_relationship, RELATIONSHIP_FIELDS, rel_context)
            if not {"source", "target", "type"} <= set(relationship):
                raise CorrelationError(f"{rel_context} requires source, target, and type")
            verification = relationship.get("verification_status", item.get("verification_status", "not_attempted"))
            temporal = relationship.get("temporal_status", item.get("temporal_status", "unresolved"))
            inference = relationship.get("inference_state", "automated")
            if verification not in VERIFICATION_STATES or temporal not in TEMPORAL_STATES or inference not in INFERENCE_STATES:
                raise CorrelationError(f"{rel_context} has an unsupported analytical state")
            clean_relationships.append({
                "source": _entity(relationship["source"], f"{rel_context}.source"),
                "target": _entity(relationship["target"], f"{rel_context}.target"),
                "type": _text(relationship["type"], f"{rel_context}.type"),
                "inference_state": inference,
                "verification_status": verification,
                "verification": _verification(
                    relationship.get("verification", item.get("verification")),
                    verification,
                    f"{rel_context}.verification",
                ),
                "temporal_status": temporal,
            })
        verification = item.get("verification_status", "not_attempted")
        temporal = item.get("temporal_status", "unresolved")
        if verification not in VERIFICATION_STATES or temporal not in TEMPORAL_STATES:
            raise CorrelationError(f"{context} has an unsupported analytical state")
        verification_record = _verification(
            item.get("verification"), verification, f"{context}.verification"
        )
        observed_at = _text(item["observed_at"], f"{context}.observed_at")
        published_at = _text(
            item.get("published_at"), f"{context}.published_at", optional=True
        )
        for label, timestamp in (("observed_at", observed_at), ("published_at", published_at)):
            if timestamp is None:
                continue
            try:
                parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError as exc:
                raise CorrelationError(f"{context}.{label} must be an ISO-8601 timestamp") from exc
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise CorrelationError(f"{context}.{label} must include a timezone")
        results.append({
            "url": canonical_url(item["url"]),
            "title": _text(item["title"], f"{context}.title"),
            "snippet": _text(item["snippet"], f"{context}.snippet"),
            "source_file": _text(item["source_file"], f"{context}.source_file"),
            "observed_at": observed_at,
            "published_at": published_at,
            "entities": [_entity(entity, f"{context}.entities[{entity_index}]") for entity_index, entity in enumerate(entities)],
            "relationships": clean_relationships,
            "source_identity": {
                "canonical_url": canonical,
                "publisher": _text(source_identity.get("publisher"), f"{context}.source_identity.publisher", optional=True),
                "content_fingerprint": fingerprint.casefold() if fingerprint else None,
                "syndication_group": _text(source_identity.get("syndication_group"), f"{context}.source_identity.syndication_group", optional=True),
            },
            "verification_status": verification,
            "verification": verification_record,
            "temporal_status": temporal,
        })
    return {"schema": PROVIDER_SCHEMA, "provider": provider, "query": clean_query, "results": results}


def _source_group(identity: dict[str, Any]) -> str:
    # The most explicit dependency hints win. Identical content is deliberately
    # treated as dependent even when it appears at several URLs.
    if identity.get("content_fingerprint"):
        key = ["content", identity["content_fingerprint"]]
    elif identity.get("syndication_group"):
        key = ["syndication", identity["syndication_group"]]
    else:
        key = ["url", identity["canonical_url"]]
    return _stable_id("source-group", key)


def _assessment(scope: str, evidence: list[str], groups: list[str], contradictions: list[str], verification: str, temporal: str, assessed_at: str | None) -> dict[str, Any]:
    if scope not in CONFIDENCE_SCOPES:
        raise CorrelationError(f"unsupported confidence scope: {scope}")
    independent = sorted(set(groups))
    # Explicit, intentionally modest heuristic: one independent source starts
    # at .55 and each additional independent source contributes .15, capped.
    score = min(0.95, 0.40 + 0.15 * len(independent)) if evidence else None
    if contradictions:
        score = round(max(0.0, (score or 0.0) - 0.25), 6)
    if scope == "currentness" and temporal == "unresolved":
        score = None
    return {
        "scope": scope,
        "score": score,
        "method": "independent-source-count-v1",
        "assessed_at": assessed_at,
        "evidence": sorted(set(evidence)),
        "independent_source_groups": independent,
        "dependent_observation_count": max(0, len(set(evidence)) - len(independent)),
        "contradictions": sorted(set(contradictions)),
        "verification_status": verification,
        "contribution": {
            "independent_source_count": len(independent),
            "contradiction_penalty": 0.25 if contradictions else 0.0,
        },
        "rationale": (
            "verification state is separate from confidence; explicit "
            "contradicting evidence contributes the documented contradiction penalty"
        ),
    }


def build_graph(
    payloads: Iterable[dict[str, Any]],
    canonicalize: Callable[[str, str], str],
    *,
    case_id: str,
) -> dict[str, Any]:
    """Build a deterministic intelligence graph from normalized payloads."""
    observations_by_id: dict[str, dict[str, Any]] = {}
    entity_sources: dict[str, list[str]] = {}
    entity_records: dict[str, dict[str, Any]] = {}
    relationship_evidence: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for payload in payloads:
        clean = validate_provider_payload(payload)
        for result in clean["results"]:
            group = _source_group(result["source_identity"])
            observation_identity = {
                "provider": clean["provider"], "query": clean["query"],
                "url": result["url"], "source_file": result["source_file"],
                "entities": result["entities"], "relationships": result["relationships"],
            }
            observation_id = _stable_id("observation", observation_identity)
            if observation_id in observations_by_id:
                continue
            observation_contradictions = []
            if result["verification_status"] == "contradicted":
                observation_contradictions.append(
                    _stable_id("contradiction", [observation_id, "contradicted_evidence"])
                )
            if result["temporal_status"] == "conflicting":
                observation_contradictions.append(
                    _stable_id("contradiction", [observation_id, "temporal_conflict"])
                )
            observation_entities = []
            for entity in result["entities"]:
                canonical = canonicalize(entity["type"], entity["value"])
                entity_id = _stable_id("entity", [entity["type"], canonical])
                entity_records.setdefault(entity_id, {
                    "id": entity_id, "type": entity["type"], "value": entity["value"],
                    "canonical_value": canonical,
                })
                entity_sources.setdefault(entity_id, []).append(observation_id)
                observation_entities.append(entity_id)
            for relationship in result["relationships"]:
                endpoints = []
                for key in ("source", "target"):
                    entity = relationship[key]
                    canonical = canonicalize(entity["type"], entity["value"])
                    entity_id = _stable_id("entity", [entity["type"], canonical])
                    entity_records.setdefault(entity_id, {
                        "id": entity_id, "type": entity["type"], "value": entity["value"],
                        "canonical_value": canonical,
                    })
                    entity_sources.setdefault(entity_id, []).append(observation_id)
                    endpoints.append(entity_id)
                    observation_entities.append(entity_id)
                key = (endpoints[0], relationship["type"], endpoints[1])
                relationship_evidence.setdefault(key, []).append({
                    "observation_id": observation_id, "source_group": group,
                    **{field: relationship[field] for field in ("inference_state", "verification_status", "temporal_status")},
                    "verification": relationship["verification"],
                })
            observations_by_id[observation_id] = {
                "id": observation_id, "provider": clean["provider"],
                "query": clean["query"], "url": result["url"],
                "title": result["title"], "snippet": result["snippet"],
                "source_file": result["source_file"], "observed_at": result["observed_at"],
                "published_at": result["published_at"], "source_group": group,
                "source_identity": result["source_identity"],
                "entity_ids": sorted(set(observation_entities)),
                "verification_status": result["verification_status"],
                "verification": result["verification"],
                "temporal_status": result["temporal_status"],
                "contradictions": observation_contradictions,
                "confidence": _assessment("observation", [observation_id], [group], observation_contradictions, result["verification_status"], result["temporal_status"], result["observed_at"]),
            }
    observations = sorted(observations_by_id.values(), key=lambda item: item["id"])
    relationships = []
    for key, evidence in sorted(relationship_evidence.items()):
        states = {item["verification_status"] for item in evidence}
        temporal_states = {item["temporal_status"] for item in evidence}
        verification_conflict = "verified" in states and "contradicted" in states
        contradicted_evidence = "contradicted" in states
        temporal_conflict = len(temporal_states) > 1 or "conflicting" in temporal_states
        contradiction_ids: list[str] = []
        relationship_id = _stable_id("relationship", list(key))
        if verification_conflict:
            contradiction_ids.append(_stable_id("contradiction", [relationship_id, "verification_conflict"]))
        elif contradicted_evidence:
            contradiction_ids.append(_stable_id("contradiction", [relationship_id, "contradicted_evidence"]))
        if temporal_conflict:
            contradiction_ids.append(_stable_id("contradiction", [relationship_id, "temporal_conflict"]))
        verification = (
            "contradicted" if contradicted_evidence
            else sorted(states)[0] if len(states) == 1 else "inconclusive"
        )
        temporal = "conflicting" if temporal_conflict else next(iter(temporal_states))
        evidence_ids = [item["observation_id"] for item in evidence]
        groups = [item["source_group"] for item in evidence]
        assessed_at = max(
            item["observed_at"] for item in observations
            if item["id"] in set(evidence_ids)
        )
        relationships.append({
            "id": relationship_id, "source_entity_id": key[0], "type": key[1],
            "target_entity_id": key[2],
            "inference_state": "analyst_confirmed" if all(item["inference_state"] == "analyst_confirmed" for item in evidence) else "automated",
            "verification_status": verification, "temporal_status": temporal,
            "verification": [
                item["verification"] for item in evidence
                if item["verification"] is not None
            ],
            "evidence": sorted(set(evidence_ids)), "contradictions": contradiction_ids,
            "confidence": _assessment("relationship", evidence_ids, groups, contradiction_ids, verification, temporal, assessed_at),
            "identity_confidence": _assessment("identity", evidence_ids, groups, contradiction_ids, verification, temporal, assessed_at),
            "currentness_confidence": _assessment("currentness", evidence_ids, groups, contradiction_ids, verification, temporal, assessed_at),
        })
    contradictions = []
    for observation in observations:
        for contradiction_id in observation["contradictions"]:
            contradictions.append({
                "id": contradiction_id,
                "kind": (
                    "temporal_conflict"
                    if observation["temporal_status"] == "conflicting"
                    and contradiction_id == _stable_id(
                        "contradiction", [observation["id"], "temporal_conflict"]
                    )
                    else "contradicted_evidence"
                ),
                "observation_id": observation["id"],
                "evidence": [observation["id"]],
                "resolution_state": "unresolved",
            })
    for relationship in relationships:
        for contradiction_id in relationship["contradictions"]:
            kind = "temporal_conflict" if contradiction_id == _stable_id(
                "contradiction", [relationship["id"], "temporal_conflict"]
            ) else (
                "verification_conflict" if contradiction_id == _stable_id(
                    "contradiction", [relationship["id"], "verification_conflict"]
                ) else "contradicted_evidence"
            )
            contradictions.append({
                "id": contradiction_id, "kind": kind,
                "relationship_id": relationship["id"],
                "evidence": relationship["evidence"], "resolution_state": "unresolved",
            })
    entities = []
    for entity_id, entity in sorted(entity_records.items()):
        sources = sorted(set(entity_sources.get(entity_id, [])))
        groups = [next(item["source_group"] for item in observations if item["id"] == source) for source in sources]
        assessed_at = max(
            item["observed_at"] for item in observations if item["id"] in set(sources)
        ) if sources else None
        entities.append({**entity, "observations": sources, "confidence": _assessment("identity", sources, groups, [], "not_attempted", "unresolved", assessed_at)})
    return {
        "schema": GRAPH_SCHEMA, "case_id": case_id,
        "entities": entities, "observations": observations,
        "relationships": relationships,
        "contradictions": sorted(contradictions, key=lambda item: item["id"]),
        "source_groups": sorted({item["source_group"] for item in observations}),
    }
