#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Versioned entity records derived from durable case data and observations."""
from __future__ import annotations

import hashlib
from typing import Any

ENTITY_SCHEMA = 1


def entity_id(entity_type: str, canonical_value: str) -> str:
    digest = hashlib.sha256(
        f"{entity_type}\0{canonical_value}".encode()
    ).hexdigest()[:20]
    return f"entity-{digest}"


def build_seed_entities(
    metadata: dict[str, Any],
    canonicalize,
) -> dict[str, Any]:
    """Project case targets into deterministic, provenance-linked entities."""
    by_id: dict[str, dict[str, Any]] = {}
    for target in metadata["targets"]:
        canonical_value = canonicalize(target["type"], target["value"])
        identifier = entity_id(target["type"], canonical_value)
        source = {
            "kind": "case_target",
            "target_id": target["id"],
            "added_at": target["added_at"],
        }
        if identifier in by_id:
            by_id[identifier]["sources"].append(source)
        else:
            by_id[identifier] = {
                "id": identifier,
                "type": target["type"],
                "value": target["value"],
                "canonical_value": canonical_value,
                "origin": "seed",
                "confidence": {
                    "score": 1.0,
                    "scope": "seed_fidelity",
                    "method": "operator_supplied",
                },
                "sources": [source],
            }
    entities = list(by_id.values())
    for entity in entities:
        entity["sources"].sort(key=lambda source: source["target_id"])
    entities.sort(key=lambda entity: (entity["type"], entity["canonical_value"]))
    return {
        "schema": ENTITY_SCHEMA,
        "case_id": metadata["id"],
        "entity_count": len(entities),
        "entities": entities,
        "relationships": [],
    }


def build_case_entities(
    metadata: dict[str, Any],
    candidates: list[dict[str, Any]],
    canonicalize,
) -> dict[str, Any]:
    """Merge seeds and extracted candidates without implying identity."""
    projection = build_seed_entities(metadata, canonicalize)
    by_id = {entity["id"]: entity for entity in projection["entities"]}
    for candidate in candidates:
        canonical_value = canonicalize(candidate["type"], candidate["value"])
        identifier = entity_id(candidate["type"], canonical_value)
        source = {
            "kind": "extracted_observation",
            "candidate_id": candidate["id"],
            "target_id": candidate["target"]["id"],
            "plugin": candidate["source"]["plugin"],
            "source_file": candidate["source"]["source_file"],
        }
        if identifier in by_id:
            if source not in by_id[identifier]["sources"]:
                by_id[identifier]["sources"].append(source)
            continue
        by_id[identifier] = {
            "id": identifier,
            "type": candidate["type"],
            "value": candidate["value"],
            "canonical_value": canonical_value,
            "origin": "extracted",
            "confidence": {
                "score": None,
                "scope": "observation",
                "method": "unverified_extraction",
            },
            "sources": [source],
        }
    result = list(by_id.values())
    for entity in result:
        entity["sources"].sort(
            key=lambda source: (
                source["kind"],
                source.get("target_id", ""),
                source.get("candidate_id", ""),
            )
        )
    result.sort(key=lambda entity: (entity["type"], entity["canonical_value"]))
    projection["entities"] = result
    projection["entity_count"] = len(result)
    return projection
