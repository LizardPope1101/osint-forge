#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Versioned entity records derived from durable case data.

This module deliberately starts with case targets only. Later releases can add
entities extracted from normalized findings without changing the seed contract.
"""
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
