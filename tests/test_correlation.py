# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
import copy
import json
from pathlib import Path
import tempfile
import unittest

from forge import correlation, osint_forge


def payload():
    return {
        "schema": 1,
        "provider": "fixture-search",
        "query": {"type": "email", "value": "Person@Example.com"},
        "results": [{
            "url": "HTTPS://Example.com/profile#fragment",
            "title": "Fixture profile",
            "snippet": "Synthetic public record.",
            "source_file": "runs/fixture/results.json",
            "observed_at": "2026-08-04T12:00:00+00:00",
            "published_at": None,
            "entities": [
                {"type": "email", "value": "Person@Example.com"},
                {"type": "username", "value": "fixture_person"},
            ],
            "relationships": [{
                "source": {"type": "email", "value": "Person@Example.com"},
                "target": {"type": "username", "value": "fixture_person"},
                "type": "uses_account",
            }],
            "source_identity": {
                "canonical_url": "https://example.com/profile",
                "publisher": "Example",
                "content_fingerprint": "a" * 64,
                "syndication_group": None,
            },
            "verification_status": "tool_unavailable",
            "verification": {
                "sensor": "fixture-verifier",
                "sensor_version": "1",
                "method": "compatibility-check",
                "evidence": ["synthetic-sensor-record"],
            },
            "temporal_status": "unresolved",
        }],
    }


class CorrelationTests(unittest.TestCase):
    def test_graph_is_deterministic_and_deduplicates_entities_not_provenance(self):
        first = payload()
        second = copy.deepcopy(first)
        second["provider"] = "second-search"
        second["results"][0]["url"] = "https://mirror.example/profile"
        second["results"][0]["source_identity"]["canonical_url"] = second["results"][0]["url"]
        second["results"][0]["source_file"] = "runs/fixture/mirror.json"
        graph = correlation.build_graph([second, first], osint_forge.canonical_entity_value, case_id="fixture")
        rerun = correlation.build_graph([second, first], osint_forge.canonical_entity_value, case_id="fixture")
        self.assertEqual(graph, rerun)
        self.assertEqual(len(graph["entities"]), 2)
        self.assertEqual(len(graph["observations"]), 2)
        self.assertEqual(len(graph["relationships"]), 1)
        self.assertEqual(len(graph["source_groups"]), 1)  # identical content
        self.assertEqual(graph["relationships"][0]["confidence"]["dependent_observation_count"], 1)
        self.assertEqual(graph["relationships"][0]["verification_status"], "tool_unavailable")
        self.assertIsNone(graph["relationships"][0]["currentness_confidence"]["score"])
        duplicate = correlation.build_graph(
            [first, copy.deepcopy(first)],
            osint_forge.canonical_entity_value,
            case_id="fixture",
        )
        self.assertEqual(len(duplicate["observations"]), 1)
        self.assertEqual(len(duplicate["relationships"][0]["evidence"]), 1)
        self.assertEqual(len(duplicate["observations"][0]["entity_ids"]), 2)

    def test_independent_sources_raise_explainable_confidence(self):
        second = copy.deepcopy(payload())
        second["provider"] = "independent-search"
        second["results"][0]["url"] = "https://independent.example/profile"
        second["results"][0]["source_identity"] = {
            "canonical_url": second["results"][0]["url"], "publisher": None,
            "content_fingerprint": "b" * 64, "syndication_group": None,
        }
        second["results"][0]["source_file"] = "runs/fixture/independent.json"
        graph = correlation.build_graph([payload(), second], osint_forge.canonical_entity_value, case_id="fixture")
        confidence = graph["relationships"][0]["confidence"]
        self.assertEqual(len(confidence["independent_source_groups"]), 2)
        self.assertEqual(confidence["score"], 0.7)
        self.assertIn("separate", confidence["rationale"])

    def test_contradictions_are_first_class_and_reduce_confidence(self):
        contrary = copy.deepcopy(payload())
        contrary["provider"] = "contrary-search"
        contrary["results"][0]["source_file"] = "runs/fixture/contrary.json"
        contrary["results"][0]["source_identity"]["content_fingerprint"] = "c" * 64
        contrary["results"][0]["relationships"][0]["verification_status"] = "contradicted"
        confirmed = payload()
        confirmed["results"][0]["relationships"][0]["verification_status"] = "verified"
        graph = correlation.build_graph([confirmed, contrary], osint_forge.canonical_entity_value, case_id="fixture")
        self.assertEqual(graph["relationships"][0]["verification_status"], "contradicted")
        self.assertEqual(graph["relationships"][0]["temporal_status"], "unresolved")
        self.assertEqual(len(graph["contradictions"]), 1)
        self.assertEqual(graph["contradictions"][0]["resolution_state"], "unresolved")
        contradicted_only = correlation.build_graph(
            [contrary], osint_forge.canonical_entity_value, case_id="fixture"
        )
        self.assertEqual(contradicted_only["relationships"][0]["verification_status"], "contradicted")
        self.assertEqual(len(contradicted_only["contradictions"]), 1)
        self.assertEqual(contradicted_only["relationships"][0]["confidence"]["score"], 0.3)
        contrary["results"][0]["verification_status"] = "contradicted"
        observation_graph = correlation.build_graph(
            [contrary], osint_forge.canonical_entity_value, case_id="fixture"
        )
        self.assertTrue(observation_graph["observations"][0]["contradictions"])
        self.assertEqual(observation_graph["observations"][0]["confidence"]["score"], 0.3)
        temporal = copy.deepcopy(payload())
        temporal["provider"] = "newer-search"
        temporal["results"][0]["source_file"] = "runs/fixture/newer.json"
        temporal["results"][0]["source_identity"]["content_fingerprint"] = "d" * 64
        temporal["results"][0]["relationships"][0]["temporal_status"] = "historical_high_confidence"
        temporal_graph = correlation.build_graph(
            [payload(), temporal], osint_forge.canonical_entity_value, case_id="fixture"
        )
        self.assertEqual(temporal_graph["relationships"][0]["temporal_status"], "conflicting")
        self.assertIn("temporal_conflict", {item["kind"] for item in temporal_graph["contradictions"]})

    def test_content_fingerprint_overrides_inconsistent_syndication_labels(self):
        first = payload()
        first["results"][0]["source_identity"]["syndication_group"] = "claimed-a"
        second = copy.deepcopy(first)
        second["provider"] = "mirror"
        second["results"][0]["url"] = "https://mirror.example/profile"
        second["results"][0]["source_identity"]["canonical_url"] = second["results"][0]["url"]
        second["results"][0]["source_identity"]["syndication_group"] = "claimed-b"
        second["results"][0]["source_file"] = "runs/fixture/mirror.json"
        graph = correlation.build_graph(
            [first, second], osint_forge.canonical_entity_value, case_id="fixture"
        )
        self.assertEqual(len(graph["source_groups"]), 1)
        self.assertEqual(graph["relationships"][0]["confidence"]["score"], 0.55)

    def test_strict_contract_rejects_future_unknown_and_bad_states(self):
        future = payload()
        future["schema"] = 2
        with self.assertRaisesRegex(correlation.CorrelationError, "newer than supported"):
            correlation.validate_provider_payload(future)
        unknown = payload()
        unknown["secret"] = "field"
        with self.assertRaisesRegex(correlation.CorrelationError, "unknown fields"):
            correlation.validate_provider_payload(unknown)
        invalid = payload()
        invalid["results"][0]["verification_status"] = "probably"
        with self.assertRaisesRegex(correlation.CorrelationError, "unsupported analytical state"):
            correlation.validate_provider_payload(invalid)
        unsupported_claim = payload()
        unsupported_claim["results"][0]["verification_status"] = "verified"
        unsupported_claim["results"][0].pop("verification")
        with self.assertRaisesRegex(correlation.CorrelationError, "verification must be an object"):
            correlation.validate_provider_payload(unsupported_claim)

    def test_case_bounded_loader_rejects_traversal_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case = root / "case"
            source = case / "runs" / "provider.json"
            source.parent.mkdir(parents=True)
            evidence = case / "runs" / "fixture" / "results.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_text("{}\n", encoding="utf-8")
            source.write_text(json.dumps(payload()), encoding="utf-8")
            self.assertEqual(correlation.load_provider_payload(case, "runs/provider.json")["provider"], "fixture-search")
            with self.assertRaisesRegex(correlation.CorrelationError, "escapes"):
                correlation.load_provider_payload(case, "../outside.json")
            link = case / "linked.json"
            link.symlink_to(source)
            with self.assertRaisesRegex(correlation.CorrelationError, "symbolic-link"):
                correlation.load_provider_payload(case, "linked.json")

    def test_url_credentials_and_invalid_fingerprints_are_rejected(self):
        unsafe = payload()
        unsafe["results"][0]["url"] = "https://user:pass@example.com/"
        with self.assertRaisesRegex(correlation.CorrelationError, "credentials"):
            correlation.validate_provider_payload(unsafe)
        malformed = payload()
        malformed["results"][0]["source_identity"]["content_fingerprint"] = "not-sha256"
        with self.assertRaisesRegex(correlation.CorrelationError, "SHA-256"):
            correlation.validate_provider_payload(malformed)

    def test_every_verification_and_temporal_state_is_explicit(self):
        for verification in sorted(correlation.VERIFICATION_STATES):
            fixture = payload()
            fixture["results"][0]["verification_status"] = verification
            fixture["results"][0]["relationships"][0]["verification_status"] = verification
            graph = correlation.build_graph(
                [fixture], osint_forge.canonical_entity_value, case_id="fixture"
            )
            self.assertEqual(graph["observations"][0]["verification_status"], verification)
            self.assertEqual(graph["relationships"][0]["verification_status"], verification)
            self.assertEqual(
                graph["relationships"][0]["confidence"]["verification_status"],
                verification,
            )
        for temporal in sorted(correlation.TEMPORAL_STATES):
            fixture = payload()
            fixture["results"][0]["temporal_status"] = temporal
            fixture["results"][0]["relationships"][0]["temporal_status"] = temporal
            graph = correlation.build_graph(
                [fixture], osint_forge.canonical_entity_value, case_id="fixture"
            )
            self.assertEqual(graph["relationships"][0]["temporal_status"], temporal)
            currentness = graph["relationships"][0]["currentness_confidence"]
            self.assertEqual(currentness["assessed_at"], "2026-08-04T12:00:00+00:00")
            self.assertIn("contribution", currentness)

    def test_timestamps_entity_types_and_analyst_claims_are_rejected(self):
        naive = payload()
        naive["results"][0]["observed_at"] = "2026-08-04T12:00:00"
        with self.assertRaisesRegex(correlation.CorrelationError, "timezone"):
            correlation.validate_provider_payload(naive)
        unsupported = payload()
        unsupported["results"][0]["entities"][0]["type"] = "person_record"
        with self.assertRaisesRegex(correlation.CorrelationError, "unsupported"):
            correlation.validate_provider_payload(unsupported)
        analyst = payload()
        analyst["results"][0]["relationships"][0]["inference_state"] = "analyst_confirmed"
        with self.assertRaisesRegex(correlation.CorrelationError, "unsupported analytical state"):
            correlation.validate_provider_payload(analyst)


if __name__ == "__main__":
    unittest.main()
