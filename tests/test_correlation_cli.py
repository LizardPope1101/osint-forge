# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from forge import osint_forge, reporting


class CorrelationCliTests(unittest.TestCase):
    def _payload(self, source_file: str = "result.txt") -> dict:
        entity = {"type": "email", "value": "analyst@example.com"}
        account = {"type": "username", "value": "example_handle"}
        return {
            "schema": 1,
            "provider": "fixture-search",
            "query": entity,
            "results": [{
                "url": "https://profiles.example.test/example_handle",
                "title": "Synthetic profile",
                "snippet": "Synthetic fixture only",
                "source_file": source_file,
                "observed_at": "2026-08-04T12:00:00+00:00",
                "published_at": None,
                "entities": [entity, account],
                "relationships": [{
                    "source": entity,
                    "target": account,
                    "type": "uses_account",
                    "verification_status": "tool_unavailable",
                    "temporal_status": "unresolved",
                }],
                "source_identity": {
                    "canonical_url": "https://profiles.example.test/example_handle",
                    "publisher": "Example Test",
                    "content_fingerprint": hashlib.sha256(
                        b"synthetic evidence\n"
                    ).hexdigest(),
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

    def test_observe_intelligence_report_and_redaction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cases = root / "cases"
            incoming = root / "incoming"
            incoming.mkdir()
            (incoming / "result.txt").write_text("synthetic evidence\n", encoding="utf-8")
            payload_path = incoming / "provider.json"
            payload_path.write_text(json.dumps(self._payload()), encoding="utf-8")
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(cases)}):
                self.assertEqual(osint_forge.cmd_case_create(argparse.Namespace(
                    case="case", purpose="Synthetic", authorization="Owned fixtures"
                )), 0)
                self.assertEqual(osint_forge.cmd_case_add(argparse.Namespace(
                    case="case", type="email", target="analyst@example.com"
                )), 0)
                self.assertEqual(osint_forge.cmd_case_observe(argparse.Namespace(
                    case="case", provider="fixture-search", input=payload_path
                )), 0)
                case_path, metadata = osint_forge.load_case("case")
                graph = osint_forge.build_case_intelligence(case_path, metadata)
                self.assertEqual(len(graph["observations"]), 1)
                self.assertEqual(graph["relationships"][0]["verification_status"], "tool_unavailable")
                self.assertIsNone(graph["relationships"][0]["currentness_confidence"]["score"])
                report = osint_forge.build_case_report(case_path, metadata)
                self.assertEqual(report["schema"], 3)
                markdown = reporting.render_markdown(report, case_path / "report.md", case_path)
                self.assertIn("tool-unverified", markdown)
                redacted = reporting.redact_report(report)
                encoded = reporting.render_json(redacted)
                self.assertNotIn("analyst@example.com", encoded)
                self.assertNotIn("profiles.example.test", encoded)
                for artifact in (case_path / "observations").rglob("*"):
                    if artifact.is_file():
                        self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)

    def test_observe_rejects_scope_escape_and_source_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cases = root / "cases"
            incoming = root / "incoming"
            incoming.mkdir()
            outside = self._payload()
            outside["query"] = {"type": "email", "value": "other@example.com"}
            outside_path = incoming / "outside.json"
            outside_path.write_text(json.dumps(outside), encoding="utf-8")
            traversal = self._payload("../secret.txt")
            traversal_path = incoming / "traversal.json"
            traversal_path.write_text(json.dumps(traversal), encoding="utf-8")
            (incoming / "result.txt").write_text("tampered evidence\n", encoding="utf-8")
            mismatch_path = incoming / "mismatch.json"
            mismatch_path.write_text(json.dumps(self._payload()), encoding="utf-8")
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(cases)}):
                osint_forge.cmd_case_create(argparse.Namespace(
                    case="case", purpose="Synthetic", authorization="Owned fixtures"
                ))
                osint_forge.cmd_case_add(argparse.Namespace(
                    case="case", type="email", target="analyst@example.com"
                ))
                with self.assertRaisesRegex(SystemExit, "outside"):
                    osint_forge.cmd_case_observe(argparse.Namespace(
                        case="case", provider="fixture-search", input=outside_path
                    ))
                with self.assertRaisesRegex(SystemExit, "stay beside"):
                    osint_forge.cmd_case_observe(argparse.Namespace(
                        case="case", provider="fixture-search", input=traversal_path
                    ))
                with self.assertRaisesRegex(SystemExit, "does not match"):
                    osint_forge.cmd_case_observe(argparse.Namespace(
                        case="case", provider="fixture-search", input=mismatch_path
                    ))


if __name__ == "__main__":
    unittest.main()
