# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import tempfile
import unittest
from pathlib import Path

from forge import workflows


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = {
            "schema": 1,
            "id": "fixture",
            "name": "Fixture",
            "description": "Synthetic workflow fixture.",
            "max_concurrency": 2,
            "stages": [
                {
                    "id": "collect",
                    "purpose": "Collect synthetic observations.",
                    "expected_information_gain": "A public account observation.",
                    "plugins": ["fixture-plugin"],
                    "depends_on": [],
                    "timeout_seconds": 30,
                }
            ],
        }
        self.metadata = {
            "id": "case-001",
            "targets": [
                {"id": "email-1", "type": "email", "value": "person@example.com"},
                {"id": "name-1", "type": "name", "value": "Example Person"},
            ],
        }
        self.catalog = {
            "fixture-plugin": (
                Path("fixture-plugin"),
                {
                    "id": "fixture-plugin",
                    "plugin_version": "1",
                    "batch": True,
                    "supports": ["email"],
                    "entities": {"accepted": ["email"], "emitted": ["username"]},
                    "adapters": {"email": {"command": ["fixture", "{target}"]}},
                },
            )
        }

    def test_resolved_plan_is_deterministic_and_does_not_merge_seeds(self):
        first = workflows.resolve_plan(self.workflow, self.metadata, self.catalog, lambda _: True)
        second = workflows.resolve_plan(self.workflow, self.metadata, self.catalog, lambda _: True)
        self.assertEqual(first, second)
        self.assertEqual(first["seed_identity_assumption"], "none")
        self.assertEqual(first["stage_order"], ["collect"])
        self.assertEqual(len(first["scheduled_jobs"]), 1)
        self.assertEqual(first["scheduled_jobs"][0]["entity_id"], "email-1")
        self.assertEqual(first["coverage_gaps"][0]["entity_id"], "name-1")
        self.assertEqual(
            {item["decision"] for item in first["decisions"]},
            {"selected", "skipped"},
        )

    def test_uninstalled_and_unknown_plugins_are_explained(self):
        workflow = copy.deepcopy(self.workflow)
        workflow["stages"][0]["plugins"].append("missing-plugin")
        plan = workflows.resolve_plan(workflow, self.metadata, self.catalog, lambda _: False)
        reasons = [item["reason"] for item in plan["decisions"]]
        self.assertTrue(any("not installed" in reason for reason in reasons))
        self.assertTrue(any("not present" in reason for reason in reasons))
        self.assertEqual(plan["scheduled_jobs"], [])

    def test_unknown_fields_future_versions_cycles_and_unsafe_links_fail(self):
        malformed = copy.deepcopy(self.workflow)
        malformed["surprise"] = True
        with self.assertRaisesRegex(workflows.WorkflowError, "unknown workflow fields"):
            workflows.validate_workflow(malformed)
        future = copy.deepcopy(self.workflow)
        future["schema"] = 2
        with self.assertRaisesRegex(workflows.WorkflowError, "newer than supported"):
            workflows.validate_workflow(future)
        cyclic = copy.deepcopy(self.workflow)
        cyclic["stages"].append({
            "id": "second", "purpose": "Second.",
            "expected_information_gain": "More observations.",
            "plugins": ["fixture-plugin"], "depends_on": ["collect"],
            "timeout_seconds": 30,
        })
        cyclic["stages"][0]["depends_on"] = ["second"]
        with self.assertRaisesRegex(workflows.WorkflowError, "cycle"):
            workflows.validate_workflow(cyclic)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            actual = root / "actual.json"
            actual.write_text(json.dumps(self.workflow), encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(actual)
            with self.assertRaisesRegex(workflows.WorkflowError, "symbolic-link"):
                workflows.load_workflow(link)

    def test_builtin_profile_validates(self):
        root = Path(__file__).resolve().parents[1]
        profile = workflows.load_workflow(root / "workflows" / "public-identity.json")
        self.assertEqual(profile["id"], "public-identity")


if __name__ == "__main__":
    unittest.main()
