# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from forge import osint_forge


class CatalogTests(unittest.TestCase):
    def test_catalog_discovers_expected_plugins(self):
        self.assertEqual(
            set(osint_forge.catalog()),
            {
                "exiftool", "ghunt", "maigret", "nmap",
                "recon-ng", "sherlock", "spiderfoot",
            },
        )

    def test_all_plugin_contracts_validate(self):
        errors = []
        for directory in sorted(osint_forge.plugin_root().iterdir()):
            if directory.is_dir():
                plugin_errors, _ = osint_forge.validate_plugin_directory(directory)
                errors.extend(plugin_errors)
        self.assertEqual(errors, [])

    def test_manifest_id_must_match_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            plugin_dir = Path(temp) / "wrong-directory"
            plugin_dir.mkdir()
            manifest = {
                "schema": 1,
                "plugin_version": "1",
                "id": "different-id",
                "name": "Example",
                "description": "Example",
                "category": "testing",
                "homepage": "https://example.org",
                "upstream_license": "MIT",
                "upstream_license_url": "https://example.org/license",
                "commands": ["example"],
                "supports": [],
                "batch": False,
                "lifecycle": {},
                "requires_root": {},
                "adapters": {},
            }
            (plugin_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            errors, _ = osint_forge.validate_plugin_directory(plugin_dir)
            self.assertTrue(any("must match directory name" in error for error in errors))


class TargetTests(unittest.TestCase):
    def test_validate_target_types(self):
        self.assertTrue(osint_forge.validate_target("email", "analyst@example.com"))
        self.assertTrue(osint_forge.validate_target("username", "example_handle"))
        self.assertTrue(osint_forge.validate_target("domain", "example.com"))
        self.assertTrue(osint_forge.validate_target("ip", "192.0.2.10"))
        self.assertFalse(osint_forge.validate_target("ip", "999.0.2.10"))
        self.assertFalse(osint_forge.validate_target("domain", "https://example.com"))

    def test_batch_parser_deduplicates_and_normalizes_sections(self):
        with tempfile.TemporaryDirectory() as temp:
            target_file = Path(temp) / "targets.txt"
            target_file.write_text(
                "[Usernames]\nAlice\nalice\n\n[Emails]\nanalyst@example.com\n",
                encoding="utf-8",
            )
            self.assertEqual(
                osint_forge.parse_batch_file(target_file),
                [("username", "Alice"), ("email", "analyst@example.com")],
            )

    def test_batch_parser_rejects_target_before_section(self):
        with tempfile.TemporaryDirectory() as temp:
            target_file = Path(temp) / "targets.txt"
            target_file.write_text("example_handle\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                osint_forge.parse_batch_file(target_file)

    def test_safe_slug_is_stable_and_separates_values(self):
        first = osint_forge.safe_slug("Example Target")
        self.assertEqual(first, osint_forge.safe_slug("Example Target"))
        self.assertNotEqual(first, osint_forge.safe_slug("Example-Target"))


class ExecutionTests(unittest.TestCase):
    def test_adapter_preserves_argument_boundaries(self):
        manifest = {
            "id": "example",
            "adapters": {
                "username": {
                    "command": ["example", "--output", "{output_dir}", "{target}"]
                }
            },
        }
        result = osint_forge.adapter_command(
            Path("/tmp/plugin"),
            manifest,
            "username",
            "name; echo unsafe",
            Path("/tmp/output with spaces"),
        )
        self.assertEqual(
            result,
            ["example", "--output", "/tmp/output with spaces", "name; echo unsafe"],
        )

    def test_dry_run_does_not_execute_adapter(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(osint_forge, "require_plugin") as require:
                require.return_value = (
                    Path(temp),
                    {
                        "id": "example",
                        "adapters": {"username": {"command": ["example", "{target}"]}},
                    },
                )
                with mock.patch("subprocess.run") as run:
                    rc = osint_forge.run_adapter(
                        "example", "username", "alice", Path(temp) / "out", True
                    )
                    self.assertEqual(rc, 0)
                    run.assert_not_called()


class CliTests(unittest.TestCase):
    def test_version_command(self):
        self.assertRegex(osint_forge.__version__, r"^\d+\.\d+\.\d+")

    def test_validate_command_succeeds(self):
        rc = osint_forge.cmd_validate(argparse.Namespace(json=False))
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
