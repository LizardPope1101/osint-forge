# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import json
import os
import shutil
import subprocess
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

    def test_lifecycle_path_cannot_escape_plugin_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            plugin_dir = Path(temp) / "example"
            plugin_dir.mkdir()
            with self.assertRaises(ValueError):
                osint_forge.resolve_plugin_file(plugin_dir, "../outside.sh")
            with self.assertRaises(ValueError):
                osint_forge.resolve_plugin_file(plugin_dir, "/tmp/outside.sh")

    def test_batch_plugin_requires_adapter_for_every_supported_type(self):
        with tempfile.TemporaryDirectory() as temp:
            plugin_dir = Path(temp) / "example"
            plugin_dir.mkdir()
            for action in ("install", "update", "remove", "doctor"):
                script = plugin_dir / f"{action}.sh"
                script.write_text("#!/bin/sh\n", encoding="utf-8")
                script.chmod(0o755)
            manifest = {
                "schema": 1,
                "plugin_version": "1",
                "id": "example",
                "name": "Example",
                "description": "Example",
                "category": "testing",
                "homepage": "https://example.org",
                "upstream_license": "MIT",
                "upstream_license_url": "https://example.org/license",
                "tags": [],
                "commands": ["example"],
                "supports": ["email", "username"],
                "batch": True,
                "lifecycle": {
                    action: f"{action}.sh"
                    for action in ("install", "update", "remove", "doctor")
                },
                "requires_root": {
                    action: False
                    for action in ("install", "update", "remove", "doctor")
                },
                "adapters": {
                    "email": {"command": ["example", "{target}"]},
                },
            }
            (plugin_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            errors, _ = osint_forge.validate_plugin_directory(plugin_dir)
            self.assertTrue(any("missing adapters for: username" in error for error in errors))

    def test_catalog_loading_rejects_invalid_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            plugin_dir = Path(temp) / "example"
            plugin_dir.mkdir()
            (plugin_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "id": "example",
                        "name": "Example",
                        "description": "Example",
                        "category": "testing",
                        "lifecycle": {},
                        "commands": ["example"],
                        "supports": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "invalid plugin contract"):
                osint_forge.load_manifest(plugin_dir)

    def test_plugin_template_is_a_valid_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            plugin_dir = Path(temp) / "example"
            shutil.copytree(
                osint_forge.SOURCE_ROOT / "docs" / "plugin-template",
                plugin_dir,
            )
            errors, warnings = osint_forge.validate_plugin_directory(plugin_dir)
            self.assertEqual(errors, [])
            self.assertEqual(warnings, [])


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

    def test_missing_adapter_executable_writes_failure_status(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "out"
            with mock.patch.object(osint_forge, "require_plugin") as require, \
                 mock.patch.object(osint_forge, "is_installed", return_value=True):
                require.return_value = (
                    Path(temp),
                    {
                        "id": "example",
                        "adapters": {
                            "username": {
                                "command": ["definitely-not-an-osint-forge-command", "{target}"]
                            }
                        },
                    },
                )
                rc = osint_forge.run_adapter(
                    "example", "username", "alice", output, False
                )
            self.assertEqual(rc, 127)
            status = json.loads((output / "status.json").read_text(encoding="utf-8"))
            self.assertEqual(status["exit_code"], 127)
            self.assertIn("error", status)
            self.assertEqual((output.stat().st_mode & 0o777), 0o700)
            for filename in ("stdout.log", "stderr.log", "status.json"):
                self.assertEqual(((output / filename).stat().st_mode & 0o777), 0o600)

    def test_batch_run_directories_do_not_collide(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = osint_forge.create_run_directory(root, "same name", "20260101-120000")
            second = osint_forge.create_run_directory(root, "same name", "20260101-120000")
            self.assertNotEqual(first, second)
            self.assertTrue(first.is_dir())
            self.assertTrue(second.is_dir())

    def test_batch_executes_matching_plugins_and_writes_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            for command in ("maigret", "sherlock"):
                executable = fake_bin / command
                executable.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
                executable.chmod(0o755)
            targets = root / "targets.txt"
            targets.write_text("[Usernames]\nexample_handle\n", encoding="utf-8")
            output_root = root / "output"
            args = argparse.Namespace(
                input=targets,
                output_root=output_root,
                name="integration",
                plugins=["maigret", "sherlock"],
                jobs=2,
                dry_run=False,
            )
            with mock.patch.dict(
                os.environ,
                {
                    "PATH": f"{fake_bin}:{os.environ['PATH']}",
                    "OSINT_FORGE_STATE": str(root / "state"),
                },
            ):
                rc = osint_forge.cmd_batch(args)
            self.assertEqual(rc, 0)
            run_dirs = list(output_root.iterdir())
            self.assertEqual(len(run_dirs), 1)
            summary = json.loads(
                (run_dirs[0] / "summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(summary["target_count"], 1)
            self.assertEqual(summary["job_count"], 2)
            self.assertEqual(
                {item["plugin"] for item in summary["results"]},
                {"maigret", "sherlock"},
            )
            self.assertTrue(all(item["exit_code"] == 0 for item in summary["results"]))
            self.assertEqual((run_dirs[0].stat().st_mode & 0o777), 0o700)
            self.assertEqual(
                ((run_dirs[0] / "targets-input.txt").stat().st_mode & 0o777),
                0o600,
            )
            self.assertEqual(
                ((run_dirs[0] / "summary.json").stat().st_mode & 0o777),
                0o600,
            )

    def test_lifecycle_start_failure_returns_command_not_found(self):
        with tempfile.TemporaryDirectory() as temp:
            plugin_dir = Path(temp)
            script = plugin_dir / "install.sh"
            script.write_text("#!/missing/interpreter\n", encoding="utf-8")
            script.chmod(0o755)
            manifest = {
                "id": "example",
                "name": "Example",
                "plugin_version": "1",
                "lifecycle": {"install": "install.sh"},
                "requires_root": {"install": False},
            }
            with mock.patch.object(
                osint_forge, "require_plugin", return_value=(plugin_dir, manifest)
            ):
                rc = osint_forge.run_lifecycle("example", "install")
            self.assertEqual(rc, 127)

    def test_command_search_includes_pipx_user_bin(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            user_bin = home / ".local" / "bin"
            user_bin.mkdir(parents=True)
            command = user_bin / "osint-forge-fake-command"
            command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            command.chmod(0o755)
            with mock.patch.dict(os.environ, {"HOME": str(home), "PATH": "/usr/bin"}), \
                 mock.patch.object(Path, "home", return_value=home):
                self.assertTrue(osint_forge.command_exists(command.name))


class CliTests(unittest.TestCase):
    def test_version_command(self):
        self.assertRegex(osint_forge.__version__, r"^\d+\.\d+\.\d+")

    def test_validate_command_succeeds(self):
        rc = osint_forge.cmd_validate(argparse.Namespace(json=False))
        self.assertEqual(rc, 0)

    def test_list_status_filters_are_mutually_exclusive(self):
        parser = osint_forge.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["forge", "list", "--installed", "--available"])

    def test_batch_rejects_unknown_plugin_filter(self):
        with tempfile.TemporaryDirectory() as temp:
            target_file = Path(temp) / "targets.txt"
            target_file.write_text("[Usernames]\nalice\n", encoding="utf-8")
            args = argparse.Namespace(
                input=target_file,
                output_root=Path(temp) / "out",
                name="test",
                plugins=["typo-plugin"],
                jobs=1,
                dry_run=True,
            )
            with self.assertRaisesRegex(SystemExit, "Unknown batch plugin"):
                osint_forge.cmd_batch(args)


class ShellScriptTests(unittest.TestCase):
    def test_missing_dependency_does_not_fail_dry_run(self):
        common = osint_forge.SOURCE_ROOT / "scripts" / "plugin-common.sh"
        script = (
            f"source {common!s}\n"
            "need command-that-does-not-exist-for-osint-forge\n"
            "run command-that-does-not-exist-for-osint-forge --example\n"
        )
        env = {
            **os.environ,
            "OSINT_FORGE_PLUGIN_ID": "example",
            "OSINT_FORGE_PLUGIN_DIR": "/tmp/example",
            "OSINT_FORGE_DRY_RUN": "1",
        }
        completed = subprocess.run(
            ["bash", "-c", script],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("dependency required", completed.stdout)
        self.assertIn("DRY-RUN:", completed.stdout)

    def test_doctor_propagates_tool_self_check_failure(self):
        doctor = osint_forge.SOURCE_ROOT / "plugins" / "ghunt" / "doctor.sh"
        with tempfile.TemporaryDirectory() as temp:
            fake = Path(temp) / "ghunt"
            fake.write_text("#!/bin/sh\nexit 42\n", encoding="utf-8")
            fake.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{temp}:{os.environ['PATH']}",
                "OSINT_FORGE_ROOT": str(osint_forge.SOURCE_ROOT),
                "OSINT_FORGE_PLUGIN_ID": "ghunt",
                "OSINT_FORGE_PLUGIN_DIR": str(doctor.parent),
                "OSINT_FORGE_DRY_RUN": "0",
            }
            completed = subprocess.run(
                [str(doctor)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 42)
        self.assertNotIn("OK: ghunt", completed.stdout)

    @unittest.skipUnless(os.geteuid() == 0, "isolated framework install requires root")
    def test_framework_install_replaces_stale_files_and_uninstalls_cleanly(self):
        root = osint_forge.SOURCE_ROOT
        with tempfile.TemporaryDirectory() as temp:
            sandbox = Path(temp)
            install_root = sandbox / "share" / "osint-forge"
            bin_dir = sandbox / "bin"
            etc_root = sandbox / "etc" / "osint-forge"
            target_home = sandbox / "home"
            target_home.mkdir()
            env = {
                **os.environ,
                "OSINT_FORGE_INSTALL_ROOT": str(install_root),
                "OSINT_FORGE_BIN_DIR": str(bin_dir),
                "OSINT_FORGE_ETC_ROOT": str(etc_root),
                "OSINT_FORGE_TARGET_HOME": str(target_home),
            }
            install_script = root / "scripts" / "install-framework.sh"
            uninstall_script = root / "scripts" / "uninstall-framework.sh"

            first = subprocess.run(
                [str(install_script)], env=env, text=True, capture_output=True, check=False
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertTrue((install_root / "forge" / "osint_forge.py").is_file())
            self.assertTrue((bin_dir / "osint").is_file())
            config = target_home / ".config" / "osint-forge" / "targets.txt"
            self.assertTrue(config.is_file())
            config.write_text("[Usernames]\nkeep-me\n", encoding="utf-8")

            stale = install_root / "stale-file"
            stale.write_text("obsolete", encoding="utf-8")
            second = subprocess.run(
                [str(install_script)], env=env, text=True, capture_output=True, check=False
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertFalse(stale.exists())
            self.assertEqual(config.read_text(encoding="utf-8"), "[Usernames]\nkeep-me\n")

            removed = subprocess.run(
                [str(uninstall_script)], env=env, text=True, capture_output=True, check=False
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse(install_root.exists())
            self.assertFalse((bin_dir / "osint").exists())
            self.assertTrue(config.is_file())


if __name__ == "__main__":
    unittest.main()
