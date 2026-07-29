# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import contextlib
import io
import json
import os
import shlex
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

    def test_batch_parser_reports_missing_and_non_utf8_input(self):
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / "missing.txt"
            with self.assertRaisesRegex(SystemExit, "does not exist"):
                osint_forge.parse_batch_file(missing)
            invalid = Path(temp) / "invalid.txt"
            invalid.write_bytes(b"\xff")
            with self.assertRaisesRegex(SystemExit, "not valid UTF-8"):
                osint_forge.parse_batch_file(invalid)

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

    def test_adapter_enforces_private_permissions_on_upstream_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            command = fake_bin / "artifact-writer"
            command.write_text(
                "#!/bin/sh\n"
                "mkdir reports\n"
                "touch reports/result.json\n",
                encoding="utf-8",
            )
            command.chmod(0o755)
            output = root / "out"
            with mock.patch.object(osint_forge, "require_plugin") as require, \
                 mock.patch.object(osint_forge, "is_installed", return_value=True), \
                 mock.patch.dict(
                     os.environ,
                     {"PATH": f"{fake_bin}:{os.environ['PATH']}"},
                 ):
                require.return_value = (
                    root,
                    {
                        "id": "example",
                        "adapters": {
                            "username": {
                                "command": ["artifact-writer", "{target}"]
                            }
                        },
                    },
                )
                rc = osint_forge.run_adapter(
                    "example", "username", "alice", output, False
                )
            self.assertEqual(rc, 0)
            self.assertEqual(
                ((output / "reports").stat().st_mode & 0o777),
                0o700,
            )
            self.assertEqual(
                ((output / "reports" / "result.json").stat().st_mode & 0o777),
                0o600,
            )

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires O_NOFOLLOW")
    def test_private_log_refuses_symbolic_link(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            victim = root / "victim"
            victim.write_text("preserve", encoding="utf-8")
            (root / "stdout.log").symlink_to(victim)
            with self.assertRaises(OSError):
                osint_forge.open_private_log(root / "stdout.log")
            self.assertEqual(victim.read_text(encoding="utf-8"), "preserve")

    def test_batch_run_directories_do_not_collide(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = osint_forge.create_run_directory(root, "same name", "20260101-120000")
            second = osint_forge.create_run_directory(root, "same name", "20260101-120000")
            self.assertNotEqual(first, second)
            self.assertTrue(first.is_dir())
            self.assertTrue(second.is_dir())
            self.assertEqual((root.stat().st_mode & 0o777), 0o700)

    def test_batch_run_directory_uses_utc_identifier(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = osint_forge.create_run_directory(Path(temp), "utc")
            self.assertRegex(run_dir.name, r"^\d{8}T\d{6}Z-utc$")

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
            for path in run_dirs[0].rglob("*"):
                expected = 0o700 if path.is_dir() else 0o600
                self.assertEqual(
                    (path.stat().st_mode & 0o777),
                    expected,
                    f"unexpected permissions for {path}",
                )

    def test_batch_without_matching_jobs_leaves_no_run_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            targets = root / "targets.txt"
            targets.write_text("[Usernames]\nexample_handle\n", encoding="utf-8")
            output_root = root / "output"
            args = argparse.Namespace(
                input=targets,
                output_root=output_root,
                name="no-match",
                plugins=[],
                jobs=1,
                dry_run=False,
            )
            with mock.patch.object(osint_forge, "is_installed", return_value=False):
                self.assertEqual(osint_forge.cmd_batch(args), 1)
            self.assertFalse(output_root.exists())

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

    def test_lifecycle_includes_pipx_user_bin(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            user_bin = home / ".local" / "bin"
            user_bin.mkdir(parents=True)
            command = user_bin / "osint-forge-fake-command"
            command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            command.chmod(0o755)
            script = home / "doctor.sh"
            script.write_text(
                "#!/bin/sh\ncommand -v osint-forge-fake-command >/dev/null\n",
                encoding="utf-8",
            )
            script.chmod(0o755)
            manifest = {
                "id": "example",
                "name": "Example",
                "plugin_version": "1",
                "lifecycle": {"doctor": "doctor.sh"},
                "requires_root": {"doctor": False},
            }
            with mock.patch.dict(os.environ, {"HOME": str(home), "PATH": "/usr/bin"}), \
                 mock.patch.object(Path, "home", return_value=home), \
                 mock.patch.object(
                     osint_forge,
                     "require_plugin",
                     return_value=(home, manifest),
                 ):
                rc = osint_forge.run_lifecycle("example", "doctor")

            self.assertEqual(rc, 0)

    def test_lifecycle_flushes_heading_before_child_output(self):
        with tempfile.TemporaryDirectory() as temp:
            plugin_dir = Path(temp)
            script = plugin_dir / "doctor.sh"
            script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            script.chmod(0o755)
            manifest = {
                "id": "example",
                "name": "Example",
                "plugin_version": "1",
                "lifecycle": {"doctor": "doctor.sh"},
                "requires_root": {"doctor": False},
            }
            output = io.StringIO()

            def run(command_args, *, env, check):
                print("CHILD")
                return subprocess.CompletedProcess(command_args, 0)

            with mock.patch.object(
                osint_forge,
                "require_plugin",
                return_value=(plugin_dir, manifest),
            ), mock.patch("subprocess.run", side_effect=run), \
                 contextlib.redirect_stdout(output):
                rc = osint_forge.run_lifecycle("example", "doctor")

            self.assertEqual(rc, 0)
            self.assertLess(output.getvalue().index("DOCTOR"), output.getvalue().index("CHILD"))

    def test_stale_install_record_does_not_claim_missing_tool_is_installed(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.dict(
                os.environ,
                {
                    "OSINT_FORGE_STATE": str(Path(temp) / "state"),
                    "PATH": str(Path(temp) / "empty-bin"),
                },
            ):
                osint_forge.save_record(
                    "maigret",
                    osint_forge.catalog()["maigret"][1],
                    "install",
                )
                self.assertFalse(osint_forge.is_installed("maigret"))

    def test_adapter_refuses_symbolic_link_output_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / "outside"
            outside.mkdir()
            output = root / "output"
            output.symlink_to(outside, target_is_directory=True)
            with mock.patch.object(osint_forge, "require_plugin") as require:
                require.return_value = (
                    root,
                    {
                        "id": "example",
                        "adapters": {"username": {"command": ["example", "{target}"]}},
                    },
                )
                with self.assertRaisesRegex(RuntimeError, "symbolic-link"):
                    osint_forge.run_adapter(
                        "example", "username", "alice", output, True
                    )


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


class CaseManagementTests(unittest.TestCase):
    def create_case(self, root: Path, case_id: str = "case-001"):
        env = {"OSINT_FORGE_CASES": str(root)}
        with mock.patch.dict(os.environ, env):
            rc = osint_forge.cmd_case_create(
                argparse.Namespace(
                    case=case_id,
                    purpose="Synthetic integration test",
                    authorization="Owned test fixtures only",
                )
            )
        self.assertEqual(rc, 0)
        return root / case_id

    def add_target(
        self,
        root: Path,
        case_id: str = "case-001",
        target_type: str = "username",
        value: str = "example_handle",
    ):
        with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
            return osint_forge.cmd_case_add(
                argparse.Namespace(case=case_id, type=target_type, target=value)
            )

    def run_args(self, case_id: str = "case-001", **overrides):
        values = {
            "case": case_id,
            "plugins": ["maigret", "sherlock"],
            "jobs": 2,
            "rerun": False,
            "dry_run": False,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_case_create_and_add_are_private_and_append_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_case(root)
            self.assertEqual(self.add_target(root), 0)
            self.assertEqual(self.add_target(root), 0)

            metadata = json.loads((case / "case.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["schema"], osint_forge.CASE_SCHEMA)
            self.assertEqual(metadata["purpose"], "Synthetic integration test")
            self.assertEqual(metadata["authorization_scope"], "Owned test fixtures only")
            self.assertEqual(len(metadata["targets"]), 1)
            self.assertEqual((case.stat().st_mode & 0o777), 0o700)
            self.assertEqual(((case / "case.json").stat().st_mode & 0o777), 0o600)
            self.assertEqual(((case / "activity.jsonl").stat().st_mode & 0o777), 0o600)

            events = [
                json.loads(line)["event"]
                for line in (case / "activity.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(events, ["case_created", "target_added"])

    def test_case_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            cli = osint_forge.SOURCE_ROOT / "bin" / "osint"
            env = {**os.environ, "OSINT_FORGE_CASES": str(root)}
            commands = [
                [
                    str(cli), "case", "create", "cli-case",
                    "--purpose", "CLI integration",
                    "--authorization", "Owned fixture",
                ],
                [str(cli), "case", "add", "cli-case", "username", "example_handle"],
                [
                    str(cli), "case", "run", "cli-case",
                    "--plugins", "maigret", "sherlock", "--dry-run",
                ],
                [str(cli), "case", "status", "cli-case", "--json"],
                [str(cli), "case", "report", "cli-case"],
            ]
            completed = []
            for command in commands:
                result = subprocess.run(
                    command,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                completed.append(result)
            status = json.loads(completed[3].stdout)
            self.assertEqual(status["target_count"], 1)
            self.assertEqual(status["previewed_jobs"], 2)
            self.assertTrue((root / "cli-case" / "report.md").is_file())

    def test_case_rejects_unsafe_identifier_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                with self.assertRaises(SystemExit):
                    osint_forge.cmd_case_create(
                        argparse.Namespace(
                            case="../escape",
                            purpose="test",
                            authorization="test",
                        )
                    )
                root.mkdir(exist_ok=True)
                (root / "linked").symlink_to(Path(temp))
                with self.assertRaisesRegex(SystemExit, "symbolic-link"):
                    osint_forge.load_case("linked")

    def test_case_create_rejects_empty_scope_without_leaving_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                with self.assertRaisesRegex(SystemExit, "cannot be empty"):
                    osint_forge.cmd_case_create(
                        argparse.Namespace(
                            case="empty-case",
                            purpose=" ",
                            authorization="Owned fixture",
                        )
                    )
            self.assertFalse((root / "empty-case").exists())

    def test_file_target_is_normalized_and_invalid_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            self.create_case(root)
            fixture = Path(temp) / "evidence.bin"
            fixture.write_bytes(b"synthetic evidence")
            self.assertEqual(
                self.add_target(root, target_type="file", value=str(fixture)),
                0,
            )
            metadata = json.loads(
                (root / "case-001" / "case.json").read_text(encoding="utf-8")
            )
            self.assertEqual(metadata["targets"][0]["value"], str(fixture.resolve()))
            with self.assertRaisesRegex(SystemExit, "Invalid file"):
                self.add_target(
                    root,
                    target_type="file",
                    value=str(Path(temp) / "missing.bin"),
                )

    def test_unknown_case_and_malformed_metadata_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                with self.assertRaisesRegex(SystemExit, "Unknown case"):
                    osint_forge.load_case("missing")
                malformed = root / "malformed"
                malformed.mkdir()
                (malformed / "case.json").write_text("{", encoding="utf-8")
                with self.assertRaisesRegex(SystemExit, "invalid case.json"):
                    osint_forge.load_case("malformed")

    def test_case_rejects_malformed_target_and_job_records(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_case(root)
            metadata_path = case / "case.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["targets"] = [{"id": "wrong", "type": "username"}]
            osint_forge.write_private_json(metadata_path, metadata)
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                with self.assertRaisesRegex(SystemExit, "invalid target record"):
                    osint_forge.load_case("case-001")

            metadata["targets"] = []
            metadata["jobs"] = {"job": {"status": "failed", "exit_code": "1"}}
            osint_forge.write_private_json(metadata_path, metadata)
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                with self.assertRaisesRegex(SystemExit, "invalid job exit code"):
                    osint_forge.load_case("case-001")

    def test_nested_case_directory_symbolic_link_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case = root / "case"
            case.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (case / "raw").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "symbolic-link"):
                osint_forge.secure_case_directory(
                    case / "raw" / "username",
                    case,
                )

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires O_NOFOLLOW")
    def test_case_activity_refuses_symbolic_link(self):
        with tempfile.TemporaryDirectory() as temp:
            case = Path(temp) / "case"
            case.mkdir()
            victim = Path(temp) / "victim"
            victim.write_text("preserve", encoding="utf-8")
            (case / "activity.jsonl").symlink_to(victim)
            with self.assertRaises(OSError):
                osint_forge.append_case_activity(case, "test")
            self.assertEqual(victim.read_text(encoding="utf-8"), "preserve")

    def test_empty_case_and_unknown_plugin_cannot_start_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            self.create_case(root)
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                with self.assertRaisesRegex(SystemExit, "add at least one target"):
                    osint_forge.cmd_case_run(
                        self.run_args(plugins=["maigret"], dry_run=True)
                    )
            self.add_target(root)
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                with self.assertRaisesRegex(SystemExit, "Unknown case plugin"):
                    osint_forge.cmd_case_run(
                        self.run_args(plugins=["not-a-plugin"], dry_run=True)
                    )

    def test_dry_run_preserves_provenance_without_completing_jobs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_case(root)
            self.add_target(root)
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                rc = osint_forge.cmd_case_run(
                    self.run_args(dry_run=True)
                )
            self.assertEqual(rc, 0)
            metadata = json.loads((case / "case.json").read_text(encoding="utf-8"))
            self.assertEqual(
                {state["status"] for state in metadata["jobs"].values()},
                {"previewed"},
            )
            status_files = list((case / "runs").glob("*/raw/**/status.json"))
            self.assertEqual(len(status_files), 2)
            run_metadata = json.loads(
                next((case / "runs").glob("*/run.json")).read_text(encoding="utf-8")
            )
            self.assertEqual(len(run_metadata["planned_jobs"]), 2)
            self.assertTrue(
                all(isinstance(job["command"], list) for job in run_metadata["planned_jobs"])
            )
            for status_file in status_files:
                status = json.loads(status_file.read_text(encoding="utf-8"))
                self.assertTrue(status["dry_run"])
                self.assertEqual(status["framework_version"], osint_forge.__version__)
                self.assertIn("plugin_version", status)
                self.assertIsInstance(status["command"], list)
            for directory in [case, *[p for p in case.rglob("*") if p.is_dir()]]:
                self.assertEqual((directory.stat().st_mode & 0o777), 0o700)
            for file_path in [p for p in case.rglob("*") if p.is_file()]:
                self.assertEqual((file_path.stat().st_mode & 0o777), 0o600)

    def test_failed_job_resumes_while_successful_job_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_case(root)
            self.add_target(root)

            def first_run(plugin, target_type, value, output, dry_run):
                output.mkdir(parents=True, exist_ok=True)
                rc = 1 if plugin == "sherlock" else 0
                osint_forge.write_private_json(
                    output / "status.json",
                    {
                        "plugin": plugin,
                        "target_type": target_type,
                        "target": value,
                        "command": [plugin, value],
                        "exit_code": rc,
                        "completed_at": osint_forge.now(),
                    },
                )
                return rc

            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}), \
                 mock.patch.object(osint_forge, "is_installed", return_value=True), \
                 mock.patch.object(osint_forge, "run_adapter", side_effect=first_run):
                first_rc = osint_forge.cmd_case_run(self.run_args(jobs=1))
            self.assertEqual(first_rc, 1)

            metadata = json.loads((case / "case.json").read_text(encoding="utf-8"))
            self.assertEqual(
                {state["status"] for state in metadata["jobs"].values()},
                {"completed", "failed"},
            )

            def resumed_run(plugin, target_type, value, output, dry_run):
                output.mkdir(parents=True, exist_ok=True)
                osint_forge.write_private_json(
                    output / "status.json",
                    {
                        "plugin": plugin,
                        "target_type": target_type,
                        "target": value,
                        "command": [plugin, value],
                        "exit_code": 0,
                        "completed_at": osint_forge.now(),
                    },
                )
                return 0

            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}), \
                 mock.patch.object(osint_forge, "is_installed", return_value=True), \
                 mock.patch.object(osint_forge, "run_adapter", side_effect=resumed_run) as run:
                second_rc = osint_forge.cmd_case_run(self.run_args(jobs=1))
            self.assertEqual(second_rc, 0)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0], "sherlock")
            metadata = json.loads((case / "case.json").read_text(encoding="utf-8"))
            self.assertEqual(
                {state["status"] for state in metadata["jobs"].values()},
                {"completed"},
            )

    def test_internal_job_error_is_recorded_and_resumable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_case(root)
            self.add_target(root)
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}), \
                 mock.patch.object(osint_forge, "is_installed", return_value=True), \
                 mock.patch.object(
                     osint_forge,
                     "run_adapter",
                     side_effect=RuntimeError("synthetic worker failure"),
                 ):
                rc = osint_forge.cmd_case_run(
                    self.run_args(plugins=["maigret"], jobs=1)
                )
            self.assertEqual(rc, 1)
            metadata = json.loads((case / "case.json").read_text(encoding="utf-8"))
            state = next(iter(metadata["jobs"].values()))
            self.assertEqual(state["status"], "failed")
            self.assertEqual(state["exit_code"], 70)
            status = json.loads(
                next((case / "runs").glob("*/raw/**/status.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertIn("synthetic worker failure", status["error"])

    def test_interrupted_run_is_recorded_for_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_case(root)
            self.add_target(root)
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}), \
                 mock.patch.object(osint_forge, "is_installed", return_value=True), \
                 mock.patch(
                     "concurrent.futures.as_completed",
                     side_effect=KeyboardInterrupt,
                 ):
                rc = osint_forge.cmd_case_run(
                    self.run_args(plugins=["maigret"], jobs=1)
                )
            self.assertEqual(rc, 130)
            run = json.loads(
                next((case / "runs").glob("*/run.json")).read_text(encoding="utf-8")
            )
            self.assertEqual(run["status"], "interrupted")
            self.assertEqual(run["results"], [])
            events = [
                json.loads(line)
                for line in (case / "activity.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(events[-1]["event"], "run_finished")
            self.assertEqual(events[-1]["status"], "interrupted")

    def test_case_report_links_raw_output_and_cannot_escape_case(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_case(root)
            self.add_target(root)
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                osint_forge.cmd_case_run(self.run_args(dry_run=True))
                rc = osint_forge.cmd_case_report(
                    argparse.Namespace(
                        case="case-001",
                        output=Path("summaries/report.md"),
                        force=False,
                    )
                )
                with self.assertRaisesRegex(SystemExit, "inside the case"):
                    osint_forge.cmd_case_report(
                        argparse.Namespace(
                            case="case-001",
                            output=Path("../escaped.md"),
                            force=False,
                        )
                    )
                for reserved in ("case.json", "activity.jsonl", "runs/report.md"):
                    with self.assertRaisesRegex(SystemExit, "reserved case records"):
                        osint_forge.cmd_case_report(
                            argparse.Namespace(
                                case="case-001",
                                output=Path(reserved),
                                force=True,
                            )
                        )
                with self.assertRaisesRegex(SystemExit, "already exists"):
                    osint_forge.cmd_case_report(
                        argparse.Namespace(
                            case="case-001",
                            output=Path("summaries/report.md"),
                            force=False,
                        )
                    )
                forced = osint_forge.cmd_case_report(
                    argparse.Namespace(
                        case="case-001",
                        output=Path("summaries/report.md"),
                        force=True,
                    )
                )
            self.assertEqual(rc, 0)
            self.assertEqual(forced, 0)
            report = case / "summaries" / "report.md"
            content = report.read_text(encoding="utf-8")
            self.assertIn("Raw tool output is not a verified finding", content)
            self.assertIn("[preserved output](../runs/", content)
            self.assertEqual((report.stat().st_mode & 0o777), 0o600)

    def test_case_report_escapes_markdown_control_characters(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_case(root)
            metadata_path = case / "case.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["purpose"] = "line one\n# injected"
            osint_forge.write_private_json(metadata_path, metadata)
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                osint_forge.cmd_case_report(
                    argparse.Namespace(case="case-001", output=None, force=False)
                )
            report = (case / "report.md").read_text(encoding="utf-8")
            self.assertIn("line one # injected", report)
            self.assertNotIn("\n# injected", report)

    def test_legacy_case_migrates_and_future_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            legacy = root / "legacy"
            legacy.mkdir(parents=True)
            osint_forge.write_private_json(
                legacy / "case.json",
                {
                    "id": "legacy",
                    "purpose": "legacy",
                    "authorization_scope": "test",
                    "created_at": osint_forge.now(),
                },
            )
            future = root / "future"
            future.mkdir()
            osint_forge.write_private_json(
                future / "case.json",
                {"schema": osint_forge.CASE_SCHEMA + 1},
            )
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                _, migrated = osint_forge.load_case("legacy")
                self.assertEqual(migrated["schema"], osint_forge.CASE_SCHEMA)
                self.assertEqual(migrated["targets"], [])
                self.assertEqual(migrated["jobs"], {})
                with self.assertRaisesRegex(SystemExit, "newer than supported"):
                    osint_forge.load_case("future")


class ShellScriptTests(unittest.TestCase):
    def test_source_framework_lifecycles_deploy_private_launchers(self):
        for plugin_id, entrypoint in (
            ("recon-ng", "recon-ng/.venv/bin/python"),
            ("spiderfoot", "spiderfoot/.venv/bin/python"),
        ):
            with self.subTest(plugin=plugin_id):
                plugin = osint_forge.SOURCE_ROOT / "plugins" / plugin_id
                launcher = (plugin / "launcher.sh").read_text(encoding="utf-8")
                self.assertIn("umask 0077", launcher)
                self.assertIn(f"exec /opt/osint-forge/{entrypoint}", launcher)
                for lifecycle in ("install.sh", "update.sh"):
                    content = (plugin / lifecycle).read_text(encoding="utf-8")
                    self.assertIn(
                        'install -m 0755 "${OSINT_FORGE_PLUGIN_DIR}/launcher.sh" '
                        f"/usr/local/bin/{plugin_id}",
                        content,
                    )
        spiderfoot_launcher = (
            osint_forge.SOURCE_ROOT / "plugins" / "spiderfoot" / "launcher.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('application="/opt/osint-forge/spiderfoot"', spiderfoot_launcher)
        self.assertIn('cd "$application"', spiderfoot_launcher)
        self.assertIn("Unable to enter SpiderFoot application directory", spiderfoot_launcher)

    def test_spiderfoot_lifecycle_installs_native_build_dependencies(self):
        plugin = osint_forge.SOURCE_ROOT / "plugins" / "spiderfoot"
        dependencies = (plugin / "build-dependencies.sh").read_text(encoding="utf-8")
        for package in (
            "build-essential",
            "cargo",
            "libffi-dev",
            "libjpeg-dev",
            "libopenjp2-7-dev",
            "libssl-dev",
            "libtinyxml2-dev",
            "libxml2-dev",
            "libxslt1-dev",
            "python3-dev",
            "swig",
            "zlib1g-dev",
        ):
            self.assertIn(package, dependencies)
        self.assertIn("run apt-get update", dependencies)
        self.assertIn('run apt-get install -y "${spiderfoot_build_dependencies[@]}"', dependencies)
        for lifecycle in ("install.sh", "update.sh"):
            content = (plugin / lifecycle).read_text(encoding="utf-8")
            self.assertIn(
                'source "${OSINT_FORGE_PLUGIN_DIR}/build-dependencies.sh"',
                content,
            )
            self.assertIn("install_spiderfoot_build_dependencies", content)

    def test_spiderfoot_python_313_requirements_overlay(self):
        plugin = osint_forge.SOURCE_ROOT / "plugins" / "spiderfoot"
        helper = plugin / "requirements-compat.sh"
        for lifecycle in ("install.sh", "update.sh"):
            content = (plugin / lifecycle).read_text(encoding="utf-8")
            self.assertIn(
                'source "${OSINT_FORGE_PLUGIN_DIR}/requirements-compat.sh"',
                content,
            )
            self.assertIn("spiderfoot_requirements_file", content)

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            upstream = base / "requirements.txt"
            original = "requests>=2,<3\nlxml>=4.9.2,<5\npyyaml>=6,<7\n"
            upstream.write_text(original, encoding="utf-8")
            python313 = base / "python313"
            python313.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            python313.chmod(0o755)

            command = (
                f"source {shlex.quote(str(helper))}\n"
                f"spiderfoot_requirements_file {shlex.quote(str(base))} "
                f"{shlex.quote(str(python313))}\n"
            )
            completed = subprocess.run(
                ["bash", "-c", command],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            overlay = Path(completed.stdout.strip())
            self.assertEqual(overlay, base / ".osint-forge-requirements.txt")
            self.assertEqual(upstream.read_text(encoding="utf-8"), original)
            self.assertEqual(
                overlay.read_text(encoding="utf-8"),
                "requests>=2,<3\nlxml>=5.3,<6\npyyaml>=6,<7\n",
            )
            self.assertEqual(overlay.stat().st_mode & 0o777, 0o644)

    def test_spiderfoot_older_python_uses_upstream_requirements(self):
        plugin = osint_forge.SOURCE_ROOT / "plugins" / "spiderfoot"
        helper = plugin / "requirements-compat.sh"
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            upstream = base / "requirements.txt"
            upstream.write_text("lxml>=4.9.2,<5\n", encoding="utf-8")
            python312 = base / "python312"
            python312.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            python312.chmod(0o755)
            command = (
                f"source {shlex.quote(str(helper))}\n"
                f"spiderfoot_requirements_file {shlex.quote(str(base))} "
                f"{shlex.quote(str(python312))}\n"
            )
            completed = subprocess.run(
                ["bash", "-c", command],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(Path(completed.stdout.strip()), upstream)
            self.assertFalse((base / ".osint-forge-requirements.txt").exists())

    def test_spiderfoot_requirements_overlay_dry_run_does_not_write(self):
        plugin = osint_forge.SOURCE_ROOT / "plugins" / "spiderfoot"
        helper = plugin / "requirements-compat.sh"
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / "requirements.txt").write_text(
                "lxml>=4.9.2,<5\n",
                encoding="utf-8",
            )
            python313 = base / "python313"
            python313.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            python313.chmod(0o755)
            command = (
                "dry_run=1\n"
                f"source {shlex.quote(str(helper))}\n"
                f"spiderfoot_requirements_file {shlex.quote(str(base))} "
                f"{shlex.quote(str(python313))}\n"
            )
            completed = subprocess.run(
                ["bash", "-c", command],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                Path(completed.stdout.strip()),
                base / ".osint-forge-requirements.txt",
            )
            self.assertFalse((base / ".osint-forge-requirements.txt").exists())

    def test_spiderfoot_requirements_overlay_fails_closed(self):
        plugin = osint_forge.SOURCE_ROOT / "plugins" / "spiderfoot"
        helper = plugin / "requirements-compat.sh"
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / "requirements.txt").write_text(
                "requests>=2,<3\n",
                encoding="utf-8",
            )
            python313 = base / "python313"
            python313.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            python313.chmod(0o755)
            command = (
                f"source {shlex.quote(str(helper))}\n"
                f"spiderfoot_requirements_file {shlex.quote(str(base))} "
                f"{shlex.quote(str(python313))}\n"
            )
            completed = subprocess.run(
                ["bash", "-c", command],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Expected exactly one lxml requirement", completed.stderr)
            self.assertFalse((base / ".osint-forge-requirements.txt").exists())

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

    @unittest.skipUnless(os.geteuid() == 0, "isolated bootstrap requires root")
    def test_bootstrap_configures_pipx_user_path(self):
        root = osint_forge.SOURCE_ROOT
        with tempfile.TemporaryDirectory() as temp:
            sandbox = Path(temp)
            fake_bin = sandbox / "fake-bin"
            fake_bin.mkdir()
            calls = sandbox / "calls"
            for name in ("apt-get", "pipx"):
                executable = fake_bin / name
                executable.write_text(
                    f"#!/bin/sh\nprintf '%s %s\\n' {name} \"$*\" >> {calls}\n",
                    encoding="utf-8",
                )
                executable.chmod(0o755)
            target_home = sandbox / "home"
            target_home.mkdir()
            env = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "OSINT_FORGE_INSTALL_ROOT": str(sandbox / "share" / "osint-forge"),
                "OSINT_FORGE_BIN_DIR": str(sandbox / "bin"),
                "OSINT_FORGE_ETC_ROOT": str(sandbox / "etc" / "osint-forge"),
                "OSINT_FORGE_TARGET_HOME": str(target_home),
            }
            completed = subprocess.run(
                [str(root / "bootstrap.sh")],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            recorded = calls.read_text(encoding="utf-8")
            self.assertIn("apt-get update", recorded)
            self.assertIn("pipx ensurepath", recorded)

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
            self.assertTrue((install_root / ".osint-forge-install").is_file())
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

            cases = sandbox / "cases"
            runtime_env = {
                **env,
                "OSINT_FORGE_ROOT": str(install_root),
                "OSINT_FORGE_CASES": str(cases),
            }
            installed_cli = bin_dir / "osint"
            installed_commands = [
                [str(installed_cli), "--version"],
                [
                    str(installed_cli), "case", "create", "installed-case",
                    "--purpose", "Installed CLI integration",
                    "--authorization", "Owned fixture",
                ],
                [
                    str(installed_cli), "case", "add", "installed-case",
                    "username", "example_handle",
                ],
                [
                    str(installed_cli), "case", "run", "installed-case",
                    "--plugins", "maigret", "sherlock", "--dry-run",
                ],
                [str(installed_cli), "case", "status", "installed-case", "--json"],
                [str(installed_cli), "case", "report", "installed-case"],
            ]
            for command in installed_commands:
                completed = subprocess.run(
                    command,
                    env=runtime_env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue((cases / "installed-case" / "report.md").is_file())

            removed = subprocess.run(
                [str(uninstall_script)], env=env, text=True, capture_output=True, check=False
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse(install_root.exists())
            self.assertFalse((bin_dir / "osint").exists())
            self.assertTrue(config.is_file())
            self.assertTrue((cases / "installed-case" / "case.json").is_file())

    @unittest.skipUnless(os.geteuid() == 0, "isolated framework install requires root")
    def test_uninstall_refuses_unrecognized_paths_and_launchers(self):
        root = osint_forge.SOURCE_ROOT
        with tempfile.TemporaryDirectory() as temp:
            sandbox = Path(temp)
            install_root = sandbox / "share" / "osint-forge"
            bin_dir = sandbox / "bin"
            target_home = sandbox / "home"
            target_home.mkdir()
            env = {
                **os.environ,
                "OSINT_FORGE_INSTALL_ROOT": str(install_root),
                "OSINT_FORGE_BIN_DIR": str(bin_dir),
                "OSINT_FORGE_ETC_ROOT": str(sandbox / "etc" / "osint-forge"),
                "OSINT_FORGE_TARGET_HOME": str(target_home),
            }
            uninstall_script = root / "scripts" / "uninstall-framework.sh"
            install_root.mkdir(parents=True)
            unrecognized = subprocess.run(
                [str(uninstall_script)], env=env, text=True,
                capture_output=True, check=False,
            )
            self.assertNotEqual(unrecognized.returncode, 0)
            self.assertTrue(install_root.is_dir())

            shutil.rmtree(install_root)
            installed = subprocess.run(
                [str(root / "scripts" / "install-framework.sh")],
                env=env, text=True, capture_output=True, check=False,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            launcher = bin_dir / "osint"
            launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            refused = subprocess.run(
                [str(uninstall_script)], env=env, text=True,
                capture_output=True, check=False,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertTrue(install_root.is_dir())
            self.assertTrue(launcher.is_file())


if __name__ == "__main__":
    unittest.main()
