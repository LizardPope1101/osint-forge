# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import csv
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from forge import osint_forge, reporting


FIXTURES = Path(__file__).parent / "fixtures" / "reporting"


class ReportingTests(unittest.TestCase):
    def create_fixture_case(self, root: Path) -> Path:
        case = root / "report-case"
        case.mkdir(parents=True, mode=0o700)
        timestamp = "2026-07-29T12:00:00+00:00"
        target_specs = [
            ("file", "/evidence/sample.txt"),
            ("email", "analyst@example.com"),
            ("username", "example_handle"),
            ("ip", "192.0.2.10"),
        ]
        target_ids = {
            kind: osint_forge.target_id(kind, value)
            for kind, value in target_specs
        }
        targets = [
            {
                "id": target_ids[kind],
                "type": kind,
                "value": value,
                "added_at": timestamp,
            }
            for kind, value in target_specs
        ]
        jobs = {}
        sources = {
            "exiftool": (target_ids["file"], "file", "/evidence/sample.txt", "stdout.log", "exiftool.json"),
            "ghunt": (target_ids["email"], "email", "analyst@example.com", "results.json", "ghunt.json"),
            "maigret": (
                target_ids["username"], "username", "example_handle",
                "reports/report_example_handle_simple.json", "maigret.json",
            ),
            "nmap": (target_ids["ip"], "ip", "192.0.2.10", "results.xml", "nmap.xml"),
            "sherlock": (
                target_ids["username"], "username", "example_handle",
                "example_handle.csv", "sherlock.csv",
            ),
        }
        for plugin, (target_id, target_type, target, destination, fixture) in sources.items():
            output_rel = f"runs/run-001/raw/{target_type}s/value/{plugin}"
            output = case / output_rel
            output.mkdir(parents=True, mode=0o700)
            destination_path = output / destination
            destination_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(FIXTURES / fixture, destination_path)
            destination_path.chmod(0o600)
            osint_forge.write_private_json(
                output / "status.json",
                {
                    "plugin": plugin,
                    "plugin_version": "2",
                    "framework_version": "0.4.0",
                    "target_id": target_id,
                    "target_type": target_type,
                    "target": target,
                    "command": [plugin, target],
                    "exit_code": 0,
                    "started_at": timestamp,
                    "completed_at": timestamp,
                },
            )
            jobs[f"{plugin}-job"] = {
                "status": "completed",
                "exit_code": 0,
                "plugin": plugin,
                "plugin_version": "2",
                "target_id": target_id,
                "last_run": "run-001",
                "output": output_rel,
                "completed_at": timestamp,
            }
        failed_output = case / "runs/run-001/raw/usernames/value/sherlock-failed"
        failed_output.mkdir(parents=True, mode=0o700)
        osint_forge.write_private_json(
            failed_output / "status.json",
            {
                "plugin": "sherlock",
                "plugin_version": "2",
                "framework_version": "0.4.0",
                "target_id": target_ids["username"],
                "target_type": "username",
                "target": "example_handle",
                "command": ["sherlock", "example_handle"],
                "exit_code": 1,
                "error": "synthetic adapter failure",
                "started_at": timestamp,
                "completed_at": timestamp,
            },
        )
        jobs["failed-job"] = {
            "status": "failed",
            "exit_code": 1,
            "plugin": "sherlock",
            "plugin_version": "2",
            "target_id": target_ids["username"],
            "last_run": "run-001",
            "output": str(failed_output.relative_to(case)),
            "completed_at": timestamp,
        }
        metadata = {
            "schema": 1,
            "id": "report-case",
            "purpose": "Synthetic <script>alert(1)</script> report",
            "authorization_scope": "Owned fixtures only",
            "created_at": timestamp,
            "updated_at": timestamp,
            "targets": targets,
            "jobs": jobs,
        }
        osint_forge.write_private_json(case / "case.json", metadata)
        (case / "activity.jsonl").write_text("", encoding="utf-8")
        (case / "activity.jsonl").chmod(0o600)
        return case

    def test_fixture_report_is_deterministic_traceable_and_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_fixture_case(root)
            metadata = json.loads((case / "case.json").read_text(encoding="utf-8"))
            first = reporting.build_report(
                case, metadata, osint_forge.catalog(), osint_forge.__version__
            )
            second = reporting.build_report(
                case, metadata, osint_forge.catalog(), osint_forge.__version__
            )
            self.assertEqual(reporting.render_json(first), reporting.render_json(second))
            self.assertEqual(first["summary"]["finding_count"], 6)
            self.assertEqual(first["summary"]["failed_jobs"], 1)
            self.assertEqual(first["normalization_errors"], [])
            self.assertTrue(first["integrity"]["all_findings_traceable"])
            for finding in first["findings"]:
                self.assertTrue((case / finding["source"]["source_file"]).is_file())
            original_ids = {finding["id"] for finding in first["findings"]}
            for state in metadata["jobs"].values():
                if state["status"] != "completed":
                    continue
                old_output = case / state["output"]
                new_relative = state["output"].replace("run-001", "run-002", 1)
                new_output = case / new_relative
                shutil.copytree(old_output, new_output)
                state["output"] = new_relative
                state["last_run"] = "run-002"
            rerun = reporting.build_report(
                case, metadata, osint_forge.catalog(), osint_forge.__version__
            )
            self.assertEqual(
                original_ids,
                {finding["id"] for finding in rerun["findings"]},
            )

    def test_all_formats_and_shareable_redaction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_fixture_case(root)
            args = argparse.Namespace(
                case="report-case",
                format="all",
                shareable=False,
                output=None,
                force=False,
            )
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                self.assertEqual(osint_forge.cmd_case_report(args), 0)
                args.shareable = True
                self.assertEqual(osint_forge.cmd_case_report(args), 0)
            report = json.loads((case / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["finding_count"], 6)
            self.assertIn("failed", (case / "report.md").read_text(encoding="utf-8"))
            html = (case / "report.html").read_text(encoding="utf-8")
            self.assertIn("synthetic adapter failure", html)
            self.assertNotIn("<script>alert(1)</script>", html)
            rows = list(csv.DictReader(io.StringIO(
                (case / "findings.csv").read_text(encoding="utf-8")
            )))
            self.assertEqual(len(rows), 6)
            shared_text = "\n".join(
                (case / name).read_text(encoding="utf-8")
                for name in (
                    "shareable-report.json",
                    "shareable-report.md",
                    "shareable-report.html",
                    "shareable-findings.csv",
                )
            )
            for secret in (
                "report-case",
                "example_handle",
                "analyst@example.com",
                "192.0.2.10",
                "/evidence/sample.txt",
                "synthetic adapter failure",
            ):
                self.assertNotIn(secret, shared_text)
            for generated in case.glob("*report.*"):
                self.assertEqual(generated.stat().st_mode & 0o777, 0o600)

    def test_annotation_round_trip_and_unknown_finding(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_fixture_case(root)
            metadata = json.loads((case / "case.json").read_text(encoding="utf-8"))
            report = reporting.build_report(
                case, metadata, osint_forge.catalog(), osint_forge.__version__
            )
            finding_id = report["findings"][0]["id"]
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                self.assertEqual(
                    osint_forge.cmd_case_annotate(argparse.Namespace(
                        case="report-case",
                        finding=finding_id,
                        confidence="high",
                        note="Fixture verified manually.",
                        clear_note=False,
                    )),
                    0,
                )
                with self.assertRaisesRegex(SystemExit, "Unknown finding"):
                    osint_forge.cmd_case_annotate(argparse.Namespace(
                        case="report-case",
                        finding="finding-does-not-exist",
                        confidence="low",
                        note=None,
                        clear_note=False,
                    ))
            metadata = json.loads((case / "case.json").read_text(encoding="utf-8"))
            updated = reporting.build_report(
                case, metadata, osint_forge.catalog(), osint_forge.__version__
            )
            reviewed = next(item for item in updated["findings"] if item["id"] == finding_id)
            self.assertEqual(reviewed["confidence"], "high")
            self.assertEqual(reviewed["analyst_note"], "Fixture verified manually.")
            self.assertEqual(
                (case / "findings" / "reviews.json").stat().st_mode & 0o777,
                0o600,
            )

    def test_source_symlink_is_rejected_and_report_records_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_fixture_case(root)
            source = next(case.glob("runs/**/exiftool/stdout.log"))
            source.unlink()
            source.symlink_to(FIXTURES / "exiftool.json")
            metadata = json.loads((case / "case.json").read_text(encoding="utf-8"))
            report = reporting.build_report(
                case, metadata, osint_forge.catalog(), osint_forge.__version__
            )
            self.assertEqual(report["summary"]["normalization_error_count"], 1)
            self.assertIn("symbolic link", report["normalization_errors"][0]["error"])

    def test_report_output_symbolic_link_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_fixture_case(root)
            (case / "actual").mkdir()
            (case / "linked").symlink_to(case / "actual", target_is_directory=True)
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                with self.assertRaisesRegex(SystemExit, "symbolic link"):
                    osint_forge.cmd_case_report(argparse.Namespace(
                        case="report-case",
                        format="json",
                        shareable=False,
                        output=Path("linked/report.json"),
                        force=False,
                    ))

    def test_review_directory_symbolic_link_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_fixture_case(root)
            outside = Path(temp) / "outside"
            outside.mkdir()
            (case / "findings").symlink_to(outside, target_is_directory=True)
            metadata = json.loads((case / "case.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(reporting.NormalizationError, "symbolic-link"):
                reporting.build_report(
                    case, metadata, osint_forge.catalog(), osint_forge.__version__
                )

    def test_tampered_status_provenance_is_not_normalized(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "cases"
            case = self.create_fixture_case(root)
            status_path = next(case.glob("runs/**/exiftool/status.json"))
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["target"] = "/different/file.txt"
            osint_forge.write_private_json(status_path, status)
            metadata = json.loads((case / "case.json").read_text(encoding="utf-8"))
            report = reporting.build_report(
                case, metadata, osint_forge.catalog(), osint_forge.__version__
            )
            self.assertEqual(report["summary"]["normalization_error_count"], 1)
            self.assertEqual(
                [
                    finding for finding in report["findings"]
                    if finding["source"]["plugin"] == "exiftool"
                ],
                [],
            )
            self.assertIn(
                "status provenance does not match",
                report["normalization_errors"][0]["error"],
            )


if __name__ == "__main__":
    unittest.main()
