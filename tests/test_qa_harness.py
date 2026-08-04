# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "qa_harness", ROOT / "scripts/qa-harness.py"
)
assert SPEC and SPEC.loader
qa_harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qa_harness)


def arguments(root: Path, **overrides):
    values = {
        "profile": "development",
        "evidence_root": root,
        "resume": None,
        "candidate_ref": None,
        "authorization": "synthetic harness regression",
        "allow_dirty": True,
        "verify": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class QaHarnessTests(unittest.TestCase):
    def setUp(self):
        def isolated_git(_root, *arguments):
            if arguments == ("rev-parse", "HEAD"):
                return "a" * 40
            if arguments == ("rev-parse", "HEAD^{tree}"):
                return "b" * 40
            if arguments == ("remote", "get-url", "origin"):
                return "https://github.com/LizardPope1101/osint-forge.git"
            if arguments == ("branch", "--show-current"):
                return "synthetic-test"
            if arguments == ("rev-parse", "--show-toplevel"):
                return str(ROOT)
            if arguments == ("rev-parse", "HEAD^{commit}"):
                return "a" * 40
            if arguments == ("rev-parse", "origin/main^{commit}"):
                return "a" * 40
            if arguments == ("status", "--porcelain=v1", "--untracked-files=all"):
                return ""
            raise AssertionError(f"Unexpected Git call: {arguments!r}")

        patcher = mock.patch.object(qa_harness, "git", side_effect=isolated_git)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_passed_run_can_resume_only_with_untampered_evidence(self):
        plan = [
            qa_harness.command_step(
                "synthetic-pass",
                ["python3", "-c", "print('synthetic pass')"],
                required="python3",
            )
        ]
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            qa_harness, "build_plan", return_value=plan
        ):
            evidence = Path(temporary)
            first = qa_harness.Harness(arguments(evidence))
            first.initialize()
            try:
                self.assertEqual(first.run(), 0)
                run_dir = first.run_dir
            finally:
                first.release_lock()

            resumed = qa_harness.Harness(
                arguments(evidence, resume=run_dir)
            )
            resumed.initialize()
            try:
                self.assertEqual(resumed.run(), 0)
            finally:
                resumed.release_lock()

            log = next((run_dir / "logs").glob("*.log"))
            log.write_text("tampered\n", encoding="utf-8")
            rejected = qa_harness.Harness(
                arguments(evidence, resume=run_dir)
            )
            with self.assertRaisesRegex(
                qa_harness.HarnessError, "evidence changed"
            ):
                rejected.initialize()

    def test_release_resume_reuses_recorded_candidate_ref(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(qa_harness, "build_plan", return_value=[]), \
             mock.patch.object(qa_harness.Harness, "validate_remote_candidate"):
            evidence = Path(temporary)
            first = qa_harness.Harness(arguments(
                evidence,
                profile="release",
                candidate_ref="origin/main",
                allow_dirty=False,
            ))
            first.initialize()
            run_dir = first.run_dir
            first.release_lock()

            resumed = qa_harness.Harness(arguments(
                evidence,
                profile="release",
                resume=run_dir,
                allow_dirty=False,
            ))
            resumed.initialize()
            try:
                self.assertEqual(resumed.args.candidate_ref, "origin/main")
            finally:
                resumed.release_lock()

    def test_failed_step_records_exit_code_and_is_resumable(self):
        failing = [
            qa_harness.command_step(
                "synthetic-failure",
                ["python3", "-c", "raise SystemExit(7)"],
                required="python3",
            )
        ]
        passing = [
            qa_harness.command_step(
                "synthetic-failure",
                ["python3", "-c", "print('recovered')"],
                required="python3",
            )
        ]
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            qa_harness, "build_plan", return_value=failing
        ):
            evidence = Path(temporary)
            first = qa_harness.Harness(arguments(evidence))
            first.initialize()
            try:
                self.assertEqual(first.run(), 1)
                run_dir = first.run_dir
                self.assertEqual(first.state["status"], "failed")
                self.assertEqual(
                    first.state["steps"]["synthetic-failure"]["exit_code"], 7
                )
            finally:
                first.release_lock()

            # A changed plan is deliberately not resumable, even if it would pass.
            with mock.patch.object(qa_harness, "build_plan", return_value=passing):
                rejected = qa_harness.Harness(
                    arguments(evidence, resume=run_dir)
                )
                with self.assertRaisesRegex(qa_harness.HarnessError, "plan_hash"):
                    rejected.initialize()

    def test_manifest_verifier_detects_changed_and_unmanifested_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            evidence = run_dir / "state.json"
            evidence.write_text("{}\n", encoding="utf-8")
            digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
            (run_dir / "MANIFEST.sha256").write_text(
                f"{digest}  state.json\n", encoding="utf-8"
            )
            self.assertEqual(qa_harness.verify_evidence(run_dir), 0)

            evidence.write_text('{"changed": true}\n', encoding="utf-8")
            with mock.patch("sys.stderr", new=io.StringIO()):
                self.assertEqual(qa_harness.verify_evidence(run_dir), 1)

            evidence.write_text("{}\n", encoding="utf-8")
            (run_dir / "extra.log").write_text("untracked evidence\n", encoding="utf-8")
            with mock.patch("sys.stderr", new=io.StringIO()):
                self.assertEqual(qa_harness.verify_evidence(run_dir), 1)

    def test_status_reports_current_step(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            qa_harness.atomic_json(
                run_dir / "state.json",
                {
                    "run_id": "synthetic-run",
                    "status": "running",
                    "profile": "release",
                    "commit": "a" * 40,
                    "current_step": "unit-integration-tests",
                    "steps": {
                        "python-compile": {"status": "passed"},
                        "unit-integration-tests": {"status": "running"},
                    },
                    "started_at": "2026-07-30T00:00:00+00:00",
                    "completed_at": None,
                    "failure": None,
                },
            )
            output = io.StringIO()
            with mock.patch("sys.stdout", new=output):
                self.assertEqual(qa_harness.show_status(run_dir), 0)
            rendered = output.getvalue()
            self.assertIn("Status:       running", rendered)
            self.assertIn("Current step: unit-integration-tests", rendered)
            self.assertIn("passed=1", rendered)
            self.assertIn("running=1", rendered)

    def test_release_profile_never_allows_dirty_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            harness = qa_harness.Harness(
                arguments(
                    Path(temporary),
                    profile="release",
                    allow_dirty=True,
                    candidate_ref="HEAD",
                )
            )
            with self.assertRaisesRegex(
                qa_harness.HarnessError, "forbidden for the release profile"
            ):
                harness.validate_candidate()

    def test_evidence_path_rejects_symbolic_link_component(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual = root / "actual"
            actual.mkdir()
            linked = root / "linked"
            linked.symlink_to(actual, target_is_directory=True)
            harness = qa_harness.Harness(arguments(linked))
            with self.assertRaisesRegex(
                qa_harness.HarnessError, "symbolic-link QA evidence path"
            ):
                harness.initialize()

    def test_git_zip_extraction_preserves_executable_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "source.zip"
            destination = root / "extracted"
            destination.mkdir()
            member = zipfile.ZipInfo("bin/osint")
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o755) << 16
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(member, "#!/bin/sh\n")

            qa_harness.Harness.unpack_git_zip(archive, destination)

            extracted = destination / "bin" / "osint"
            self.assertEqual(stat.S_IMODE(extracted.stat().st_mode), 0o755)

    def test_git_zip_extraction_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "source.zip"
            destination = root / "extracted"
            destination.mkdir()
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("../escaped", "unsafe\n")

            with self.assertRaisesRegex(
                qa_harness.HarnessError, "escapes extraction root"
            ):
                qa_harness.Harness.unpack_git_zip(archive, destination)
            self.assertFalse((root / "escaped").exists())


if __name__ == "__main__":
    unittest.main()
