# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from forge import integrity, osint_forge


class IntegrityTests(unittest.TestCase):
    def make_case(self, root: Path, case_id: str = "portable-case") -> Path:
        with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
            self.assertEqual(osint_forge.cmd_case_create(argparse.Namespace(
                case=case_id, purpose="Synthetic portability test",
                authorization="Owned fixtures only",
            )), 0)
            self.assertEqual(osint_forge.cmd_case_add(argparse.Namespace(
                case=case_id, type="email", target="analyst@example.com",
            )), 0)
        return root / case_id

    def test_manifest_detects_modified_missing_and_unexpected_files(self):
        with tempfile.TemporaryDirectory() as temp:
            case = self.make_case(Path(temp) / "cases")
            manifest = integrity.build_manifest(
                case, case_id="portable-case", framework_version="test"
            )
            self.assertTrue(integrity.verify_manifest(case, manifest)["valid"])
            (case / "case.json").write_text("modified", encoding="utf-8")
            (case / "activity.jsonl").unlink()
            (case / "unexpected.txt").write_text("new", encoding="utf-8")
            result = integrity.verify_manifest(case, manifest)
            self.assertFalse(result["valid"])
            self.assertEqual(result["modified"], ["case.json"])
            self.assertEqual(result["missing"], ["activity.jsonl"])
            self.assertEqual(result["unexpected"], ["unexpected.txt"])

    def test_full_bundle_is_deterministic_and_round_trips(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source_root = base / "source"
            case = self.make_case(source_root)
            one = base / "one.osint-case"
            two = base / "two.osint-case"
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(source_root)}):
                for output in (one, two):
                    self.assertEqual(osint_forge.cmd_case_export(argparse.Namespace(
                        case="portable-case", mode="full", output=output, force=False,
                    )), 0)
            self.assertEqual(hashlib.sha256(one.read_bytes()).digest(), hashlib.sha256(two.read_bytes()).digest())
            imported_root = base / "imported"
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(imported_root)}):
                self.assertEqual(osint_forge.cmd_case_import(argparse.Namespace(
                    bundle=one, case="portable-case",
                )), 0)
            imported = imported_root / "portable-case"
            for path in integrity._case_files(case):
                relative = path.relative_to(case)
                self.assertEqual(path.read_bytes(), (imported / relative).read_bytes())
            manifest = json.loads((imported / integrity.MANIFEST_NAME).read_text())
            self.assertTrue(integrity.verify_manifest(imported, manifest)["valid"])

    def test_redacted_bundle_excludes_targets_raw_evidence_and_notes(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "cases"
            case = self.make_case(root)
            (case / "notes" / "secret.txt").write_text("private-note", encoding="utf-8")
            (case / "runs" / "raw-secret.txt").write_text("raw-secret", encoding="utf-8")
            output = base / "share.osint-case"
            with mock.patch.dict(os.environ, {"OSINT_FORGE_CASES": str(root)}):
                self.assertEqual(osint_forge.cmd_case_export(argparse.Namespace(
                    case="portable-case", mode="redacted", output=output, force=False,
                )), 0)
            manifest, members = integrity.inspect_bundle(output)
            joined = b"\n".join(members.values())
            self.assertEqual(manifest["mode"], "redacted")
            self.assertNotIn(b"analyst@example.com", joined)
            self.assertNotIn(b"portable-case", joined)
            self.assertNotIn(b"private-note", joined)
            self.assertNotIn(b"raw-secret", joined)
            self.assertFalse(any(name.startswith("runs/") for name in members))

    def test_bundle_rejects_traversal_links_and_corruption(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for label, configure in (
                ("traversal", lambda info: setattr(info, "filename", "../escape")),
                ("symlink", lambda info: setattr(info, "external_attr", (0o120777 << 16))),
            ):
                bundle = root / f"{label}.zip"
                info = zipfile.ZipInfo("artifact")
                configure(info)
                with zipfile.ZipFile(bundle, "w") as archive:
                    archive.writestr(info, b"bad")
                with self.assertRaises(integrity.IntegrityError):
                    integrity.inspect_bundle(bundle)

            members = {"case.json": b"{}"}
            manifest = integrity.bundle_manifest("case", "test", "full", members)
            bundle = root / "corrupt.zip"
            integrity.write_bundle(bundle, manifest, members)
            data = bytearray(bundle.read_bytes())
            data[-10] ^= 1
            bundle.write_bytes(data)
            with self.assertRaises(integrity.IntegrityError):
                integrity.inspect_bundle(bundle)

            stderr = io.StringIO()
            with mock.patch("sys.argv", ["osint", "case", "inspect", str(bundle)]), \
                 contextlib.redirect_stderr(stderr):
                self.assertEqual(osint_forge.main(), 2)
            self.assertIn("ERROR: invalid bundle:", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_case_manifest_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "file").write_text("evidence", encoding="utf-8")
            (root / "link").symlink_to(root / "file")
            with self.assertRaisesRegex(integrity.IntegrityError, "symbolic link"):
                integrity.build_manifest(root, case_id="case", framework_version="test")


if __name__ == "__main__":
    unittest.main()
