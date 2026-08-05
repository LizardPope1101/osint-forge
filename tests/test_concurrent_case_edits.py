# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import concurrent.futures
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from forge import osint_forge


class ConcurrentCaseEditTests(unittest.TestCase):
    def test_case_lock_serializes_overlapping_editors(self):
        with tempfile.TemporaryDirectory() as temporary:
            case = Path(temporary)
            first_has_lock = threading.Event()
            release_first = threading.Event()
            second_has_lock = threading.Event()

            def first_editor():
                with osint_forge.case_lock(case):
                    first_has_lock.set()
                    self.assertTrue(release_first.wait(timeout=5))

            def second_editor():
                self.assertTrue(first_has_lock.wait(timeout=5))
                with osint_forge.case_lock(case):
                    second_has_lock.set()

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(first_editor)
                second = pool.submit(second_editor)
                self.assertTrue(first_has_lock.wait(timeout=5))
                self.assertFalse(second_has_lock.wait(timeout=0.1))
                release_first.set()
                first.result(timeout=5)
                second.result(timeout=5)

            self.assertTrue(second_has_lock.is_set())

    def test_concurrent_target_additions_preserve_every_update(self):
        worker_count = 16
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.dict(
                os.environ,
                {"OSINT_FORGE_CASES": temporary},
                clear=False,
            ):
                osint_forge.cmd_case_create(argparse.Namespace(
                    case="concurrent-edit",
                    purpose="Concurrent edit regression fixture",
                    authorization="Controlled local test data",
                ))
                barrier = threading.Barrier(worker_count)

                def add_target(index):
                    barrier.wait(timeout=5)
                    return osint_forge.cmd_case_add(argparse.Namespace(
                        case="concurrent-edit",
                        type="username",
                        target=f"fixture-user-{index:02d}",
                    ))

                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=worker_count
                ) as pool:
                    results = list(pool.map(add_target, range(worker_count)))

                _, metadata = osint_forge.load_case("concurrent-edit")
                self.assertEqual(results, [0] * worker_count)
                self.assertEqual(len(metadata["targets"]), worker_count)
                self.assertEqual(
                    {target["value"] for target in metadata["targets"]},
                    {f"fixture-user-{index:02d}" for index in range(worker_count)},
                )
                self.assertTrue(all(
                    target["id"] == osint_forge.target_id(
                        target["type"], target["value"]
                    )
                    for target in metadata["targets"]
                ))


if __name__ == "__main__":
    unittest.main()
