import json
import tempfile
import unittest
from pathlib import Path

import osint_forge


class CoreTests(unittest.TestCase):
    def test_manifests_load_and_ids_match(self):
        plugins = osint_forge.load_plugins()
        self.assertEqual(
            set(plugins),
            {"exiftool", "ghunt", "maigret", "nmap", "recon-ng", "sherlock", "spiderfoot"},
        )

    def test_expand_preserves_argument_boundaries(self):
        result = osint_forge.expand(
            ["tool", "--out", "{output_dir}", "{target}"],
            {"output_dir": "/tmp/a b", "target": "name;echo nope"},
        )
        self.assertEqual(result, ["tool", "--out", "/tmp/a b", "name;echo nope"])

    def test_target_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "targets.ini"
            path.write_text("[usernames]\nalice\nbob\n", encoding="utf-8")
            self.assertEqual(osint_forge.read_targets(path), {"usernames": ["alice", "bob"]})

    def test_manifests_are_json(self):
        for path in osint_forge.PLUGIN_ROOT.glob("*/manifest.json"):
            json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

