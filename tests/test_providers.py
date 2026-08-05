# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from forge import osint_forge, providers


class ProviderAdapterTests(unittest.TestCase):
    def adapter(self, script: Path) -> dict:
        return {
            "schema": 1,
            "id": "fixture-search",
            "name": "Synthetic fixture search",
            "provider_version": "1",
            "accepts": ["email"],
            "command": [
                sys.executable, str(script), "{query_type}", "{query_value}",
                "{output_dir}",
            ],
            "timeout_seconds": 10,
        }

    def test_contract_is_strict_versioned_and_argv_based(self):
        valid = self.adapter(Path("fixture.py"))
        self.assertEqual(providers.validate_adapter(valid)["schema"], 1)
        future = dict(valid, schema=2)
        with self.assertRaisesRegex(providers.ProviderError, "newer"):
            providers.validate_adapter(future)
        shell = dict(valid, command="fixture {query_value}")
        with self.assertRaisesRegex(providers.ProviderError, "argv"):
            providers.validate_adapter(shell)
        missing = dict(valid, command=["fixture", "{query_value}"])
        with self.assertRaisesRegex(providers.ProviderError, "placeholders"):
            providers.validate_adapter(missing)
        reserved = dict(valid, environment=["HOME"])
        with self.assertRaisesRegex(providers.ProviderError, "environment"):
            providers.validate_adapter(reserved)

    def test_case_search_executes_provider_and_preserves_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cases = root / "cases"
            adapter_root = root / "adapter"
            adapter_root.mkdir()
            script = adapter_root / "fixture.py"
            script.write_text(
                "import hashlib,json,os,pathlib,sys\n"
                "assert 'AMBIENT_SECRET' not in os.environ\n"
                "kind,value,out=sys.argv[1:]\n"
                "root=pathlib.Path(out); (root/'evidence.txt').write_text('synthetic\\n')\n"
                "entity={'type':kind,'value':value}\n"
                "account={'type':'username','value':'fixture_user'}\n"
                "result={'schema':1,'provider':'fixture-search','query':entity,'results':["
                "{'url':'https://search.example.test/result','title':'Fixture','snippet':'Synthetic',"
                "'source_file':'evidence.txt','observed_at':'2026-08-04T12:00:00+00:00',"
                "'entities':[entity,account],'relationships':[{'source':entity,'target':account,'type':'uses_account'}],"
                "'source_identity':{'canonical_url':'https://search.example.test/result','content_fingerprint':hashlib.sha256(b'synthetic\\n').hexdigest()}}]}\n"
                "(root/'provider.json').write_text(json.dumps(result))\n",
                encoding="utf-8",
            )
            adapter_path = adapter_root / "adapter.json"
            adapter_path.write_text(json.dumps(self.adapter(script)), encoding="utf-8")
            with mock.patch.dict(os.environ, {
                "OSINT_FORGE_CASES": str(cases), "AMBIENT_SECRET": "must-not-leak"
            }):
                osint_forge.cmd_case_create(argparse.Namespace(
                    case="case", purpose="Synthetic", authorization="Owned fixture"
                ))
                osint_forge.cmd_case_add(argparse.Namespace(
                    case="case", type="email", target="analyst@example.com"
                ))
                rc = osint_forge.cmd_case_search(argparse.Namespace(
                    case="case", adapter=adapter_path, target=None
                ))
                self.assertEqual(rc, 0)
                case_path, metadata = osint_forge.load_case("case")
                graph = osint_forge.build_case_intelligence(case_path, metadata)
                self.assertEqual(len(graph["observations"]), 1)
                execution = next((case_path / "observations").glob("provider-*/execution.json"))
                record = json.loads(execution.read_text(encoding="utf-8"))
                self.assertEqual(record["exit_code"], 0)
                self.assertEqual(record["provider_version"], "1")
                self.assertEqual(record["adapter"], providers.validate_adapter(self.adapter(script)))
                self.assertEqual(len(record["adapter_sha256"]), 64)
                self.assertEqual(execution.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
