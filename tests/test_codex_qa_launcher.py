# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "codex-qa.sh"
COMMIT = "a" * 40


class CodexQaLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.base = Path(self.temp_dir.name)
        self.home = self.base / "home"
        self.bin_dir = self.base / "bin"
        self.home.mkdir(mode=0o700)
        self.bin_dir.mkdir(mode=0o700)
        self._write_stubs()

    def _write(self, name, content):
        path = self.bin_dir / name
        path.write_text(textwrap.dedent(content), encoding="utf-8")
        path.chmod(0o700)

    def _write_stubs(self):
        self._write(
            "git",
            f"""\
            #!/usr/bin/env bash
            case "$*" in
              "rev-parse --is-inside-work-tree") echo true ;;
              "status --porcelain=v1") printf '%s' "${{MOCK_DIRTY:-}}" ;;
              "rev-parse HEAD") echo "${{MOCK_COMMIT:-{COMMIT}}}" ;;
              "branch --show-current") echo "${{MOCK_BRANCH:-main}}" ;;
              "fetch --quiet origin main") ;;
              "rev-parse refs/remotes/origin/main")
                echo "${{MOCK_REMOTE_MAIN:-{COMMIT}}}"
                ;;
              *) echo "unexpected git invocation: $*" >&2; exit 91 ;;
            esac
            """,
        )
        self._write(
            "tmux",
            """\
            #!/usr/bin/env bash
            case "${1:-}" in
              has-session) exit 1 ;;
              new-session) printf '%s\n' "$*" >"${MOCK_TMUX_LOG:?}" ;;
              *) exit 0 ;;
            esac
            """,
        )
        self._write(
            "codex",
            """\
            #!/usr/bin/env bash
            [[ "${1:-}" == "login" && "${2:-}" == "status" ]] && exit 0
            exit 92
            """,
        )
        self._write("gh", "#!/usr/bin/env bash\nexit 0\n")
        self._write("sudo", "#!/usr/bin/env bash\nexit 0\n")
        self._write("osint", "#!/usr/bin/env bash\necho 'OSINT Forge 0.5.0'\n")

    def _environment(self, **updates):
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(self.home),
                "PATH": f"{self.bin_dir}:{environment['PATH']}",
                "MOCK_TMUX_LOG": str(self.base / "tmux.log"),
                "OSINT_FORGE_CODEX_QA_SESSION": "launcher-test",
                "OSINT_FORGE_CODEX_QA_TEST_OS_ID": "debian",
            }
        )
        environment.update(updates)
        return environment

    def _run(self, *arguments, **environment):
        return subprocess.run(
            [str(LAUNCHER), *arguments],
            cwd=ROOT,
            env=self._environment(**environment),
            text=True,
            capture_output=True,
            check=False,
        )

    def _only_run(self):
        sessions = self.home / "OSINT-Forge-QA" / "codex-sessions"
        runs = list(sessions.iterdir())
        self.assertEqual(len(runs), 1)
        return runs[0]

    def test_help_does_not_require_runtime_dependencies(self):
        result = subprocess.run(
            [str(LAUNCHER), "--help"],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "HOME": str(self.home)},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("release", result.stdout)
        self.assertIn("status", result.stdout)

    def test_development_launch_builds_private_persistent_run(self):
        result = self._run("development")
        self.assertEqual(result.returncode, 0, result.stderr)
        run_dir = self._only_run()

        self.assertEqual(stat.S_IMODE(run_dir.stat().st_mode), 0o700)
        for filename in ("metadata.txt", "prompt.md"):
            self.assertEqual(
                stat.S_IMODE((run_dir / filename).stat().st_mode),
                0o600,
            )
        self.assertEqual(stat.S_IMODE((run_dir / "run.sh").stat().st_mode), 0o700)

        runner = (run_dir / "run.sh").read_text(encoding="utf-8")
        prompt = (run_dir / "prompt.md").read_text(encoding="utf-8")
        self.assertIn("--ask-for-approval never exec", runner)
        self.assertIn("--sandbox workspace-write", runner)
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", runner)
        self.assertIn("--json", runner)
        self.assertIn("Testing and corrective patching are authorized", prompt)
        self.assertIn("publication is not part", prompt)
        self.assertIn("Source version: OSINT Forge 0.8.1", prompt)
        self.assertIn("Installed version: OSINT Forge 0.5.0", prompt)
        self.assertTrue((self.base / "tmux.log").is_file())

    def test_release_launch_is_exact_main_and_uses_dedicated_vm_boundary(self):
        result = self._run("release")
        self.assertEqual(result.returncode, 0, result.stderr)
        run_dir = self._only_run()
        runner = (run_dir / "run.sh").read_text(encoding="utf-8")
        prompt = (run_dir / "prompt.md").read_text(encoding="utf-8")

        self.assertIn("--dangerously-bypass-approvals-and-sandbox", runner)
        self.assertNotIn("--sandbox workspace-write", runner)
        self.assertIn("release QA", prompt)
        self.assertIn("use origin/main as the candidate ref", prompt)
        self.assertIn(COMMIT, prompt)

    def test_release_rejects_wrong_branch_before_creating_evidence(self):
        result = self._run("release", MOCK_BRANCH="feature/test")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must start from branch main", result.stderr)
        self.assertFalse((self.home / "OSINT-Forge-QA").exists())

    def test_release_rejects_stale_main_before_creating_evidence(self):
        result = self._run("release", MOCK_REMOTE_MAIN="b" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match origin/main", result.stderr)
        self.assertFalse((self.home / "OSINT-Forge-QA").exists())

    def test_dirty_tree_is_rejected_before_creating_evidence(self):
        result = self._run("development", MOCK_DIRTY=" M README.md")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("worktree is not clean", result.stderr)
        self.assertFalse((self.home / "OSINT-Forge-QA").exists())

    def test_symbolic_link_evidence_root_is_rejected(self):
        private_root = self.base / "private"
        private_root.mkdir(mode=0o700)
        linked_root = self.base / "linked"
        linked_root.symlink_to(private_root, target_is_directory=True)
        result = self._run(
            "development",
            OSINT_FORGE_QA_ROOT=str(linked_root),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symbolic link", result.stderr)
        self.assertEqual(list(private_root.iterdir()), [])

    def test_status_reads_latest_progress_without_starting_codex(self):
        result = self._run("development")
        self.assertEqual(result.returncode, 0, result.stderr)
        run_dir = self._only_run()
        (run_dir / "events.jsonl").write_text(
            '{"type":"item.completed","item":{"type":"agent_message",'
            '"text":"Running archive validation"}}\n',
            encoding="utf-8",
        )
        (run_dir / "events.jsonl").chmod(0o600)
        (run_dir / "exit-code").write_text("0\n", encoding="utf-8")
        (run_dir / "exit-code").chmod(0o600)

        status_result = self._run("status")
        self.assertEqual(status_result.returncode, 0, status_result.stderr)
        self.assertIn("Running archive validation", status_result.stdout)
        self.assertIn("Exit code:      0", status_result.stdout)


if __name__ == "__main__":
    unittest.main()
