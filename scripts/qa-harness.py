#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 LizardPope1101
# SPDX-License-Identifier: GPL-3.0-or-later
"""Resumable, tamper-evident OSINT Forge QA harness."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable
import zipfile


SCHEMA = 1
HARNESS_VERSION = 1
PROFILES = ("development", "release")
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bgh[opusr]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
)
PROHIBITED_TRACKED_PARTS = {
    "OSINT-Cases",
    "OSINT-Forge-QA",
    "__pycache__",
}
EXPECTED_HOSTED_CHECKS = {
    "Python 3.10 and plugin contracts",
    "Python 3.11 and plugin contracts",
    "Python 3.12 and plugin contracts",
    "Python 3.13 and plugin contracts",
    "Shell quality",
    "Clean install (Debian stable)",
    "Clean install (Ubuntu 24.04)",
    "Analyze (actions)",
    "Analyze (python)",
}


class HarnessError(RuntimeError):
    """A fail-closed harness error."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIRECTORY_MODE)
    path.parent.chmod(PRIVATE_DIRECTORY_MODE)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        PRIVATE_FILE_MODE,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        path.chmod(PRIVATE_FILE_MODE)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT,
        PRIVATE_FILE_MODE,
    )
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(PRIVATE_FILE_MODE)


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(path.expanduser()))


def reject_symlink_components(path: Path, context: str) -> None:
    absolute = lexical_absolute(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise HarnessError(f"Refusing symbolic-link {context}: {current}")


def tracked_files(root: Path) -> list[Path]:
    output = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return [root / item.decode("utf-8") for item in output.split(b"\0") if item]


def command_step(name: str, command: list[str], *, required: str | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "kind": "command",
        "command": command,
        "required": required,
    }


def internal_step(name: str, function: str) -> dict[str, Any]:
    return {"name": name, "kind": "internal", "function": function}


def shell_files(root: Path) -> list[str]:
    paths = [root / "bootstrap.sh", root / "bin/osint"]
    for pattern in ("scripts/*.sh", "plugins/*/*.sh", "docs/plugin-template/*.sh"):
        paths.extend(sorted(root.glob(pattern)))
    return [str(path.relative_to(root)) for path in paths]


def build_plan(root: Path, profile: str) -> list[dict[str, Any]]:
    shells = shell_files(root)
    plan = [
        command_step(
            "python-compile",
            ["python3", "-m", "py_compile", "forge/osint_forge.py", "forge/entities.py", "forge/reporting.py"],
            required="python3",
        ),
        command_step(
            "unit-integration-tests",
            ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"],
            required="python3",
        ),
        command_step("plugin-contracts", ["./bin/osint", "forge", "validate"]),
        command_step("cli-smoke-version", ["./bin/osint", "--version"]),
        command_step("cli-smoke-list", ["./bin/osint", "forge", "list"]),
        command_step("cli-smoke-categories", ["./bin/osint", "forge", "categories"]),
        command_step("shell-syntax", ["bash", "-n", *shells], required="bash"),
        command_step(
            "shellcheck",
            ["shellcheck", "-e", "SC1090,SC2034", *shells],
            required="shellcheck" if profile == "release" else None,
        ),
        command_step("git-diff-check", ["git", "diff", "--check", "HEAD"], required="git"),
        internal_step("executable-modes", "check_executable_modes"),
        internal_step("repository-hygiene", "check_repository_hygiene"),
        internal_step("markdown-links", "check_markdown_links"),
        internal_step("credential-patterns", "check_credential_patterns"),
        internal_step("version-consistency", "check_version_consistency"),
        internal_step("plugin-lifecycle-dry-runs", "check_lifecycle_dry_runs"),
    ]
    if profile == "release":
        plan.append(internal_step("exact-commit-hosted-checks", "check_hosted_checks"))
        plan.append(internal_step("source-archive-parity", "check_source_archives"))
    return plan


def plan_hash(plan: list[dict[str, Any]]) -> str:
    encoded = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class Harness:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root = Path(__file__).resolve().parents[1]
        self.profile = args.profile
        self.plan = build_plan(self.root, self.profile)
        self.commit = git(self.root, "rev-parse", "HEAD")
        self.tree = git(self.root, "rev-parse", "HEAD^{tree}")
        self.version = self.read_version()
        self.run_dir = self.resolve_run_directory()
        self.state_path = self.run_dir / "state.json"
        self.events_path = self.run_dir / "events.jsonl"
        self.logs_dir = self.run_dir / "logs"
        self.lock_path = self.run_dir / ".lock"
        self.state: dict[str, Any] = {}
        self.child: subprocess.Popen[bytes] | None = None

    def read_version(self) -> str:
        match = re.search(
            r'^__version__\s*=\s*"([^"]+)"',
            (self.root / "forge/osint_forge.py").read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        if not match:
            raise HarnessError("Could not read framework version")
        return match.group(1)

    def resolve_run_directory(self) -> Path:
        if self.args.resume:
            return lexical_absolute(self.args.resume)
        base = lexical_absolute(self.args.evidence_root)
        return base / "runs" / f"{utc_stamp()}-{self.commit[:12]}"

    def initialize(self) -> None:
        os.umask(0o077)
        reject_symlink_components(self.run_dir, "QA evidence path")
        if self.root.resolve() in (self.run_dir, *self.run_dir.parents):
            raise HarnessError("QA evidence must be stored outside the source repository")
        if self.args.resume:
            if not self.state_path.is_file():
                raise HarnessError(f"Resume state does not exist: {self.state_path}")
            self.state = json.loads(self.state_path.read_text(encoding="utf-8"))
            self.validate_resume()
        else:
            self.run_dir.mkdir(parents=True, mode=PRIVATE_DIRECTORY_MODE)
            self.logs_dir.mkdir(mode=PRIVATE_DIRECTORY_MODE)
            if self.state_path.exists():
                raise HarnessError(f"Run already exists: {self.run_dir}")
            self.state = {
                "schema": SCHEMA,
                "harness_version": HARNESS_VERSION,
                "run_id": self.run_dir.name,
                "status": "created",
                "profile": self.profile,
                "repository": git(self.root, "remote", "get-url", "origin"),
                "root": str(self.root),
                "commit": self.commit,
                "tree": self.tree,
                "branch": git(self.root, "branch", "--show-current"),
                "framework_version": self.version,
                "candidate_ref": self.args.candidate_ref,
                "authorization": self.args.authorization,
                "host": socket.gethostname(),
                "platform": sys.platform,
                "python": sys.version.split()[0],
                "created_at": utc_now(),
                "started_at": None,
                "completed_at": None,
                "plan_hash": plan_hash(self.plan),
                "steps": {},
                "current_step": None,
                "failure": None,
            }
            self.write_state()
        self.acquire_lock()
        self.validate_candidate()
        self.enforce_private_modes()

    def validate_resume(self) -> None:
        expected = {
            "schema": SCHEMA,
            "harness_version": HARNESS_VERSION,
            "profile": self.profile,
            "commit": self.commit,
            "tree": self.tree,
            "framework_version": self.version,
            "plan_hash": plan_hash(self.plan),
        }
        for key, value in expected.items():
            if self.state.get(key) != value:
                raise HarnessError(
                    f"Resume mismatch for {key}: expected {value!r}, "
                    f"recorded {self.state.get(key)!r}"
                )
        recorded_candidate = self.state.get("candidate_ref")
        if self.args.candidate_ref and self.args.candidate_ref != recorded_candidate:
            raise HarnessError(
                "Resume mismatch for candidate_ref: "
                f"requested {self.args.candidate_ref!r}, recorded {recorded_candidate!r}"
            )
        if not self.args.candidate_ref:
            self.args.candidate_ref = recorded_candidate
        for name, result in self.state.get("steps", {}).items():
            if result.get("status") != "passed":
                continue
            log = self.run_dir / result["log"]
            if not log.is_file() or sha256(log) != result.get("log_sha256"):
                raise HarnessError(f"Completed-step evidence changed or is missing: {name}")

    def validate_candidate(self) -> None:
        top = Path(git(self.root, "rev-parse", "--show-toplevel")).resolve()
        if top != self.root.resolve():
            raise HarnessError(f"Harness root mismatch: {top} != {self.root.resolve()}")
        if self.args.candidate_ref:
            resolved = git(self.root, "rev-parse", f"{self.args.candidate_ref}^{{commit}}")
            if resolved != self.commit:
                raise HarnessError(
                    f"Candidate ref {self.args.candidate_ref!r} resolves to {resolved}, "
                    f"not checked-out HEAD {self.commit}"
                )
            self.validate_remote_candidate()
        elif self.profile == "release":
            raise HarnessError("--candidate-ref is required for the release profile")
        dirty = git(self.root, "status", "--porcelain=v1", "--untracked-files=all")
        if dirty and not self.args.allow_dirty:
            raise HarnessError("Working tree is not clean; refusing non-reproducible QA run")
        if self.profile == "release" and self.args.allow_dirty:
            raise HarnessError("--allow-dirty is forbidden for the release profile")
        for step in self.plan:
            required = step.get("required")
            if required and shutil.which(required) is None:
                raise HarnessError(f"Required command is unavailable: {required}")

    def validate_remote_candidate(self) -> None:
        assert self.args.candidate_ref
        if not self.args.candidate_ref.startswith("origin/"):
            return
        branch = self.args.candidate_ref.removeprefix("origin/")
        result = subprocess.run(
            ["git", "-C", str(self.root), "ls-remote", "origin", f"refs/heads/{branch}"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        records = result.stdout.splitlines()
        if len(records) != 1:
            raise HarnessError(
                f"Could not resolve exact remote branch for {self.args.candidate_ref}"
            )
        remote_commit = records[0].split()[0]
        if remote_commit != self.commit:
            raise HarnessError(
                f"Remote {self.args.candidate_ref} is {remote_commit}, "
                f"not checked-out HEAD {self.commit}"
            )

    def acquire_lock(self) -> None:
        if self.lock_path.exists():
            try:
                lock = json.loads(self.lock_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise HarnessError(f"Unreadable QA lock: {self.lock_path}") from error
            if lock.get("host") == socket.gethostname():
                try:
                    os.kill(int(lock["pid"]), 0)
                except (ProcessLookupError, ValueError, KeyError):
                    self.lock_path.unlink()
                except PermissionError as error:
                    raise HarnessError(f"Cannot verify existing QA lock: {lock}") from error
                else:
                    raise HarnessError(f"QA run is already active: {lock}")
            else:
                raise HarnessError(f"QA lock belongs to another host: {lock}")
        descriptor = os.open(
            self.lock_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            PRIVATE_FILE_MODE,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(
                {"pid": os.getpid(), "host": socket.gethostname(), "created_at": utc_now()},
                handle,
                sort_keys=True,
            )
            handle.write("\n")

    def release_lock(self) -> None:
        self.lock_path.unlink(missing_ok=True)

    def write_state(self) -> None:
        atomic_json(self.state_path, self.state)

    def event(self, event: str, **details: Any) -> None:
        append_jsonl(self.events_path, {"time": utc_now(), "event": event, **details})

    def enforce_private_modes(self) -> None:
        for path in [self.run_dir, *self.run_dir.rglob("*")]:
            if path == self.lock_path and not path.exists():
                continue
            if path.is_symlink():
                raise HarnessError(f"QA evidence contains a symbolic link: {path}")
            path.chmod(PRIVATE_DIRECTORY_MODE if path.is_dir() else PRIVATE_FILE_MODE)

    def run(self) -> int:
        previous_handlers = {
            signum: signal.getsignal(signum)
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        }

        def interrupt(_signum: int, _frame: Any) -> None:
            raise KeyboardInterrupt

        for signum in previous_handlers:
            signal.signal(signum, interrupt)
        try:
            self.state["status"] = "running"
            self.state["started_at"] = self.state.get("started_at") or utc_now()
            self.state["completed_at"] = None
            self.state["failure"] = None
            self.write_state()
            self.event("run_started", profile=self.profile, commit=self.commit)
            print(f"QA run: {self.run_dir}", flush=True)
            print(f"Profile: {self.profile}", flush=True)
            print(f"Commit: {self.commit}", flush=True)
            try:
                for index, step in enumerate(self.plan, start=1):
                    previous = self.state["steps"].get(step["name"], {})
                    if previous.get("status") == "passed":
                        print(
                            f"SKIP {index:02d}/{len(self.plan):02d} "
                            f"{step['name']} (verified)",
                            flush=True,
                        )
                        continue
                    self.execute_step(index, step)
            except KeyboardInterrupt:
                self.mark_terminal("interrupted", "execution interrupted", exit_code=130)
                return 130
            except BaseException as error:
                self.mark_terminal("failed", str(error), exit_code=1)
                return 1
            self.state["status"] = "passed"
            self.state["current_step"] = None
            self.state["completed_at"] = utc_now()
            self.write_state()
            self.event("run_passed", commit=self.commit)
            self.write_manifest()
            self.enforce_private_modes()
            print(f"PASS: {self.profile} QA completed for {self.commit}", flush=True)
            print(f"Evidence: {self.run_dir}", flush=True)
            return 0
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)

    def mark_terminal(self, status: str, message: str, *, exit_code: int) -> None:
        self.state["status"] = status
        self.state["current_step"] = None
        self.state["completed_at"] = utc_now()
        self.state["failure"] = {"message": message, "exit_code": exit_code}
        self.write_state()
        self.event(f"run_{status}", message=message, exit_code=exit_code)
        self.write_manifest()
        self.enforce_private_modes()
        print(f"{status.upper()}: {message}", file=sys.stderr, flush=True)
        print(f"Resume with: {Path(__file__).relative_to(self.root)} "
              f"--profile {self.profile} --resume {shlex.quote(str(self.run_dir))}",
              file=sys.stderr, flush=True)

    def execute_step(self, index: int, step: dict[str, Any]) -> None:
        name = step["name"]
        log_path = self.logs_dir / f"{index:02d}-{name}.log"
        started = utc_now()
        result = {
            "status": "running",
            "started_at": started,
            "completed_at": None,
            "exit_code": None,
            "log": str(log_path.relative_to(self.run_dir)),
            "log_sha256": None,
        }
        self.state["steps"][name] = result
        self.state["current_step"] = name
        self.write_state()
        self.event("step_started", step=name, index=index)
        print(f"RUN  {index:02d}/{len(self.plan):02d} {name}", flush=True)
        with log_path.open("wb") as log:
            os.chmod(log_path, PRIVATE_FILE_MODE)
            heading = (
                f"step={name}\nstarted_at={started}\ncommit={self.commit}\n"
                f"profile={self.profile}\n"
            )
            if step["kind"] == "command":
                heading += "command=" + shlex.join(step["command"]) + "\n"
            log.write(heading.encode())
            log.flush()
            os.fsync(log.fileno())
            try:
                if step["kind"] == "command":
                    exit_code = self.run_command(step, log)
                else:
                    exit_code = self.run_internal(step, log)
            except KeyboardInterrupt:
                result.update(
                    status="interrupted",
                    completed_at=utc_now(),
                    exit_code=130,
                )
                log.write(b"\ninterrupted=true\n")
                log.flush()
                os.fsync(log.fileno())
                result["log_sha256"] = sha256(log_path)
                self.write_state()
                self.event("step_interrupted", step=name)
                raise
            except BaseException as error:
                exit_code = 1
                log.write(f"\ninternal_error={error!r}\n".encode())
            log.write(f"\ncompleted_at={utc_now()}\nexit_code={exit_code}\n".encode())
            log.flush()
            os.fsync(log.fileno())
        result.update(
            status="passed" if exit_code == 0 else "failed",
            completed_at=utc_now(),
            exit_code=exit_code,
            log_sha256=sha256(log_path),
        )
        self.state["current_step"] = None
        self.write_state()
        self.event(f"step_{result['status']}", step=name, exit_code=exit_code)
        if exit_code:
            raise HarnessError(f"Step failed ({exit_code}): {name}; see {log_path}")

    def run_command(self, step: dict[str, Any], log: Any) -> int:
        command = step["command"]
        if shutil.which(command[0]) is None and not step.get("required"):
            log.write(f"optional_command_unavailable={command[0]}\n".encode())
            return 0
        environment = os.environ.copy()
        environment["OSINT_FORGE_ROOT"] = str(self.root)
        self.child = subprocess.Popen(
            command,
            cwd=self.root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        assert self.child.stdout is not None
        try:
            for chunk in iter(lambda: self.child.stdout.read(8192), b""):
                log.write(chunk)
                log.flush()
            return self.child.wait()
        except KeyboardInterrupt:
            os.killpg(self.child.pid, signal.SIGTERM)
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.child.pid, signal.SIGKILL)
                self.child.wait()
            raise
        finally:
            if self.child.stdout is not None:
                self.child.stdout.close()
            self.child = None

    def run_internal(self, step: dict[str, Any], log: Any) -> int:
        function: Callable[[Any], None] = getattr(self, step["function"])
        try:
            function(log)
            return 0
        except KeyboardInterrupt:
            raise
        except BaseException as error:
            log.write(f"FAIL: {error}\n".encode())
            return 1

    def check_executable_modes(self, log: Any) -> None:
        expected = [self.root / "bootstrap.sh", self.root / "bin/osint", self.root / "forge/osint_forge.py"]
        expected.extend(self.root / path for path in shell_files(self.root) if path not in {"bootstrap.sh", "bin/osint"})
        expected.append(self.root / "scripts/qa-harness.py")
        invalid = [str(path.relative_to(self.root)) for path in expected if not os.access(path, os.X_OK)]
        if invalid:
            raise HarnessError(f"Files missing executable mode: {', '.join(sorted(set(invalid)))}")
        log.write(f"checked={len(set(expected))}\n".encode())

    def check_repository_hygiene(self, log: Any) -> None:
        invalid: list[str] = []
        for path in tracked_files(self.root):
            relative = path.relative_to(self.root)
            if any(part in PROHIBITED_TRACKED_PARTS for part in relative.parts):
                invalid.append(str(relative))
            if relative.name.endswith((".pyc", ".log", ".tmp")):
                invalid.append(str(relative))
        if invalid:
            raise HarnessError(f"Prohibited tracked artifacts: {', '.join(sorted(set(invalid)))}")
        log.write(f"tracked_files={len(tracked_files(self.root))}\n".encode())

    def check_markdown_links(self, log: Any) -> None:
        link_pattern = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
        failures: list[str] = []
        checked = 0
        for document in tracked_files(self.root):
            if document.suffix.lower() != ".md":
                continue
            text = document.read_text(encoding="utf-8")
            for target in link_pattern.findall(text):
                target = target.strip().split()[0].strip("<>")
                if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                    continue
                checked += 1
                local = (document.parent / target.split("#", 1)[0]).resolve()
                if self.root.resolve() not in (local, *local.parents) or not local.exists():
                    failures.append(f"{document.relative_to(self.root)} -> {target}")
        if failures:
            raise HarnessError("Broken or escaping Markdown links: " + "; ".join(failures))
        log.write(f"local_links_checked={checked}\n".encode())

    def check_credential_patterns(self, log: Any) -> None:
        matches: list[str] = []
        scanned = 0
        for path in tracked_files(self.root):
            try:
                content = path.read_bytes()
            except OSError as error:
                raise HarnessError(f"Could not scan {path}: {error}") from error
            if b"\0" in content:
                continue
            scanned += 1
            if any(pattern.search(content) for pattern in SECRET_PATTERNS):
                matches.append(str(path.relative_to(self.root)))
        if matches:
            raise HarnessError(f"Credential-like material found: {', '.join(matches)}")
        log.write(f"text_files_scanned={scanned}\n".encode())

    def check_version_consistency(self, log: Any) -> None:
        outputs = [
            subprocess.run(
                ["./bin/osint", "--version"],
                cwd=self.root,
                env={**os.environ, "OSINT_FORGE_ROOT": str(self.root)},
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip(),
            subprocess.run(
                ["./bin/osint", "forge", "version"],
                cwd=self.root,
                env={**os.environ, "OSINT_FORGE_ROOT": str(self.root)},
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip(),
        ]
        expected = f"OSINT Forge {self.version}"
        if outputs != [expected, expected]:
            raise HarnessError(f"Version mismatch: expected {expected!r}, got {outputs!r}")
        log.write(f"version={self.version}\n".encode())

    def check_lifecycle_dry_runs(self, log: Any) -> None:
        state = self.run_dir / "dry-run-state"
        state.mkdir(mode=PRIVATE_DIRECTORY_MODE, exist_ok=True)
        count = 0
        for plugin_dir in sorted((self.root / "plugins").iterdir()):
            if not plugin_dir.is_dir():
                continue
            plugin = plugin_dir.name
            environment = {
                **os.environ,
                "OSINT_FORGE_ROOT": str(self.root),
                "OSINT_FORGE_STATE": str(state),
                "OSINT_FORGE_PLUGIN_ID": plugin,
                "OSINT_FORGE_PLUGIN_DIR": str(plugin_dir),
                "OSINT_FORGE_DRY_RUN": "1",
            }
            for lifecycle in ("install.sh", "update.sh", "remove.sh"):
                command = [str(plugin_dir / lifecycle)]
                log.write(("command=" + shlex.join(command) + "\n").encode())
                result = subprocess.run(
                    command,
                    cwd=self.root,
                    env=environment,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                if result.returncode:
                    raise HarnessError(
                        f"{plugin}/{lifecycle} dry-run failed with {result.returncode}"
                    )
                count += 1
        log.write(f"lifecycle_dry_runs={count}\n".encode())

    def check_source_archives(self, log: Any) -> None:
        with tempfile.TemporaryDirectory(prefix="osint-forge-archives-") as temporary:
            temporary_path = Path(temporary)
            tar_path = temporary_path / "source.tar"
            zip_path = temporary_path / "source.zip"
            subprocess.run(
                ["git", "archive", "--format=tar", f"--output={tar_path}", self.commit],
                cwd=self.root,
                check=True,
            )
            subprocess.run(
                ["git", "archive", "--format=zip", f"--output={zip_path}", self.commit],
                cwd=self.root,
                check=True,
            )
            tar_root = temporary_path / "tar"
            zip_root = temporary_path / "zip"
            tar_root.mkdir()
            zip_root.mkdir()
            shutil.unpack_archive(str(tar_path), str(tar_root), "tar")
            self.unpack_git_zip(zip_path, zip_root)
            tar_files = self.directory_hashes(tar_root)
            zip_files = self.directory_hashes(zip_root)
            if tar_files != zip_files:
                raise HarnessError("Git tar and ZIP archive contents differ")
            if any(".git" in Path(name).parts for name in tar_files):
                raise HarnessError("Source archive contains Git metadata")
            log.write(f"archive_files={len(tar_files)}\n".encode())
            log.write(f"tar_sha256={sha256(tar_path)}\n".encode())
            log.write(f"zip_sha256={sha256(zip_path)}\n".encode())
            for label, extracted in (("tar", tar_root), ("zip", zip_root)):
                environment = {**os.environ, "OSINT_FORGE_ROOT": str(extracted)}
                for command in (
                    ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"],
                    ["./bin/osint", "forge", "validate"],
                ):
                    log.write(
                        f"{label}_command={shlex.join(command)}\n".encode()
                    )
                    result = subprocess.run(
                        command,
                        cwd=extracted,
                        env=environment,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
                    if result.returncode:
                        raise HarnessError(
                            f"{label} archive check failed ({result.returncode}): "
                            f"{shlex.join(command)}"
                        )

    @staticmethod
    def unpack_git_zip(archive: Path, destination: Path) -> None:
        """Extract a Git ZIP while retaining its recorded Unix file modes."""
        destination = destination.resolve()
        with zipfile.ZipFile(archive) as handle:
            members = handle.infolist()
            for member in members:
                relative = Path(member.filename)
                extracted = (destination / relative).resolve()
                if destination not in (extracted, *extracted.parents):
                    raise HarnessError(
                        f"ZIP archive member escapes extraction root: {member.filename}"
                    )
            handle.extractall(destination)
            for member in members:
                extracted = (destination / member.filename).resolve()
                mode = stat.S_IMODE(member.external_attr >> 16)
                if mode and extracted.exists():
                    extracted.chmod(mode)

    def check_hosted_checks(self, log: Any) -> None:
        if shutil.which("gh") is None:
            raise HarnessError("GitHub CLI is required for exact-commit hosted checks")
        remote = git(self.root, "remote", "get-url", "origin")
        match = re.search(
            r"(?:github\.com[:/])(?P<slug>[^/]+/[^/]+?)(?:\.git)?$",
            remote,
        )
        if not match:
            raise HarnessError(f"Cannot derive GitHub repository from origin: {remote}")
        slug = match.group("slug")
        result = subprocess.run(
            [
                "gh",
                "api",
                "--paginate",
                f"repos/{slug}/commits/{self.commit}/check-runs",
                "--jq",
                ".check_runs[] | [.name, .status, (.conclusion // \"\")] | @tsv",
            ],
            cwd=self.root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        log.write(result.stdout.encode())
        log.write(result.stderr.encode())
        if result.returncode:
            raise HarnessError(f"Could not retrieve GitHub checks ({result.returncode})")
        checks: dict[str, tuple[str, str]] = {}
        for line in result.stdout.splitlines():
            try:
                name, status, conclusion = line.split("\t", 2)
            except ValueError:
                raise HarnessError(f"Malformed GitHub check record: {line!r}")
            checks[name] = (status, conclusion)
        missing = sorted(EXPECTED_HOSTED_CHECKS - checks.keys())
        unsuccessful = sorted(
            name
            for name in EXPECTED_HOSTED_CHECKS & checks.keys()
            if checks[name] != ("completed", "success")
        )
        if missing or unsuccessful:
            raise HarnessError(
                f"Hosted checks not green; missing={missing}, unsuccessful={unsuccessful}"
            )
        log.write(f"required_hosted_checks={len(EXPECTED_HOSTED_CHECKS)}\n".encode())

    @staticmethod
    def directory_hashes(root: Path) -> dict[str, str]:
        return {
            str(path.relative_to(root)): sha256(path)
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def write_manifest(self) -> None:
        manifest = self.run_dir / "MANIFEST.sha256"
        lines = []
        for path in sorted(self.run_dir.rglob("*")):
            if path.is_file() and path not in {manifest, self.lock_path}:
                lines.append(f"{sha256(path)}  {path.relative_to(self.run_dir)}")
        temporary = manifest.with_name(f".{manifest.name}.{os.getpid()}.tmp")
        temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
        temporary.chmod(PRIVATE_FILE_MODE)
        temporary.replace(manifest)


def verify_evidence(run_dir: Path) -> int:
    run_dir = run_dir.expanduser().absolute()
    manifest = run_dir / "MANIFEST.sha256"
    if not manifest.is_file():
        print(f"Missing evidence manifest: {manifest}", file=sys.stderr)
        return 1
    failures = []
    expected_paths = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        try:
            expected, relative = line.split("  ", 1)
        except ValueError:
            failures.append(f"malformed manifest line: {line!r}")
            continue
        path = run_dir / relative
        expected_paths.add(path)
        if not path.is_file():
            failures.append(f"missing: {relative}")
        elif sha256(path) != expected:
            failures.append(f"changed: {relative}")
    actual_paths = {
        path
        for path in run_dir.rglob("*")
        if path.is_file() and path.name not in {"MANIFEST.sha256", ".lock"}
    }
    for path in sorted(actual_paths - expected_paths):
        failures.append(f"unmanifested: {path.relative_to(run_dir)}")
    if failures:
        print("Evidence verification failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"PASS: evidence manifest verified: {run_dir}")
    return 0


def show_status(run_dir: Path) -> int:
    run_dir = lexical_absolute(run_dir)
    state_path = run_dir / "state.json"
    if not state_path.is_file():
        print(f"Missing QA state: {state_path}", file=sys.stderr)
        return 1
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"Unreadable QA state: {error}", file=sys.stderr)
        return 1
    steps = state.get("steps", {})
    counts: dict[str, int] = {}
    for result in steps.values():
        status = result.get("status", "unknown")
        counts[status] = counts.get(status, 0) + 1
    print(f"Run:          {state.get('run_id', run_dir.name)}")
    print(f"Status:       {state.get('status', 'unknown')}")
    print(f"Profile:      {state.get('profile', 'unknown')}")
    print(f"Commit:       {state.get('commit', 'unknown')}")
    print(f"Current step: {state.get('current_step') or 'none'}")
    print(
        "Steps:        "
        + (", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
           or "none")
    )
    print(f"Started:      {state.get('started_at') or 'not started'}")
    print(f"Completed:    {state.get('completed_at') or 'not completed'}")
    if state.get("failure"):
        print(f"Failure:      {state['failure'].get('message', 'unknown')}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, default="development")
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=Path.home() / "OSINT-Forge-QA",
        help="Private evidence root (default: ~/OSINT-Forge-QA)",
    )
    parser.add_argument("--resume", type=Path, help="Resume an existing run directory")
    parser.add_argument(
        "--candidate-ref",
        help="Require this ref to resolve to the checked-out HEAD commit",
    )
    parser.add_argument(
        "--authorization",
        default="local development validation",
        help="Recorded authorization/scope statement",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow a dirty tree in development profile only",
    )
    parser.add_argument(
        "--verify",
        type=Path,
        metavar="RUN_DIRECTORY",
        help="Verify an existing evidence manifest and exit",
    )
    parser.add_argument(
        "--status",
        type=Path,
        metavar="RUN_DIRECTORY",
        help="Show concise progress for an existing run and exit",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.verify and args.status:
        print("--verify and --status are mutually exclusive", file=sys.stderr)
        return 2
    if args.verify:
        return verify_evidence(args.verify)
    if args.status:
        return show_status(args.status)
    harness: Harness | None = None
    try:
        harness = Harness(args)
        harness.initialize()
        return harness.run()
    except (HarnessError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    finally:
        if harness is not None:
            harness.release_lock()


if __name__ == "__main__":
    raise SystemExit(main())
