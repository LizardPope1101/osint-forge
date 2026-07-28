#!/usr/bin/env python3
from __future__ import annotations

import argparse
import configparser
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
PLUGIN_ROOT = ROOT / "plugins"
STATE_HOME = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
STATE_ROOT = STATE_HOME / "osint-forge"


@dataclass(frozen=True)
class Plugin:
    plugin_id: str
    directory: Path
    data: dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.data.get("name", self.plugin_id))


def load_plugins() -> dict[str, Plugin]:
    loaded: dict[str, Plugin] = {}
    for path in sorted(PLUGIN_ROOT.glob("*/manifest.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        plugin_id = str(data.get("id", ""))
        if not plugin_id or plugin_id != path.parent.name:
            raise ValueError(f"Manifest ID mismatch: {path}")
        if plugin_id in loaded:
            raise ValueError(f"Duplicate plugin ID: {plugin_id}")
        loaded[plugin_id] = Plugin(plugin_id, path.parent, data)
    return loaded


def expand(argv: list[str], values: dict[str, str]) -> list[str]:
    return [part.format_map(values) for part in argv]


def lifecycle_argv(plugin: Plugin, action: str) -> list[str]:
    spec = plugin.data.get("lifecycle", {}).get(action)
    if not spec:
        raise ValueError(f"{plugin.plugin_id} does not define {action}")
    argv = list(spec["argv"])
    if spec.get("root") and os.geteuid() != 0:
        argv.insert(0, "sudo")
    return argv


def run(argv: list[str], *, output: Path | None = None, check: bool = True) -> int:
    print("+", " ".join(argv))
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as handle:
            result = subprocess.run(argv, stdout=handle, stderr=subprocess.STDOUT, text=True)
    else:
        result = subprocess.run(argv)
    if check and result.returncode:
        raise subprocess.CalledProcessError(result.returncode, argv)
    return result.returncode


def is_installed(plugin: Plugin) -> bool:
    detect = plugin.data.get("lifecycle", {}).get("detect", {})
    command = detect.get("command")
    return bool(command and shutil.which(command))


def select_plugins(args: argparse.Namespace, plugins: dict[str, Plugin]) -> list[Plugin]:
    if getattr(args, "all", False):
        return list(plugins.values())
    names = getattr(args, "plugin", None) or []
    missing = [name for name in names if name not in plugins]
    if missing:
        raise ValueError("Unknown plugin(s): " + ", ".join(missing))
    return [plugins[name] for name in names]


def cmd_plugins(plugins: dict[str, Plugin]) -> None:
    for plugin in plugins.values():
        targets = ", ".join(plugin.data.get("targets", [])) or "-"
        print(f"{plugin.plugin_id:12} {plugin.name:20} targets={targets}")


def cmd_lifecycle(action: str, selected: list[Plugin]) -> None:
    for plugin in selected:
        if action == "install" and is_installed(plugin):
            print(f"{plugin.plugin_id}: already installed")
            continue
        if action in {"update", "remove"} and not is_installed(plugin):
            print(f"{plugin.plugin_id}: not installed; skipped")
            continue
        run(lifecycle_argv(plugin, action))


def read_targets(path: Path) -> dict[str, list[str]]:
    parser = configparser.ConfigParser(allow_no_value=True, delimiters=("=",))
    parser.optionxform = str
    parser.read(path, encoding="utf-8")
    targets: dict[str, list[str]] = {}
    for section in parser.sections():
        values = []
        for key, value in parser.items(section):
            candidate = key if not value else f"{key}={value}"
            candidate = candidate.strip()
            if candidate:
                values.append(candidate)
        targets[section.lower()] = values
    return targets


def cmd_batch(path: Path, selected: list[Plugin]) -> None:
    targets = read_targets(path)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_root = STATE_ROOT / "runs" / stamp
    work = 0
    for plugin in selected:
        if not is_installed(plugin):
            print(f"{plugin.plugin_id}: not installed; skipped", file=sys.stderr)
            continue
        adapter = plugin.data.get("adapter", {})
        template = adapter.get("argv")
        target_type = adapter.get("target_type")
        if not template or not target_type:
            continue
        for index, target in enumerate(targets.get(target_type, []), start=1):
            output_dir = run_root / plugin.plugin_id / f"{index:03d}"
            output_dir.mkdir(parents=True, exist_ok=True)
            values = {"target": target, "output_dir": str(output_dir)}
            run(expand(list(template), values), output=output_dir / "command.log", check=False)
            (output_dir / "target.txt").write_text(target + "\n", encoding="utf-8")
            work += 1
    print(f"Completed {work} task(s). Results: {run_root}")


def cmd_status(plugins: dict[str, Plugin]) -> None:
    for plugin in plugins.values():
        print(f"{plugin.plugin_id:12} {'installed' if is_installed(plugin) else 'missing'}")


def cmd_doctor(plugins: dict[str, Plugin]) -> None:
    required = ["python3", "git", "pipx"]
    failed = False
    for command in required:
        found = shutil.which(command)
        print(f"{command:12} {found or 'MISSING'}")
        failed |= not bool(found)
    print(f"{'plugins':12} {len(plugins)} manifest(s)")
    print(f"{'state':12} {STATE_ROOT}")
    if failed:
        raise SystemExit(1)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="osint-forge")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("plugins", help="list available plugins")
    commands.add_parser("status", help="show installed tools")
    commands.add_parser("doctor", help="check base dependencies")
    for action in ("install", "update", "remove"):
        item = commands.add_parser(action)
        item.add_argument("plugin", nargs="*")
        item.add_argument("--all", action="store_true")
    batch = commands.add_parser("batch", help="run plugins against an INI target file")
    batch.add_argument("target_file", type=Path)
    batch.add_argument("--plugin", action="append", default=[])
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        plugins = load_plugins()
        if args.command == "plugins":
            cmd_plugins(plugins)
        elif args.command == "status":
            cmd_status(plugins)
        elif args.command == "doctor":
            cmd_doctor(plugins)
        elif args.command in {"install", "update", "remove"}:
            selected = select_plugins(args, plugins)
            if not selected:
                raise ValueError("Specify one or more plugins, or use --all")
            cmd_lifecycle(args.command, selected)
        elif args.command == "batch":
            selected = select_plugins(args, plugins) if args.plugin else list(plugins.values())
            cmd_batch(args.target_file, selected)
        return 0
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
