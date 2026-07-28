#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_HOME = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
BIN_HOME = Path.home() / ".local/bin"
INSTALL_ROOT = DATA_HOME / "osint-forge"


def copy_project() -> None:
    if INSTALL_ROOT.exists():
        shutil.rmtree(INSTALL_ROOT)
    shutil.copytree(
        ROOT,
        INSTALL_ROOT,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
    )
    BIN_HOME.mkdir(parents=True, exist_ok=True)
    launcher = BIN_HOME / "osint-forge"
    launcher.write_text(
        "#!/usr/bin/env bash\n"
        f'exec python3 "{INSTALL_ROOT / "osint_forge.py"}" "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def ensure_path() -> None:
    profile = Path.home() / ".profile"
    marker = 'export PATH="$HOME/.local/bin:$PATH"'
    current = profile.read_text(encoding="utf-8") if profile.exists() else ""
    if marker not in current:
        with profile.open("a", encoding="utf-8") as handle:
            if current and not current.endswith("\n"):
                handle.write("\n")
            handle.write(f"\n# OSINT Forge\n{marker}\n")


if __name__ == "__main__":
    copy_project()
    ensure_path()
    print(f"Installed OSINT Forge in {INSTALL_ROOT}")
    print("Run: source ~/.profile && osint-forge doctor")

