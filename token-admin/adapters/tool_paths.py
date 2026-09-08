"""Paths to native files shipped beside the application.

All portable builds use the same layout: the launcher is in the package root
and platform-specific native files are kept in one flat ``lib`` directory.
"""

import os
import sys
from pathlib import Path


def application_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def lib_dir() -> Path:
    return application_root() / "lib"


def lib_file(name: str, *system_names: str) -> Path:
    bundled = lib_dir() / name
    if bundled.is_file():
        return bundled
    candidates: list[Path] = []
    if os.name == "nt":
        system = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32"
        candidates.extend(system / item for item in system_names)
    else:
        for directory in (Path("/usr/lib"), Path("/usr/local/lib"), Path("/lib")):
            candidates.extend(directory / item for item in system_names)
    return next((item for item in candidates if item.is_file()), bundled)
