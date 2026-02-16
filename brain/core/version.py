from __future__ import annotations

import subprocess
from importlib.metadata import PackageNotFoundError, version


def get_casm_version() -> str:
    try:
        return version("g2cv-casm")
    except PackageNotFoundError:
        try:
            return version("casm")
        except PackageNotFoundError:
            return _version_from_git() or "dev"


def _version_from_git() -> str | None:
    try:
        value = subprocess.check_output(
            ["git", "describe", "--tags", "--dirty", "--always"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return None
    if not value:
        return None
    if value.startswith("v"):
        return value[1:]
    return value
