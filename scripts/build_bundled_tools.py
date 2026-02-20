from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys

from pathlib import Path


TOOLS = ("probe", "http_verify", "dns_enum")


def platform_id() -> str:
    if sys.platform.startswith("linux"):
        os_name = "linux"
    elif sys.platform == "darwin":
        os_name = "darwin"
    elif sys.platform.startswith("win"):
        os_name = "windows"
    else:
        os_name = sys.platform

    arch_raw = platform.machine().strip().lower()
    arch_map = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }
    arch = arch_map.get(arch_raw, arch_raw)
    return f"{os_name}-{arch}"


def binary_name(tool: str) -> str:
    if sys.platform.startswith("win"):
        return f"{tool}.exe"
    return tool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Go tools into brain/_bin/<platform>")
    parser.add_argument(
        "--version",
        default=os.environ.get("CASM_TOOL_VERSION", "dev"),
        help="Version to inject into Go tools via -ldflags",
    )
    parser.add_argument(
        "--clean-platform-dir",
        action="store_true",
        help="Delete existing binaries in the target platform directory before build",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    hands = root / "hands"
    if not (hands / "go.mod").exists():
        raise SystemExit("hands/go.mod not found")

    if shutil.which("go") is None:
        raise SystemExit("go compiler not found in PATH")

    target_platform = platform_id()
    out_dir = root / "brain" / "_bin" / target_platform
    out_dir.mkdir(parents=True, exist_ok=True)
    if args.clean_platform_dir:
        for item in out_dir.iterdir():
            if item.is_file():
                item.unlink()

    for tool in TOOLS:
        out = out_dir / binary_name(tool)
        cmd = [
            "go",
            "build",
            "-ldflags",
            f"-X main.toolVersion={args.version}",
            "-o",
            str(out),
            f"./cmd/{tool}",
        ]
        subprocess.run(cmd, cwd=str(hands), check=True)
        if not sys.platform.startswith("win"):
            mode = out.stat().st_mode
            out.chmod(mode | 0o100)
        print(f"built {tool} -> {out.relative_to(root)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
