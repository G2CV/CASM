from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys

from dataclasses import dataclass
from pathlib import Path
from urllib import error as url_error
from urllib import request as url_request

from importlib import resources


KNOWN_TOOLS = {"probe", "http_verify", "dns_enum"}


class ToolResolutionError(RuntimeError):
    """Raised when a CASM tool binary cannot be resolved."""


@dataclass(frozen=True)
class ResolvedTool:
    tool_name: str
    path: str
    source: str


def resolve_tool_path(tool_name: str, explicit_path: str | None = None) -> ResolvedTool:
    """Resolve a runnable tool binary path for the current platform.

    Resolution order:
    1. Explicit CLI path override
    2. Bundled binary shipped in the Python package
    3. Source-tree fallback (hands/bin) for repo usage
    4. Cached downloaded binary
    5. Download from release URL template + verify SHA256 from manifest
    """
    if tool_name not in KNOWN_TOOLS:
        raise ValueError(f"Unsupported tool: {tool_name}")

    binary_name = _binary_name(tool_name)
    platform_id = _platform_id()
    cache_path = _cache_path(platform_id, binary_name)
    searched: list[Path] = []

    if explicit_path:
        path = Path(explicit_path)
        searched.append(path)
        if _is_runnable(path):
            return ResolvedTool(tool_name=tool_name, path=str(path.resolve()), source="explicit")
        raise ToolResolutionError(f"Tool path not runnable: {path}")

    bundled = _materialize_bundled_binary(platform_id, binary_name)
    if bundled is not None:
        searched.append(bundled)
        if _is_runnable(bundled):
            return ResolvedTool(tool_name=tool_name, path=str(bundled.resolve()), source="bundled")

    source_tree = Path("hands") / "bin" / binary_name
    searched.append(source_tree)
    if _is_runnable(source_tree):
        return ResolvedTool(tool_name=tool_name, path=str(source_tree.resolve()), source="source-tree")

    built = _build_from_source_tree(tool_name, binary_name)
    if built is not None and _is_runnable(built):
        return ResolvedTool(tool_name=tool_name, path=str(built.resolve()), source="source-build")

    searched.append(cache_path)
    if _is_runnable(cache_path):
        return ResolvedTool(tool_name=tool_name, path=str(cache_path.resolve()), source="cache")

    downloaded = _download_binary(tool_name, platform_id, binary_name, cache_path)
    if downloaded is not None and _is_runnable(downloaded):
        return ResolvedTool(tool_name=tool_name, path=str(downloaded.resolve()), source="download")

    searched_str = ", ".join(str(item) for item in searched)
    raise ToolResolutionError(
        "Unable to locate tool binary. "
        f"tool={tool_name} platform={platform_id} searched=[{searched_str}]. "
        "Install a wheel that bundles tools for this platform, pass --*-tool-path, "
        "or configure CASM_TOOL_DOWNLOAD_URL_TEMPLATE and CASM_TOOL_MANIFEST_URL."
    )


def _binary_name(tool_name: str) -> str:
    if sys.platform.startswith("win"):
        return f"{tool_name}.exe"
    return tool_name


def _platform_id() -> str:
    sys_name = _normalize_system(sys.platform)
    machine = _normalize_machine(platform.machine())
    return f"{sys_name}-{machine}"


def _normalize_system(value: str) -> str:
    if value.startswith("linux"):
        return "linux"
    if value == "darwin":
        return "darwin"
    if value.startswith("win"):
        return "windows"
    return value


def _normalize_machine(value: str) -> str:
    lowered = value.strip().lower()
    mapping = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }
    return mapping.get(lowered, lowered)


def _cache_path(platform_id: str, binary_name: str) -> Path:
    return Path.home() / ".cache" / "casm" / "tools" / platform_id / binary_name


def _materialize_bundled_binary(platform_id: str, binary_name: str) -> Path | None:
    try:
        package_root = resources.files("brain")
    except ModuleNotFoundError:
        return None

    candidate = package_root.joinpath("_bin", platform_id, binary_name)
    if not candidate.is_file():
        return None

    out_path = _cache_path(platform_id, binary_name)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = candidate.read_bytes()
    if not out_path.exists() or out_path.read_bytes() != payload:
        out_path.write_bytes(payload)
    _ensure_executable(out_path)
    return out_path


def _download_binary(
    tool_name: str,
    platform_id: str,
    binary_name: str,
    cache_path: Path,
) -> Path | None:
    if os.environ.get("CASM_DISABLE_AUTO_DOWNLOAD", "false").lower() == "true":
        return None

    url_template = os.environ.get("CASM_TOOL_DOWNLOAD_URL_TEMPLATE")
    manifest_url = os.environ.get("CASM_TOOL_MANIFEST_URL")
    if not url_template or not manifest_url:
        return None

    try:
        manifest_bytes = _download_bytes(manifest_url)
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError, url_error.URLError):
        return None

    expected_sha = _manifest_sha256(manifest, tool_name, platform_id, binary_name)
    if not expected_sha:
        return None

    url = url_template.format(
        tool=tool_name,
        platform=platform_id,
        filename=binary_name,
    )

    try:
        payload = _download_bytes(url)
    except (OSError, url_error.URLError):
        return None

    digest = hashlib.sha256(payload).hexdigest()
    if digest.lower() != expected_sha.lower():
        return None

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(payload)
    _ensure_executable(cache_path)
    return cache_path


def _build_from_source_tree(tool_name: str, binary_name: str) -> Path | None:
    go_mod = Path("hands") / "go.mod"
    cmd_dir = Path("hands") / "cmd" / tool_name
    if not go_mod.exists() or not cmd_dir.exists():
        return None
    if shutil.which("go") is None:
        return None

    output_path = Path("hands") / "bin" / binary_name
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["go", "build", "-o", str(output_path.resolve()), f"./cmd/{tool_name}"]
    try:
        subprocess.run(
            cmd,
            cwd=str((Path.cwd() / "hands").resolve()),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None

    if _is_runnable(output_path):
        return output_path
    return None


def _download_bytes(url: str, timeout: int = 30) -> bytes:
    with url_request.urlopen(url, timeout=timeout) as response:
        return response.read()


def _manifest_sha256(
    manifest: dict,
    tool_name: str,
    platform_id: str,
    binary_name: str,
) -> str | None:
    direct_key = f"{platform_id}/{binary_name}"
    if isinstance(manifest.get("sha256"), dict):
        direct = manifest["sha256"].get(direct_key)
        if isinstance(direct, str):
            return direct

    tools = manifest.get("tools")
    if isinstance(tools, dict):
        platform_entry = tools.get(platform_id)
        if isinstance(platform_entry, dict):
            tool_entry = platform_entry.get(tool_name)
            if isinstance(tool_entry, dict):
                digest = tool_entry.get("sha256")
                if isinstance(digest, str):
                    return digest
    return None


def _is_runnable(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        return False
    if sys.platform.startswith("win"):
        return True
    return os.access(path, os.X_OK)


def _ensure_executable(path: Path) -> None:
    if sys.platform.startswith("win"):
        return
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR)
