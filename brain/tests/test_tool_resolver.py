import hashlib
import json

from pathlib import Path

import pytest

from brain.core import tool_resolver


def _make_executable(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)


def test_resolve_tool_path_uses_explicit_path(tmp_path) -> None:
    explicit = tmp_path / "probe"
    _make_executable(explicit)

    resolved = tool_resolver.resolve_tool_path("probe", explicit_path=str(explicit))

    assert resolved.path == str(explicit)
    assert resolved.source == "explicit"


def test_resolve_tool_path_uses_source_tree_fallback(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "hands" / "bin" / "probe"
    _make_executable(binary)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tool_resolver, "_materialize_bundled_binary", lambda *_args: None)
    monkeypatch.setattr(tool_resolver, "_download_binary", lambda *_args: None)

    resolved = tool_resolver.resolve_tool_path("probe")

    assert resolved.path == str(binary)
    assert resolved.source == "source-tree"


def test_resolve_tool_path_builds_from_source_tree(tmp_path, monkeypatch) -> None:
    tool_name = "probe"
    binary = tmp_path / "hands" / "bin" / "probe"
    cmd_dir = tmp_path / "hands" / "cmd" / tool_name
    cmd_dir.mkdir(parents=True, exist_ok=True)
    (tmp_path / "hands" / "go.mod").write_text("module test\n", encoding="utf-8")

    def fake_run(*_args, **_kwargs):
        _make_executable(binary)
        return None

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tool_resolver, "_materialize_bundled_binary", lambda *_args: None)
    monkeypatch.setattr(tool_resolver, "_download_binary", lambda *_args: None)
    monkeypatch.setattr(tool_resolver.shutil, "which", lambda *_args: "/usr/bin/go")
    monkeypatch.setattr(tool_resolver.subprocess, "run", fake_run)

    resolved = tool_resolver.resolve_tool_path(tool_name)

    assert resolved.path == str(binary)
    assert resolved.source == "source-build"


def test_resolve_tool_path_downloads_when_manifest_matches(tmp_path, monkeypatch) -> None:
    platform_id = "linux-x86_64"
    cache_path = tmp_path / "cache" / "probe"
    payload = b"probe-bin"
    digest = hashlib.sha256(payload).hexdigest()
    manifest = {
        "tools": {
            platform_id: {
                "probe": {"sha256": digest},
            }
        }
    }

    def fake_download(url: str, timeout: int = 30) -> bytes:
        if url == "https://example.test/manifest.json":
            return json.dumps(manifest).encode("utf-8")
        if url == f"https://example.test/{platform_id}/probe":
            return payload
        raise AssertionError(f"unexpected url: {url}")

    monkeypatch.setattr(tool_resolver, "_materialize_bundled_binary", lambda *_args: None)
    monkeypatch.setattr(tool_resolver, "_build_from_source_tree", lambda *_args: None)
    monkeypatch.setattr(tool_resolver, "_platform_id", lambda: platform_id)
    monkeypatch.setattr(tool_resolver, "_cache_path", lambda *_args: cache_path)
    monkeypatch.setattr(tool_resolver, "_download_bytes", fake_download)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CASM_TOOL_MANIFEST_URL", "https://example.test/manifest.json")
    monkeypatch.setenv(
        "CASM_TOOL_DOWNLOAD_URL_TEMPLATE",
        "https://example.test/{platform}/{filename}",
    )

    resolved = tool_resolver.resolve_tool_path("probe")

    assert resolved.path == str(cache_path)
    assert resolved.source == "download"
    assert cache_path.read_bytes() == payload


def test_resolve_tool_path_raises_when_unavailable(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tool_resolver, "_materialize_bundled_binary", lambda *_args: None)
    monkeypatch.setattr(tool_resolver, "_build_from_source_tree", lambda *_args: None)
    monkeypatch.setattr(tool_resolver, "_download_binary", lambda *_args: None)

    with pytest.raises(tool_resolver.ToolResolutionError):
        tool_resolver.resolve_tool_path("probe")
