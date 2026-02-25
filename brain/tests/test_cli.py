import argparse

import pytest
from types import SimpleNamespace

from brain.cli import casm
from brain.core.alerts import AlertDispatchResult
from brain.core.diff import DiffResult
from brain.core.scope import Scope
from brain.core.unified import UnifiedOutputs


@pytest.mark.parametrize(
    "argv,expected_hint",
    [
        (
            [
                "casm",
                "run",
                "probe",
                "--scope",
                "scopes/scope.yaml",
                "--enable-dns-enum",
            ],
            "only valid with `casm run unified`",
        ),
        (
            [
                "casm",
                "run",
                "probe",
                "--config",
                "scopes/scope.yaml",
            ],
            "expect `--scope`, not `--config`",
        ),
        (
            [
                "casm",
                "run",
                "unified",
                "--scope",
                "scopes/scope.yaml",
            ],
            "expect `--config`, not `--scope`",
        ),
        (
            [
                "casm",
                "run",
                "http-verify",
                "--scope",
                "scopes/scope.yaml",
                "--targets-file",
                "targets.json",
            ],
            "only available with `casm run unified`",
        ),
    ],
)
def test_cli_shows_actionable_hints_for_wrong_flags(monkeypatch, capsys, argv, expected_hint) -> None:
    monkeypatch.setattr("sys.argv", argv)

    with pytest.raises(SystemExit) as exc:
        casm.main()

    assert exc.value.code == 2
    stderr = capsys.readouterr().err
    assert "Hint:" in stderr
    assert expected_hint in stderr


def test_alert_cli_rejects_mutually_exclusive_mode_flags(monkeypatch, capsys, tmp_path) -> None:
    old_path = tmp_path / "old.sarif"
    new_path = tmp_path / "new.sarif"
    scope_path = tmp_path / "scope.yaml"
    old_path.write_text('{"runs":[]}', encoding="utf-8")
    new_path.write_text('{"runs":[]}', encoding="utf-8")
    scope_path.write_text(
        """
engagement_id: eng
allowed_domains: []
allowed_ips: []
allowed_ports: [80]
allowed_protocols: [http]
seed_targets: [localhost]
max_rate: 1
max_concurrency: 1
""",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "casm",
            "alert",
            "--config",
            str(scope_path),
            "--old",
            str(old_path),
            "--new",
            str(new_path),
            "--only-added",
            "--only-removed",
        ],
    )

    code = casm.main()
    assert code == 2
    assert "mutually exclusive" in capsys.readouterr().err


def test_unified_can_dispatch_alerts_after_run(monkeypatch, tmp_path, capsys) -> None:
    scope = Scope(
        engagement_id="eng-alert",
        allowed_domains=[],
        allowed_ips=[],
        allowed_ports=[80],
        allowed_protocols=["http"],
        seed_targets=["localhost"],
        max_rate=1.0,
        max_concurrency=1,
        notifications={"publishers": [{"type": "file", "path": str(tmp_path / "events.jsonl")}]},
    )
    baseline = tmp_path / "baseline.sarif"
    baseline.write_text('{"runs":[]}', encoding="utf-8")
    current = tmp_path / "current.sarif"
    current.write_text('{"runs":[]}', encoding="utf-8")
    evidence = tmp_path / "evidence.jsonl"
    evidence.write_text('{"run_id":"run-1"}\n', encoding="utf-8")

    monkeypatch.setattr(casm.Scope, "from_file", staticmethod(lambda _path: scope))
    monkeypatch.setattr(casm, "resolve_tool_path", lambda _name, _path: SimpleNamespace(path="/bin/true"))
    monkeypatch.setattr(
        casm,
        "run_unified",
        lambda **_kwargs: UnifiedOutputs(
            targets_path=str(tmp_path / "targets.jsonl"),
            evidence_path=str(evidence),
            report_path=str(tmp_path / "report.md"),
            sarif_path=str(current),
        ),
    )
    monkeypatch.setattr(casm, "diff_sarif", lambda *_args, **_kwargs: DiffResult([], [], []))
    monkeypatch.setattr(casm, "resolve_publisher", lambda _cfg: object())

    captured: list[dict] = []

    def _fake_dispatch(*_args, **kwargs):
        captured.append(kwargs)
        return AlertDispatchResult(considered=0, published=0, suppressed_by_cooldown=0, skipped_by_filters=0)

    monkeypatch.setattr(casm, "dispatch_diff_alerts", _fake_dispatch)

    args = argparse.Namespace(
        config="scope.yaml",
        out=str(tmp_path / "out"),
        sarif_mode="local",
        probe_tool_path=None,
        http_tool_path=None,
        targets_file=None,
        dry_run=True,
        enable_dns_enum=False,
        dns_tool_path=None,
        dns_wordlist=None,
        detailed=False,
        format="markdown,sarif",
        report_lang="en",
        alert_on_diff=True,
        baseline_sarif=str(baseline),
        alert_tool="http_verify",
        alert_dry_run=True,
        min_severity="medium",
        rule_id=["MISSING_CSP"],
        uri_regex="example",
        cooldown_minutes=10,
        max_events=5,
        state_path=str(tmp_path / "state.json"),
        only_added=False,
        only_removed=False,
    )

    code = casm.unified_command(args)

    assert code == 0
    assert len(captured) == 1
    assert captured[0]["old_path"] == str(baseline)
    assert captured[0]["new_path"] == str(current)
    assert captured[0]["dry_run"] is True
    stdout = capsys.readouterr().out
    assert "Unified alerting complete" in stdout
