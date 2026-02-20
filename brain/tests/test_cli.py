import pytest

from brain.cli import casm


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
