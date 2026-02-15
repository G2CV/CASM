import json

from brain.core.migrate import migrate_run
from brain.core.schema_version import SCHEMA_VERSION


def test_migrate_run_adds_schema_version(tmp_path) -> None:
    input_dir = tmp_path / "run"
    input_dir.mkdir()
    (input_dir / "evidence.jsonl").write_text(
        json.dumps({"id": "e1", "type": "http_response", "data": {}}) + "\n",
        encoding="utf-8",
    )
    (input_dir / "results.sarif").write_text(
        json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{}]}),
        encoding="utf-8",
    )
    (input_dir / "report.md").write_text("# Report\n\nContent\n", encoding="utf-8")

    output_dir = tmp_path / "run-migrated"
    stats = migrate_run(str(input_dir), str(output_dir))

    assert stats.migrated_evidence == 1
    evidence = json.loads((output_dir / "evidence.jsonl").read_text(encoding="utf-8").strip())
    assert evidence["schema_version"] == SCHEMA_VERSION

    sarif = json.loads((output_dir / "results.sarif").read_text(encoding="utf-8"))
    assert sarif["properties"]["schema_version"] == SCHEMA_VERSION
    assert sarif["runs"][0]["properties"]["schema_version"] == SCHEMA_VERSION

    report = (output_dir / "report.md").read_text(encoding="utf-8")
    assert f"Report schema: {SCHEMA_VERSION}" in report
