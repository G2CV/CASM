
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from brain.core.schema_version import SCHEMA_VERSION


@dataclass
class MigrationStats:
    migrated_evidence: int = 0
    skipped_evidence: int = 0
    migrated_sarif: int = 0
    skipped_sarif: int = 0
    report_updated: bool = False


def migrate_run(input_dir: str, output_dir: str, strict: bool = False) -> MigrationStats:
    """Migrate a run directory to the current schema version.

    Args:
        input_dir (str): Source run directory.
        output_dir (str): Destination directory for migrated artifacts.
        strict (bool): If True, fail on malformed JSON instead of skipping.

    Returns:
        MigrationStats: Counts of migrated and skipped artifacts.

    Raises:
        FileNotFoundError: If the input directory does not exist.
        json.JSONDecodeError: If strict is True and a JSON file is invalid.
    """
    source = Path(input_dir)
    if not source.exists():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    stats = MigrationStats()

    _migrate_targets(source, destination)
    stats.migrated_evidence, stats.skipped_evidence = _migrate_evidence(
        source, destination, strict
    )
    stats.migrated_sarif, stats.skipped_sarif = _migrate_sarif(source, destination, strict)
    stats.report_updated = _migrate_report(source, destination)

    return stats


def _migrate_targets(source: Path, destination: Path) -> None:
    targets = source / "targets.jsonl"
    if targets.exists():
        (destination / "targets.jsonl").write_text(targets.read_text(encoding="utf-8"), encoding="utf-8")


def _migrate_evidence(source: Path, destination: Path, strict: bool) -> tuple[int, int]:
    """Add schema version metadata to evidence lines when missing.

    Notes:
        Evidence is line-delimited JSON; invalid lines can be skipped to keep
        partial runs usable unless strict mode is requested.
    """
    path = source / "evidence.jsonl"
    if not path.exists():
        return 0, 0

    migrated = 0
    skipped = 0
    output = destination / "evidence.jsonl"
    with path.open("r", encoding="utf-8") as handle, output.open("w", encoding="utf-8") as out:
        for line in handle:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                if strict:
                    raise
                skipped += 1
                continue
            if "schema_version" not in event:
                event["schema_version"] = SCHEMA_VERSION
            out.write(json.dumps(event, sort_keys=True) + "\n")
            migrated += 1
    return migrated, skipped


def _migrate_sarif(source: Path, destination: Path, strict: bool) -> tuple[int, int]:
    """Ensure SARIF files include schema metadata for tooling compatibility."""
    migrated = 0
    skipped = 0
    for path in source.glob("*.sarif"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            if strict:
                raise
            skipped += 1
            continue
        _ensure_sarif_version(data)
        (destination / path.name).write_text(
            json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"
        )
        migrated += 1
    return migrated, skipped


def _migrate_report(source: Path, destination: Path) -> bool:
    """Inject report schema metadata if missing."""
    path = source / "report.md"
    if not path.exists():
        return False
    text = path.read_text(encoding="utf-8")
    if "Report schema:" in text:
        (destination / "report.md").write_text(text, encoding="utf-8")
        return False

    lines = text.splitlines()
    if lines:
        if lines[0].startswith("#"):
            updated = [lines[0], "", f"Report schema: {SCHEMA_VERSION}", ""] + lines[1:]
        else:
            updated = [f"Report schema: {SCHEMA_VERSION}", "", *lines]
    else:
        updated = [f"Report schema: {SCHEMA_VERSION}"]
    (destination / "report.md").write_text("\n".join(updated), encoding="utf-8")
    return True


def _ensure_sarif_version(data: dict) -> None:
    """Normalize schema metadata at the SARIF root and run level."""
    data.setdefault("properties", {})["schema_version"] = SCHEMA_VERSION
    runs = data.get("runs")
    if not isinstance(runs, list):
        return
    for run in runs:
        if isinstance(run, dict):
            run.setdefault("properties", {})["schema_version"] = SCHEMA_VERSION
