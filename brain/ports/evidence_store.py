
from __future__ import annotations

from typing import Protocol

from brain.core.models import Evidence, Finding


class EvidenceStore(Protocol):
    """Persistence boundary for evidence and report artifacts."""
    def write(
        self,
        engagement_id: str,
        run_id: str,
        tool_name: str | None,
        tool_version: str | None,
        findings: list[Finding],
        evidence: list[Evidence],
        report_md: str,
        tool_stderr: str | None = None,
        tool_stdout: str | None = None,
    ) -> dict:
        """Persist evidence and return artifact locations.

        Args:
            engagement_id (str): Engagement identifier for namespacing.
            run_id (str): Run identifier for namespacing.
            tool_name (str | None): Tool name to apply when missing.
            tool_version (str | None): Tool version to apply when missing.
            findings (list[Finding]): Findings to persist (if applicable).
            evidence (list[Evidence]): Evidence events to persist.
            report_md (str): Rendered report markdown.
            tool_stderr (str | None): Optional stderr content to store.
            tool_stdout (str | None): Optional stdout content to store.

        Returns:
            dict: Paths for evidence, report, and optional stderr/stdout logs.
        """
        ...
