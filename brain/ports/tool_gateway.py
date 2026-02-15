
from __future__ import annotations

from typing import Protocol

from brain.core.models import ToolRequest, ToolResult


class ToolGateway(Protocol):
    """Abstract tool runner for orchestrated workflows."""
    def run(self, request: ToolRequest) -> ToolResult:
        """Execute a tool request and return a normalized result.

        Args:
            request (ToolRequest): Structured request payload.

        Returns:
            ToolResult: Normalized tool output for orchestration.
        """
        ...
