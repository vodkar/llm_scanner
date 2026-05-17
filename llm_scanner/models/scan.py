"""Scan result models for CI pipeline output."""

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, computed_field


class ScanSeverity(StrEnum):
    """Severity levels for scan findings.

    Superset of ``IssueSeverity`` — adds ``CRITICAL`` for LLM-reported findings.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanFinding(BaseModel):
    """A single LLM-reviewed finding produced by the scanner pipeline."""

    root_id: str
    file_path: Path
    line_start: int
    line_end: int
    static_tool_messages: list[str] = Field(default_factory=list)
    """Bandit / Dlint messages that pointed to this root node (empty in diff mode)."""
    vulnerable: bool
    severity: ScanSeverity | None = None
    description: str | None = None
    cwe_id: int | None = None
    context_text: str


class ScanReport(BaseModel):
    """Complete report produced by a single scanner pipeline run."""

    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    src: Path
    mode: Literal["full", "diff"]
    strategy: str
    findings: list[ScanFinding] = Field(default_factory=list)
    total_contexts_scanned: int = 0

    @computed_field  # type: ignore[misc]
    @property
    def vulnerabilities_found(self) -> int:
        """Number of findings classified as vulnerable by the LLM."""
        return sum(1 for f in self.findings if f.vulnerable)
