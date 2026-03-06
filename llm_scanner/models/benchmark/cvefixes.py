from pydantic import BaseModel, Field

from models.context import FileSpans


class CVEFixesEntry(BaseModel):
    """Normalized CVEFixes entry with repository and location metadata."""

    cve_id: str = Field(..., description="CVE identifier")
    repo_url: str = Field(..., description="Repository URL")
    fix_hash: str = Field(..., description="Fix commit hash")
    files_spans: list[FileSpans] = Field(
        ..., description="List of modified files and their vulnerable line spans"
    )
    description: str = Field(default="", description="CVE description")
    cwe_id: int | None = Field(default=None, description="Numeric CWE identifier if available")
    severity: str | None = Field(default=None, description="CVSS severity label")
    is_vulnerable: bool = Field(
        default=True,
        description="Whether the entry represents a vulnerable span (vs. non-vulnerable context)",
    )
