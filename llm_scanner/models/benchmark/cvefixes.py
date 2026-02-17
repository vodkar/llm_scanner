from pathlib import Path

from pydantic import BaseModel, Field


class CVEFixesEntry(BaseModel):
    """Normalized CVEFixes entry with repository and location metadata."""

    cve_id: str = Field(..., description="CVE identifier")
    repo_url: str = Field(..., description="Repository URL")
    fix_hash: str = Field(..., description="Fix commit hash")
    file_path: Path = Field(..., description="Relative path to the vulnerable file")
    start_line: int = Field(..., ge=1, description="Start line of the vulnerable span")
    end_line: int = Field(..., ge=1, description="End line of the vulnerable span")
    description: str = Field(default="", description="CVE description")
    cwe_id: int | None = Field(default=None, description="Numeric CWE identifier if available")
    severity: str | None = Field(default=None, description="CVSS severity label")
