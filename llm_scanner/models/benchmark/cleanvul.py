from pydantic import BaseModel, ConfigDict, Field

from models.context import FileSpans


class CleanVulEntry(BaseModel):
    """Normalized CleanVul entry with repository and location metadata."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    commit_url: str = Field(..., description="Full GitHub commit URL")
    repo_url: str = Field(..., description="Repository base URL (no .git suffix)")
    fix_hash: str = Field(..., description="Fix commit SHA")
    file_name: str = Field(..., description="Full file path within the repository")
    func_code: str = Field(..., description="Function source code (before or after fix)")
    files_spans: list[FileSpans] = Field(
        ..., description="Located line spans for func_code in the checked-out file"
    )
    cve_id: str = Field(default="", description="CVE identifier, may be empty")
    cwe_id: int | None = Field(default=None, description="Primary numeric CWE identifier")
    cwe_ids: list[int] = Field(
        default_factory=list, description="All parsed numeric CWE identifiers"
    )
    vulnerability_score: int = Field(..., ge=0, le=4, description="Dataset confidence score 0-4")
    commit_msg: str = Field(default="", description="Commit message")
    is_vulnerable: bool = Field(
        ..., description="True = func_before (vulnerable), False = func_after (fixed)"
    )
