from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from models.context import Context


class BenchmarkMetadata(BaseModel):
    """Top-level metadata for the benchmark dataset."""

    name: str = Field(..., description="Dataset name")
    task_type: str = Field(..., description="Task type label")
    total_samples: int = Field(..., ge=0, description="Total number of samples")
    cwe_distribution: dict[str, int] = Field(
        default_factory=dict, description="Counts per CWE identifier"
    )


class BenchmarkSampleMetadata(BaseModel):
    """Metadata for a single benchmark sample."""

    model_config = ConfigDict(populate_by_name=True)

    cvefixes_number: str = Field(..., alias="CVEFixes-Number", description="CVEFixes identifier")
    description: str = Field(default="", description="CVE description")
    cwe_number: int | None = Field(default=None, description="Numeric CWE identifier")


class CleanVulSampleMetadata(BaseModel):
    """Metadata for a single CleanVul benchmark sample."""

    model_config = ConfigDict(populate_by_name=True)

    commit_url: str = Field(..., alias="CleanVul-CommitUrl", description="Source commit URL")
    description: str = Field(default="", description="Commit message used as description")
    cwe_number: int | None = Field(default=None, description="Primary numeric CWE identifier")


class BenchmarkSample(BaseModel):
    """Single labeled benchmark sample."""

    id: str = Field(..., description="Sample identifier")
    code: str = Field(..., description="Assembled context text")
    label: int = Field(..., ge=0, le=1, description="Binary label for vulnerability")
    metadata: BenchmarkSampleMetadata | CleanVulSampleMetadata = Field(
        ..., description="Sample metadata"
    )
    cwe_types: list[str] = Field(default_factory=list, description="Additional CWE tags")
    severity: str = Field(..., description="Severity label")


class BenchmarkDataset(BaseModel):
    """Benchmark dataset with metadata and samples."""

    metadata: BenchmarkMetadata
    samples: list[BenchmarkSample]


class UnassociatedSample(BaseModel):
    """Context samples that could not be associated with a CVE entry."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    entry: BenchmarkSampleMetadata | CleanVulSampleMetadata
    reason: str = Field(..., description="Reason for missing association")
    contexts: list[Context] = []
