from typing import ClassVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
)

from models.context import SnippetSegment
from models.static_finding import StaticFinding


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

    commit_url: str = Field(..., description="Source commit URL")
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
    static_findings: list[StaticFinding] | None = Field(
        default=None,
        description="Analyzer findings located in `code` (only with --include-static-findings)",
    )
    source_map: list[SnippetSegment] | None = Field(
        default=None,
        description="`code` line → repo location mapping (only with --include-static-findings)",
    )

    _OPTIONAL_ENRICHMENT_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {"static_findings", "source_map"}
    )

    @model_serializer(mode="wrap")
    def _drop_absent_enrichment(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        """Omit enrichment keys that were not requested, keeping legacy output unchanged."""

        data: dict[str, object] = handler(self)
        return {
            key: value
            for key, value in data.items()
            if not (key in self._OPTIONAL_ENRICHMENT_FIELDS and value is None)
        }


class BenchmarkDataset(BaseModel):
    """Benchmark dataset with metadata and samples."""

    metadata: BenchmarkMetadata
    samples: list[BenchmarkSample]
