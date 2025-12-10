from enum import StrEnum
from pydantic import BaseModel, Field


class TaintSourceType(StrEnum):
    """Enumeration of supported taint sources."""

    HTTP_REQUEST = "http_request"
    FILE_INPUT = "file_input"
    USER_INPUT = "user_input"
    ENV_VAR = "env_var"


class TaintSinkType(StrEnum):
    """Enumeration of dangerous sink categories."""

    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "xss"


class SanitizerType(StrEnum):
    """Enumeration of sanitizer strategies."""

    ESCAPE = "escape"
    VALIDATION = "validation"
    ENCODING = "encoding"
    ALLOWLIST = "allowlist"


class SanitizerEffectiveness(StrEnum):
    """Effectiveness levels for sanitizers."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class SeverityLevel(StrEnum):
    """Severity scale for sink risk."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TaintSourceNode(BaseModel):
    """Represents an entry point of untrusted data."""

    source_type: TaintSourceType = Field(..., description="Kind of taint source")
    code_location: str = Field(
        ..., description="Variable or parameter name where data enters"
    )
    line_number: int = Field(
        ..., ge=1, description="Line number where the taint source appears"
    )
    file_path: str = Field(..., description="Path to the file containing the source")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence that this is a taint source"
    )
    detected_by: list[str] = Field(
        default_factory=list, description="Analyzers that detected this source"
    )


class TaintSinkNode(BaseModel):
    """Represents a location where tainted data can cause harm."""

    sink_type: TaintSinkType = Field(..., description="Danger category for the sink")
    function_name: str = Field(
        ..., description="Function or API at which the sink occurs"
    )
    line_number: int = Field(
        ..., ge=1, description="Line number where the sink is located"
    )
    file_path: str = Field(..., description="Path to the file containing the sink")
    severity: SeverityLevel = Field(..., description="Risk severity of the sink")
    detected_by: list[str] = Field(
        default_factory=list, description="Analyzers that detected this sink"
    )


class SanitizerNode(BaseModel):
    """Represents a sanitizer that cleans or validates data."""

    sanitizer_type: SanitizerType = Field(..., description="Type of sanitation applied")
    function_name: str = Field(..., description="Function implementing the sanitizer")
    effectiveness: SanitizerEffectiveness = Field(
        ..., description="Effectiveness of the sanitizer"
    )
    line_number: int = Field(
        ..., ge=1, description="Line number where the sanitizer is defined or used"
    )
    file_path: str = Field(..., description="Path to the file containing the sanitizer")
    detected_by: list[str] = Field(
        default_factory=list, description="Analyzers that detected this sanitizer"
    )
