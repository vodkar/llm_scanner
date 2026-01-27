from pathlib import Path
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema


class NodeID(str):
    """Unique identifier for a node in the CPG."""

    @classmethod
    def create(
        cls, type_: str, name: str, path: str | Path, start_byte: int
    ) -> "NodeID":
        return cls(f"{type_.lower()}:{name}@{path}:{start_byte}")

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        return core_schema.no_info_after_validator_function(cls, handler(str))


class StaticAnalyzerIssue(BaseModel):
    file: Path
    line_number: int
    reason: str


T = TypeVar("T", bound=StaticAnalyzerIssue)


class StaticAnalyzerReport(BaseModel, Generic[T]):
    issues: list[T]
