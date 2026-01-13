from typing import Any

from pydantic import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema


class NodeID(str):
    """Unique identifier for a node in the CPG."""

    @classmethod
    def create(cls, type_: str, name: str, path: str, start_byte: int) -> "NodeID":
        return cls(f"{type_.lower()}:{name}@{path}:{start_byte}")

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        return core_schema.no_info_after_validator_function(cls, handler(str))
