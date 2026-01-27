from enum import StrEnum


class NodeType(StrEnum):
    """Enumeration of generic node categories."""

    FUNCTION = "Function"
    CLASS = "Class"
    MODULE = "Module"
