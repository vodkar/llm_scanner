from models.base import StaticAnalyzerIssue
from models.nodes.taint import TaintSinkType, TaintSourceType

FLOW_CODE_TO_SINK_TYPE: dict[int, TaintSinkType] = {
    5001: TaintSinkType.SQL_INJECTION,
    5002: TaintSinkType.COMMAND_INJECTION,
    5003: TaintSinkType.PATH_TRAVERSAL,
    5004: TaintSinkType.XSS,
}

# Ordered most-specific first to avoid misclassification
SOURCE_KEYWORD_MAP: list[tuple[str, TaintSourceType]] = [
    ("os.environ", TaintSourceType.ENV_VAR),
    ("environ", TaintSourceType.ENV_VAR),
    ("sys.argv", TaintSourceType.ENV_VAR),
    ("stdin", TaintSourceType.USER_INPUT),
    ("input(", TaintSourceType.USER_INPUT),
    ("request", TaintSourceType.HTTP_REQUEST),
    ("flask", TaintSourceType.HTTP_REQUEST),
    ("django", TaintSourceType.HTTP_REQUEST),
    ("fastapi", TaintSourceType.HTTP_REQUEST),
    ("open(", TaintSourceType.FILE_INPUT),
    ("file", TaintSourceType.FILE_INPUT),
]


def infer_source_type(description: str) -> TaintSourceType | None:
    """Infer TaintSourceType from a Pysa finding description string."""
    lower = description.lower()
    for keyword, source_type in SOURCE_KEYWORD_MAP:
        if keyword.lower() in lower:
            return source_type
    return None


class PysaIssue(StaticAnalyzerIssue):
    """A single taint flow reported by Pysa."""

    flow_code: int
    flow_name: str
    sink_type: TaintSinkType
    source_type: TaintSourceType | None
    column_number: int
    stop_line: int
    stop_column: int
