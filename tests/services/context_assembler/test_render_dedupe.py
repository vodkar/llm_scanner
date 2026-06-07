"""Tests for de-duplicating module-level boilerplate lines at render."""

from pathlib import Path

from models.base import NodeID
from models.context import CodeContextNode
from services.context_assembler.context_assembler import ContextAssemblerService
from services.ranking.ranking import DummyNodeRankingStrategy

_FILE_BODY = "logger = logging.getLogger(__name__)\ndef handler():\n    return None\n"


def _node(name: str, file_path: str) -> CodeContextNode:
    return CodeContextNode(
        identifier=NodeID(f"function:{name}"),
        node_kind="FunctionNode",
        name=name,
        file_path=Path(file_path),
        line_start=1,
        line_end=3,
        depth=0,
    )


def _service(tmp_path: Path) -> ContextAssemblerService:
    return ContextAssemblerService(
        project_root=tmp_path,
        context_repository=None,
        cached_neighborhood_edges=[],
        max_call_depth=2,
        token_budget=10_000,
        ranking_strategy=DummyNodeRankingStrategy(),
    )


def test_dedupes_repeated_logger_boilerplate(tmp_path: Path) -> None:
    """Identical `logger = logging.getLogger(...)` lines collapse to one."""

    (tmp_path / "a.py").write_text(_FILE_BODY, encoding="utf-8")
    (tmp_path / "b.py").write_text(_FILE_BODY, encoding="utf-8")

    context = _service(tmp_path).assemble_from_nodes(
        tmp_path, [_node("a", "a.py"), _node("b", "b.py")]
    )

    assert context.context_text.count("logger = logging.getLogger(__name__)") == 1


def test_non_boilerplate_duplicates_are_preserved(tmp_path: Path) -> None:
    """Ordinary repeated lines like `return None` are not de-duplicated."""

    (tmp_path / "a.py").write_text(_FILE_BODY, encoding="utf-8")
    (tmp_path / "b.py").write_text(_FILE_BODY, encoding="utf-8")

    context = _service(tmp_path).assemble_from_nodes(
        tmp_path, [_node("a", "a.py"), _node("b", "b.py")]
    )

    assert context.context_text.count("return None") == 2
