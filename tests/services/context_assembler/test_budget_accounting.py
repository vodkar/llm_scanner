"""The token budget applies to the rendered text, markers and completed headers included."""

from pathlib import Path

from models.base import NodeID
from models.context import CodeContextNode
from services.context_assembler.context_assembler import ContextAssemblerService
from services.ranking.ranking import DummyNodeRankingStrategy


def _line_count(text: str) -> int:
    return len(text.splitlines())


def _assemble(tmp_path: Path, token_budget: int) -> str:
    (tmp_path / "a.py").write_text("def root():\n    return Helper().run()\n", encoding="utf-8")
    (tmp_path / "b.py").write_text(
        "class Helper:\n    def run(self):\n        return 1\n", encoding="utf-8"
    )
    root = CodeContextNode(
        identifier=NodeID("function:root"),
        node_kind="FunctionNode",
        name="root",
        file_path=Path("a.py"),
        line_start=1,
        line_end=2,
        depth=0,
    )
    method = CodeContextNode(
        identifier=NodeID("function:run"),
        node_kind="FunctionNode",
        name="run",
        file_path=Path("b.py"),
        line_start=2,
        line_end=3,
        depth=1,
    )
    service = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=None,
        cached_neighborhood_edges=[(root.identifier, method.identifier, "CALLS")],
        max_call_depth=3,
        token_budget=token_budget,
        token_estimator=_line_count,
        ranking_strategy=DummyNodeRankingStrategy(),
    )
    return service.assemble_from_nodes(tmp_path, [root, method]).context_text


def test_context_is_left_out_when_rendered_text_would_exceed_budget(tmp_path: Path) -> None:
    text = _assemble(tmp_path, token_budget=6)

    assert _line_count(text) <= 6
    assert "def run(self):" not in text


def test_context_is_included_when_rendered_text_fits_budget(tmp_path: Path) -> None:
    text = _assemble(tmp_path, token_budget=8)

    assert _line_count(text) <= 8
    assert "class Helper:" in text
    assert "def run(self):" in text
