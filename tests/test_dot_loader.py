from __future__ import annotations

from pathlib import Path

from repositories.dot_loader import DotLoader
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.consts import TEST_DATA_DIR


def test_dot_loader_writes_deterministic_output(tmp_path: Path) -> None:
    src_file = (TEST_DATA_DIR / "calls" / "function_calls.py").resolve()
    nodes, edges = CPGFileBuilder(path=src_file).build()

    assert nodes
    assert edges

    out1 = tmp_path / "graph1.dot"
    out2 = tmp_path / "graph2.dot"

    DotLoader(out1).load(nodes, edges)
    DotLoader(out2).load(nodes, edges)

    text1 = out1.read_text(encoding="utf-8")
    text2 = out2.read_text(encoding="utf-8")

    assert text1 == text2
    assert "digraph" in text1
    assert "function_calls.py" in text1
    assert "bar" in text1
    assert "foo" in text1
    assert "->" in text1
