"""Tests for handling non-UTF8 source files."""

from pathlib import Path

from models.nodes.code import FunctionNode
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder


def test_cpg_file_builder_handles_non_utf8_bytes(tmp_path: Path) -> None:
    """Ensure CPGFileBuilder tolerates invalid UTF-8 bytes."""

    file_path: Path = tmp_path / "invalid_bytes.py"
    payload: bytes = b"def foo():\n    return 1\n" + bytes([0xFF, 0xFE])
    file_path.write_bytes(payload)

    nodes, _edges = CPGFileBuilder(path=file_path).build()

    assert any(isinstance(node, FunctionNode) and node.name == "foo" for node in nodes.values())
