from pathlib import Path

from models.nodes import FunctionNode
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder
from tests.consts import SAMPLE_PROJECT_ROOT


def test_cpg_directory_builder__parses_multiple_files() -> None:
    """Validate directory parsing merges results from multiple .py files."""

    builder = CPGDirectoryBuilder(root=SAMPLE_PROJECT_ROOT)

    nodes, _edges = builder.build()

    main_file = SAMPLE_PROJECT_ROOT / "main.py"
    utils_file = SAMPLE_PROJECT_ROOT / "utils.py"

    assert any(
        isinstance(node, FunctionNode)
        and node.name == "run"
        and node.file_path == main_file
        for node in nodes.values()
    )
    assert any(
        isinstance(node, FunctionNode)
        and node.name == "greet"
        and node.file_path == utils_file
        for node in nodes.values()
    )
