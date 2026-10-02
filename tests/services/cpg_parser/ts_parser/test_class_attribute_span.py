"""A class node spans its header plus the leading class-level attribute block."""

from pathlib import Path

from models.nodes.code import ClassNode
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder


def _class_span(tmp_path: Path, source: str, name: str) -> tuple[int, int]:
    file_path: Path = tmp_path / "mod.py"
    file_path.write_text(source, encoding="utf-8")
    nodes, _ = CPGFileBuilder(path=file_path, root=tmp_path).build()
    class_node = next(
        node for node in nodes.values() if isinstance(node, ClassNode) and node.name == name
    )
    return class_node.line_start, class_node.line_end


def test_class_span__includes_leading_attribute_assignments(tmp_path: Path) -> None:
    source: str = (
        "class StringAgg(Aggregate):\n"
        '    function = "STRING_AGG"\n'
        "    template = \"%(function)s(%(expressions)s, '%(delimiter)s')\"\n"
        "\n"
        "    def __init__(self, expression, delimiter):\n"
        "        super().__init__(expression, delimiter=delimiter)\n"
    )

    assert _class_span(tmp_path, source, "StringAgg") == (1, 3)


def test_class_span__stays_header_only_for_pass_body(tmp_path: Path) -> None:
    source: str = "class EmptyError(Exception):\n    pass\n"

    assert _class_span(tmp_path, source, "EmptyError") == (1, 1)


def test_class_span__stops_at_attribute_line_cap(tmp_path: Path) -> None:
    fields: str = "".join(f"    field_{index} = {index}\n" for index in range(100))
    source: str = f"class Realm(Model):\n{fields}"

    line_start, line_end = _class_span(tmp_path, source, "Realm")

    assert line_start == 1
    assert 1 < line_end < 100
