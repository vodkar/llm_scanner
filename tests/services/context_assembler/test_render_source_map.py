"""The rendered snippet must carry an exact snippet → repo source map."""

from pathlib import Path

from models.base import NodeID
from models.context import CodeContextNode, Context
from services.context_assembler.context_assembler import ContextAssemblerService
from services.context_assembler.source_map import resolve_snippet_line
from services.ranking.ranking import DummyNodeRankingStrategy

_A_BODY = (
    "logger = logging.getLogger(__name__)\n"
    "def handler(cmd):\n"
    "\n"
    "    # only a comment\n"
    "    os.system(cmd)  # trailing comment\n"
)
_B_BODY = "logger = logging.getLogger(__name__)\ndef other():\n    return eval(x)\n"


def _node(name: str, file_path: str, line_end: int) -> CodeContextNode:
    return CodeContextNode(
        identifier=NodeID(f"function:{name}"),
        node_kind="FunctionNode",
        name=name,
        file_path=Path(file_path),
        line_start=1,
        line_end=line_end,
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


def _assemble(tmp_path: Path) -> Context:
    (tmp_path / "a.py").write_text(_A_BODY, encoding="utf-8")
    (tmp_path / "b.py").write_text(_B_BODY, encoding="utf-8")
    return _service(tmp_path).assemble_from_nodes(
        tmp_path, [_node("handler", "a.py", 5), _node("other", "b.py", 3)]
    )


def test_every_mapped_line_matches_sanitized_repo_line(tmp_path: Path) -> None:
    context = _assemble(tmp_path)
    code_lines = context.context_text.split("\n")

    covered = sum(len(segment.repo_lines) for segment in context.source_map)
    assert covered == len(code_lines)
    for segment in context.source_map:
        repo_text = (tmp_path / segment.file_path).read_text(encoding="utf-8").splitlines()
        for offset, repo_line in enumerate(segment.repo_lines):
            expected = ContextAssemblerService._sanitize_line(repo_text[repo_line - 1])
            assert code_lines[segment.snippet_line_start - 1 + offset] == expected


def test_source_map_skips_blank_and_comment_lines(tmp_path: Path) -> None:
    context = _assemble(tmp_path)

    assert "" not in context.context_text.split("\n")
    assert "# only a comment" not in context.context_text
    assert resolve_snippet_line(context.source_map, Path("a.py"), 3) is None
    assert resolve_snippet_line(context.source_map, Path("a.py"), 4) is None


def test_duplicate_boilerplate_is_mapped_once(tmp_path: Path) -> None:
    context = _assemble(tmp_path)

    first = resolve_snippet_line(context.source_map, Path("a.py"), 1)
    second = resolve_snippet_line(context.source_map, Path("b.py"), 1)
    assert (first is None) != (second is None)
    sink = resolve_snippet_line(context.source_map, Path("a.py"), 5)
    assert sink is not None
    assert context.context_text.split("\n")[sink - 1] == "    os.system(cmd)"


def test_empty_render_has_empty_source_map(tmp_path: Path) -> None:
    context = _service(tmp_path).assemble_from_nodes(tmp_path, [])

    assert context.context_text == ""
    assert context.source_map == []


def test_file_with_form_feed_is_not_mapped(tmp_path: Path) -> None:
    """splitlines() treats \\x0c as a break but analyzers do not; never misattach."""

    (tmp_path / "ff.py").write_text(
        "import os\n\x0c\ndef f(cmd):\n    y = cmd\n    os.system(cmd)\n", encoding="utf-8"
    )
    context = _service(tmp_path).assemble_from_nodes(tmp_path, [_node("f", "ff.py", 7)])

    assert "os.system(cmd)" in context.context_text
    assert resolve_snippet_line(context.source_map, Path("ff.py"), 5) is None
    assert context.source_map == []
