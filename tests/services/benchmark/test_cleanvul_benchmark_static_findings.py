"""Static-findings enrichment in the CleanVul benchmark service."""

from pathlib import Path

from models.bandit_report import IssueSeverity
from models.base import NodeID
from models.benchmark.cleanvul import CleanVulEntry
from models.context import CodeContextNode, Context, FileSpans
from models.nodes.finding import BanditFindingNode
from services.benchmark.cleanvul_benchmark import CleanVulBenchmarkService, _SharedContextInputs
from services.benchmark.prepared_sample import (
    PreparedSample,
    load_prepared_sample,
    save_prepared_sample,
)
from services.benchmark.static_findings import attach_findings
from services.context_assembler.source_map import build_source_map
from services.ranking.ranking import DummyNodeRankingStrategy

_FINDING = BanditFindingNode(
    file=Path("app.py"),
    line_number=2,
    cwe_id=78,
    severity=IssueSeverity.HIGH,
    rule_id="B605",
    reason="shell",
)


def _entry() -> CleanVulEntry:
    return CleanVulEntry(
        commit_url="https://github.com/o/r/commit/abc",
        repo_url="https://github.com/o/r",
        fix_hash="abc",
        file_name="app.py",
        func_code="def run(cmd):\n    os.system(cmd)",
        files_spans=[FileSpans(Path("app.py"), [(1, 2)])],
        vulnerability_score=4,
        is_vulnerable=True,
    )


def _service(tmp_path: Path, *, include: bool) -> CleanVulBenchmarkService:
    return CleanVulBenchmarkService.model_validate(
        {
            "dataset_path": tmp_path / "cleanvul.csv",
            "output_dir": tmp_path / "out",
            "repo_cache_dir": tmp_path / "repos",
            "sample_count": 2,
            "max_call_depth": 2,
            "token_budget": 10_000,
            "include_static_findings": include,
            "strategy_factories": {"dummy": lambda _p: DummyNodeRankingStrategy()},
        }
    )


def _context_with_findings() -> Context:
    source_map = build_source_map(
        [(Path("app.py"), 1, "def run(cmd):"), (Path("app.py"), 2, "    os.system(cmd)")]
    )
    return Context(
        description="d",
        context_text="def run(cmd):\n    os.system(cmd)",
        token_count=5,
        source_map=source_map,
        static_findings=attach_findings([_FINDING], source_map, []),
    )


def test_render_attaches_findings(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def run(cmd):\n    os.system(cmd)\n", encoding="utf-8")
    root = CodeContextNode(
        identifier=NodeID("function:run"),
        node_kind="FunctionNode",
        name="run",
        file_path=Path("app.py"),
        line_start=1,
        line_end=2,
        depth=0,
    )
    service = _service(tmp_path, include=True)

    contexts = service._render_contexts_from_shared_inputs(
        repo_path=tmp_path,
        context_repository=None,
        strategies={"dummy": DummyNodeRankingStrategy()},
        shared_inputs=_SharedContextInputs(
            root_ids=[str(root.identifier)],
            plain_context_nodes=[root],
            edge_path_context_nodes=[],
            taint_scores={},
        ),
        cached_neighborhood_edges=[],
        findings=[_FINDING],
    )

    [finding] = contexts["dummy"].static_findings
    assert finding.snippet_line == 2
    assert finding.is_root is True
    assert contexts["dummy"].context_text.split("\n")[finding.snippet_line - 1] == (
        "    os.system(cmd)"
    )


def test_to_sample_includes_enrichment_when_enabled(tmp_path: Path) -> None:
    service = _service(tmp_path, include=True)
    context = _context_with_findings()
    assert len(context.static_findings) == 1

    sample = service._to_sample(_entry(), context, "s-1")

    assert sample.source_map == context.source_map
    assert sample.static_findings == context.static_findings


def test_to_sample_omits_enrichment_when_disabled(tmp_path: Path) -> None:
    service = _service(tmp_path, include=False)

    sample = service._to_sample(_entry(), _context_with_findings(), "s-1")
    dumped = sample.model_dump(by_alias=True)

    assert "static_findings" not in dumped
    assert "source_map" not in dumped


def test_prepared_sample_round_trips_findings(tmp_path: Path) -> None:
    sample = PreparedSample(
        entry=_entry(),
        repo_path=tmp_path,
        target_hash="abc",
        sample_id="s-1",
        root_ids=[],
        plain_context_nodes=[],
        edge_path_context_nodes=[],
        taint_scores={},
        neighborhood_edges=[],
        path_fill_edge_types=(),
        traversal_relationship_types=(),
        static_findings=[_FINDING],
        cache_key="k",
    )

    save_prepared_sample(tmp_path, sample)
    loaded = load_prepared_sample(tmp_path, "k")

    assert loaded is not None
    assert loaded.static_findings == [_FINDING]
    assert isinstance(loaded.static_findings[0], BanditFindingNode)
