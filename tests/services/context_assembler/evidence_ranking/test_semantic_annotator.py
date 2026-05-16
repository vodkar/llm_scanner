"""Tests for the evidence-aware semantic annotator."""

from pathlib import Path

import pytest

from models.context import CodeContextNode
from models.context_ranking import EvidenceRole, RankingCandidate
from services.ranking.evidence_ranking.semantic_annotator import (
    KNOWN_CPG_EDGE_TYPES,
    SemanticAnnotator,
)
from services.snippet_reader import SnippetReaderService


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def _write(root: Path, relative: Path, content: str) -> None:
    file_path = root / relative
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content)


def _annotator(tmp_path: Path) -> SemanticAnnotator:
    reader = SnippetReaderService(project_root=tmp_path)
    return SemanticAnnotator(project_root=tmp_path, snippet_reader=reader)


def _candidate(
    *,
    file_path: Path,
    line_start: int = 1,
    line_end: int = 5,
    depth: int = 1,
    finding_evidence_score: float = 0.0,
    taint_score: float = 0.0,
    edge_depths: dict[str, int] | None = None,
) -> RankingCandidate:
    return RankingCandidate(
        source_node=CodeContextNode(
            identifier="x",  # type: ignore[arg-type]
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            depth=depth,
            finding_evidence_score=finding_evidence_score,
            taint_score=taint_score,
            edge_depths=edge_depths,
        ),
        roles=frozenset(),
        estimated_token_count=10,
        clipped_line_start=line_start,
        clipped_line_end=line_end,
    )


def test_depth_zero_node_is_root(tmp_path: Path) -> None:
    """A node at depth 0 must be tagged ROOT."""

    _write(tmp_path, Path("a.py"), "def main():\n    pass\n")
    candidate = _candidate(file_path=Path("a.py"), depth=0)

    [annotated] = _annotator(tmp_path).annotate([candidate])

    assert EvidenceRole.ROOT in annotated.roles


def test_sanitized_by_edge_yields_sanitizer_role(tmp_path: Path) -> None:
    """Edge depth via SANITIZED_BY must produce SANITIZER role."""

    _write(tmp_path, Path("a.py"), "x = 1\n")
    candidate = _candidate(file_path=Path("a.py"), edge_depths={"SANITIZED_BY": 1})

    [annotated] = _annotator(tmp_path).annotate([candidate])

    assert EvidenceRole.SANITIZER in annotated.roles


def test_flows_to_or_taint_yields_propagation_role(tmp_path: Path) -> None:
    """FLOWS_TO edge or non-zero taint_score must produce PROPAGATION role."""

    _write(tmp_path, Path("a.py"), "x = 1\n")
    cand_flows = _candidate(file_path=Path("a.py"), edge_depths={"FLOWS_TO": 2})
    cand_taint = _candidate(file_path=Path("a.py"), taint_score=0.7)

    annotated = _annotator(tmp_path).annotate([cand_flows, cand_taint])

    assert EvidenceRole.PROPAGATION in annotated[0].roles
    assert EvidenceRole.PROPAGATION in annotated[1].roles


def test_calls_edges_yield_caller_callee_roles(tmp_path: Path) -> None:
    """CALLS edge → CALLER; CALLED_BY edge → CALLEE."""

    _write(tmp_path, Path("a.py"), "x = 1\n")
    caller = _candidate(file_path=Path("a.py"), edge_depths={"CALLS": 1})
    callee = _candidate(file_path=Path("a.py"), edge_depths={"CALLED_BY": 1})

    annotated = _annotator(tmp_path).annotate([caller, callee])

    assert EvidenceRole.CALLER in annotated[0].roles
    assert EvidenceRole.CALLEE in annotated[1].roles


def test_lexical_sink_hint_yields_sink_role(tmp_path: Path) -> None:
    """A snippet containing a SINK_HINTS token must be tagged SINK."""

    _write(tmp_path, Path("a.py"), "import subprocess\nsubprocess.run(cmd)\n")
    candidate = _candidate(file_path=Path("a.py"), line_start=1, line_end=2)

    [annotated] = _annotator(tmp_path).annotate([candidate])

    assert EvidenceRole.SINK in annotated.roles


def test_lexical_source_hint_yields_source_role(tmp_path: Path) -> None:
    """A snippet containing a SOURCE_HINTS token must be tagged SOURCE."""

    _write(tmp_path, Path("a.py"), "value = request.args.get('q')\n")
    candidate = _candidate(file_path=Path("a.py"), line_start=1, line_end=1)

    [annotated] = _annotator(tmp_path).annotate([candidate])

    assert EvidenceRole.SOURCE in annotated.roles


def test_lexical_guard_hint_yields_guard_role(tmp_path: Path) -> None:
    """A snippet containing a GUARD_HINTS token must be tagged GUARD."""

    _write(tmp_path, Path("a.py"), "validated = sanitize(value)\n")
    candidate = _candidate(file_path=Path("a.py"), line_start=1, line_end=1)

    [annotated] = _annotator(tmp_path).annotate([candidate])

    assert EvidenceRole.GUARD in annotated.roles


def test_generated_file_yields_boilerplate(tmp_path: Path) -> None:
    """Files with generated markers must be tagged BOILERPLATE."""

    _write(tmp_path, Path("vendor_pb2.py"), "x = 1\n")
    candidate = _candidate(file_path=Path("vendor_pb2.py"))

    [annotated] = _annotator(tmp_path).annotate([candidate])

    assert EvidenceRole.BOILERPLATE in annotated.roles


def test_lexical_only_sets_lexical_fallback_only_true(tmp_path: Path) -> None:
    """Lexical-only evidence must mark the candidate as fallback (capped later)."""

    _write(tmp_path, Path("a.py"), "subprocess.run('x')\n")
    candidate = _candidate(file_path=Path("a.py"), depth=2)

    [annotated] = _annotator(tmp_path).annotate([candidate])

    assert EvidenceRole.SINK in annotated.roles
    assert annotated.lexical_fallback_only is True


def test_cpg_evidence_clears_fallback_flag(tmp_path: Path) -> None:
    """A node with CPG edges must NOT be flagged as lexical-only."""

    _write(tmp_path, Path("a.py"), "subprocess.run('x')\n")
    candidate = _candidate(
        file_path=Path("a.py"),
        depth=2,
        edge_depths={"FLOWS_TO": 2},
    )

    [annotated] = _annotator(tmp_path).annotate([candidate])

    assert annotated.lexical_fallback_only is False


def test_no_evidence_falls_back_to_enclosing_context_capped(tmp_path: Path) -> None:
    """Nodes with no positive signal default to ENCLOSING_CONTEXT and are capped."""

    _write(tmp_path, Path("a.py"), "import json\nresult = json.dumps({})\n")
    candidate = _candidate(file_path=Path("a.py"), line_start=1, line_end=2, depth=3)

    [annotated] = _annotator(tmp_path).annotate([candidate])

    assert annotated.roles == frozenset({EvidenceRole.ENCLOSING_CONTEXT})
    assert annotated.lexical_fallback_only is True


def test_analyzer_finding_without_other_signals_implies_sink(tmp_path: Path) -> None:
    """A high finding_evidence_score with no other rule firing implies SINK."""

    _write(tmp_path, Path("a.py"), "result = compute(x)\n")
    candidate = _candidate(
        file_path=Path("a.py"),
        line_start=1,
        line_end=1,
        finding_evidence_score=0.8,
    )

    [annotated] = _annotator(tmp_path).annotate([candidate])

    assert EvidenceRole.SINK in annotated.roles
    assert annotated.lexical_fallback_only is False


def test_cpg_confidence_proportional_to_edge_type_count(tmp_path: Path) -> None:
    """cpg_confidence = N / total CPG edge types."""

    _write(tmp_path, Path("a.py"), "x = 1\n")
    candidate = _candidate(
        file_path=Path("a.py"),
        edge_depths={"FLOWS_TO": 1, "CALLS": 2, "CONTAINS": 1},
    )

    [annotated] = _annotator(tmp_path).annotate([candidate])

    assert annotated.cpg_confidence == pytest.approx(3 / len(KNOWN_CPG_EDGE_TYPES))


def test_no_edges_yields_zero_cpg_confidence(tmp_path: Path) -> None:
    """A node without edge_depths must have cpg_confidence == 0."""

    _write(tmp_path, Path("a.py"), "x = 1\n")
    candidate = _candidate(file_path=Path("a.py"))

    [annotated] = _annotator(tmp_path).annotate([candidate])

    assert annotated.cpg_confidence == 0.0
