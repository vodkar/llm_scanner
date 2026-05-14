"""Tests for the greedy budgeted selector."""

from pathlib import Path

import pytest

from models.context import CodeContextNode
from models.context_ranking import (
    BudgetedRankingConfig,
    EvidenceRole,
    RankingCandidate,
)
from services.ranking.evidence_ranking.budgeted_selector import (
    BudgetedSelector,
)


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def _candidate(
    *,
    identifier: str,
    file_path: str = "a.py",
    line_start: int = 1,
    line_end: int = 5,
    tokens: int,
    relevance: float,
    roles: frozenset[EvidenceRole] = frozenset({EvidenceRole.SINK}),
) -> RankingCandidate:
    return RankingCandidate(
        source_node=CodeContextNode(
            identifier=identifier,  # type: ignore[arg-type]
            file_path=Path(file_path),
            line_start=line_start,
            line_end=line_end,
            depth=1,
        ),
        roles=roles,
        estimated_token_count=tokens,
        clipped_line_start=line_start,
        clipped_line_end=line_end,
        relevance=relevance,
    )


def test_selects_highest_gain_first() -> None:
    """The candidate with the best gain must be selected first."""

    high = _candidate(identifier="hi", tokens=100, relevance=0.9, line_start=10, line_end=20)
    low = _candidate(identifier="lo", tokens=100, relevance=0.1, line_start=30, line_end=40)
    selector = BudgetedSelector(config=BudgetedRankingConfig())

    selected, _ = selector.select([high, low], token_budget=10_000)

    assert selected[0].source_node.identifier == "hi"


def test_respects_token_budget_with_safety_ratio() -> None:
    """A candidate exceeding budget × safety ratio must be rejected."""

    candidate = _candidate(identifier="big", tokens=1000, relevance=1.0)
    config = BudgetedRankingConfig(budget_safety_ratio=0.5)
    selector = BudgetedSelector(config=config)

    selected, rejected = selector.select([candidate], token_budget=1500)

    # Effective budget = 1500 * 0.5 = 750, candidate needs 1000 → rejected
    assert selected == []
    assert rejected == [candidate]


def test_includes_candidate_within_safety_budget() -> None:
    """A candidate within budget × safety ratio must be selected."""

    candidate = _candidate(identifier="ok", tokens=400, relevance=0.5)
    config = BudgetedRankingConfig(budget_safety_ratio=0.95)
    selector = BudgetedSelector(config=config)

    selected, rejected = selector.select([candidate], token_budget=500)

    # Effective budget = 500 * 0.95 = 475, candidate needs 400 → selected
    assert selected == [candidate]
    assert rejected == []


def test_role_coverage_bonus_prefers_diverse_roles() -> None:
    """When two candidates have similar relevance, the one adding NEW roles wins."""

    sink = _candidate(
        identifier="sink",
        tokens=100,
        relevance=0.5,
        roles=frozenset({EvidenceRole.SINK}),
        line_start=1,
        line_end=10,
    )
    duplicate_sink = _candidate(
        identifier="sink2",
        tokens=100,
        relevance=0.5,
        roles=frozenset({EvidenceRole.SINK}),
        line_start=20,
        line_end=30,
    )
    source = _candidate(
        identifier="source",
        tokens=100,
        relevance=0.5,
        roles=frozenset({EvidenceRole.SOURCE}),
        line_start=40,
        line_end=50,
    )
    selector = BudgetedSelector(config=BudgetedRankingConfig(role_coverage_bonus=0.5))

    selected, _ = selector.select(
        [sink, duplicate_sink, source],
        token_budget=10_000,
    )
    chosen_after_first = [c.source_node.identifier for c in selected[1:]]

    # After picking either sink first, source (new role) should outrank the duplicate sink
    assert "source" in chosen_after_first
    assert (
        chosen_after_first.index("source") < chosen_after_first.index("sink2")
        if ("sink2" in chosen_after_first)
        else True
    )


def test_redundancy_penalty_for_overlapping_lines() -> None:
    """A candidate overlapping a selected candidate's lines must be penalized."""

    a = _candidate(
        identifier="a",
        tokens=100,
        relevance=0.6,
        file_path="m.py",
        line_start=1,
        line_end=20,
    )
    b_overlapping = _candidate(
        identifier="b",
        tokens=100,
        relevance=0.55,
        file_path="m.py",
        line_start=5,  # overlaps with a
        line_end=25,
    )
    c_distinct = _candidate(
        identifier="c",
        tokens=100,
        relevance=0.50,
        file_path="other.py",
        line_start=1,
        line_end=20,
    )
    config = BudgetedRankingConfig(novelty_penalty=0.9)
    selector = BudgetedSelector(config=config)

    selected, _ = selector.select(
        [a, b_overlapping, c_distinct],
        token_budget=10_000,
    )
    order = [c.source_node.identifier for c in selected]

    # a is picked first (highest relevance). With novelty_penalty=0.9, b's
    # overlap should drop its gain below c's.
    assert order[0] == "a"
    assert order.index("c") < order.index("b")


def test_deterministic_tie_breaking() -> None:
    """Equal-gain candidates must break ties on (file_path, line_start)."""

    a = _candidate(
        identifier="a",
        tokens=100,
        relevance=0.5,
        file_path="zzz.py",
        line_start=10,
        line_end=20,
    )
    b = _candidate(
        identifier="b",
        tokens=100,
        relevance=0.5,
        file_path="aaa.py",
        line_start=10,
        line_end=20,
    )
    selector = BudgetedSelector(config=BudgetedRankingConfig(role_coverage_bonus=0.0))

    selected, _ = selector.select([a, b], token_budget=10_000)

    # aaa.py < zzz.py lexicographically
    assert selected[0].source_node.file_path == Path("aaa.py")


def test_zero_token_candidate_does_not_divide_by_zero() -> None:
    """A candidate with zero estimated tokens must not crash the selector."""

    candidate = _candidate(identifier="empty", tokens=0, relevance=0.5)
    selector = BudgetedSelector(config=BudgetedRankingConfig())

    selected, _ = selector.select([candidate], token_budget=1_000)

    assert selected == [candidate]


def test_empty_input_returns_empty_lists() -> None:
    selector = BudgetedSelector(config=BudgetedRankingConfig())

    selected, rejected = selector.select([], token_budget=1_000)

    assert selected == []
    assert rejected == []


def test_stops_when_no_remaining_candidate_fits() -> None:
    """Selection must terminate cleanly when remaining candidates exceed budget."""

    small = _candidate(identifier="small", tokens=100, relevance=0.9)
    big = _candidate(identifier="big", tokens=10_000, relevance=0.85)
    selector = BudgetedSelector(config=BudgetedRankingConfig(budget_safety_ratio=1.0))

    selected, rejected = selector.select([small, big], token_budget=500)

    assert selected == [small]
    assert rejected == [big]
