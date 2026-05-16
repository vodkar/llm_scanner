"""Tests for the noisy-OR evidence scorer."""

from pathlib import Path

import pytest

from models.context import CodeContextNode
from models.context_ranking import (
    ROLE_PRIORS,
    BudgetedRankingConfig,
    EvidenceRole,
    RankingCandidate,
)
from services.ranking.evidence_ranking.evidence_scorer import (
    clamp,
    noisy_or,
    score,
)


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def _candidate(
    *,
    roles: frozenset[EvidenceRole],
    finding_evidence_score: float = 0.0,
    taint_score: float = 0.0,
    distance_score: float = 1.0,
    context_score: float = 0.0,
    cpg_confidence: float = 0.0,
    lexical_fallback_only: bool = False,
) -> RankingCandidate:
    return RankingCandidate(
        source_node=CodeContextNode(
            identifier="x",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=1,
            line_end=1,
            depth=1,
            finding_evidence_score=finding_evidence_score,
            taint_score=taint_score,
        ),
        roles=roles,
        estimated_token_count=10,
        clipped_line_start=1,
        clipped_line_end=1,
        distance_score=distance_score,
        context_score=context_score,
        cpg_confidence=cpg_confidence,
        lexical_fallback_only=lexical_fallback_only,
    )


def test_clamp_bounds_to_unit_interval() -> None:
    assert clamp(-0.5) == 0.0
    assert clamp(0.5) == 0.5
    assert clamp(1.5) == 1.0


def test_noisy_or_zero_for_empty_input() -> None:
    assert noisy_or([]) == 0.0


def test_noisy_or_combines_via_complement_product() -> None:
    """noisy_or([a, b]) == 1 - (1-a)(1-b)."""

    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)
    assert noisy_or([1.0, 0.5]) == pytest.approx(1.0)


def test_noisy_or_clamps_inputs_before_combining() -> None:
    assert noisy_or([1.5, -0.5]) == pytest.approx(1.0)


def test_score_zero_when_no_signals() -> None:
    """A candidate with no evidence at all must score 0."""

    cand = _candidate(roles=frozenset())

    assert score(cand, BudgetedRankingConfig()) == 0.0


def test_score_uses_finding_evidence() -> None:
    """High finding_evidence_score must dominate the score."""

    cand = _candidate(roles=frozenset({EvidenceRole.SINK}), finding_evidence_score=0.9)

    assert score(cand, BudgetedRankingConfig()) > 0.5


def test_score_uses_taint_evidence() -> None:
    """Taint evidence must influence the score even without findings."""

    cand = _candidate(roles=frozenset({EvidenceRole.PROPAGATION}), taint_score=0.7)

    assert score(cand, BudgetedRankingConfig()) > 0.0


def test_role_prior_temperature_compresses_lower_roles() -> None:
    """Higher temperature compresses (lifts) lower-prior roles toward higher ones."""

    cand_low = _candidate(roles=frozenset({EvidenceRole.BOILERPLATE}), distance_score=1.0)

    score_temp1 = score(cand_low, BudgetedRankingConfig(role_prior_temperature=1.0))
    score_temp_low = score(cand_low, BudgetedRankingConfig(role_prior_temperature=0.5))

    # temp < 1 lifts the prior toward 1, increasing the role evidence
    assert score_temp_low > score_temp1


def test_lexical_fallback_caps_relevance() -> None:
    """Lexical-fallback candidates must be capped at lexical_fallback_cap."""

    cand = _candidate(
        roles=frozenset({EvidenceRole.SINK}),
        finding_evidence_score=1.0,
        taint_score=1.0,
        cpg_confidence=1.0,
        lexical_fallback_only=True,
    )
    config = BudgetedRankingConfig(lexical_fallback_cap=0.4)

    assert score(cand, config) <= 0.4 + 1e-9


def test_score_in_unit_interval() -> None:
    """All inputs being maxed out, the result must still be in [0, 1]."""

    cand = _candidate(
        roles=frozenset({EvidenceRole.ROOT}),
        finding_evidence_score=1.0,
        taint_score=1.0,
        distance_score=1.0,
        context_score=1.0,
        cpg_confidence=1.0,
    )

    result = score(cand, BudgetedRankingConfig())

    assert 0.0 <= result <= 1.0


def test_role_prior_temperature_one_uses_base_priors() -> None:
    """At temperature=1, effective role prior equals the base prior (identity)."""

    role = EvidenceRole.SINK
    cand = _candidate(
        roles=frozenset({role}),
        distance_score=1.0,
        cpg_confidence=0.0,
    )
    cfg = BudgetedRankingConfig(
        finding_evidence_scale=0.0,
        taint_evidence_scale=0.0,
        cpg_role_evidence_scale=1.0,
        context_strength=0.0,
        role_prior_temperature=1.0,
    )

    # With everything zeroed except role evidence, score = ROLE_PRIORS[SINK] * 1 (distance)
    assert score(cand, cfg) == pytest.approx(ROLE_PRIORS[role])
