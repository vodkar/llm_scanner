"""Evidence scorer — composes signals into a single relevance value via noisy-OR.

Implements the formula prescribed by TASK.md §5: per-signal scaling, role-prior
temperature shaping, and a final lexical-fallback cap. All inputs are clamped
to ``[0, 1]`` before composition, so the output is always in ``[0, 1]``.
"""

from collections.abc import Iterable

from models.context_ranking import (
    ROLE_PRIORS,
    BudgetedRankingConfig,
    RankingCandidate,
)


def clamp(value: float) -> float:
    """Clamp a float to the unit interval."""

    return min(1.0, max(0.0, value))


def noisy_or(values: Iterable[float]) -> float:
    """Combine independent probabilities using the noisy-OR rule.

    ``noisy_or([a, b, ...]) = 1 - prod(1 - clamp(v))``.
    """

    product = 1.0
    consumed = False
    for value in values:
        product *= 1.0 - clamp(value)
        consumed = True
    if not consumed:
        return 0.0
    return 1.0 - product


def score(candidate: RankingCandidate, config: BudgetedRankingConfig) -> float:
    """Compute the relevance score for a single annotated, distance-scored candidate."""

    finding_evidence = clamp(
        config.finding_evidence_scale * candidate.source_node.finding_evidence_score
    )
    taint_evidence = clamp(config.taint_evidence_scale * candidate.source_node.taint_score)

    base_role_prior = max((ROLE_PRIORS[r] for r in candidate.roles), default=0.0)
    effective_role_prior = base_role_prior**config.role_prior_temperature
    role_evidence = clamp(
        config.cpg_role_evidence_scale * effective_role_prior * candidate.distance_score
    )

    security_evidence = noisy_or(
        [finding_evidence, taint_evidence, role_evidence, candidate.cpg_confidence]
    )
    relevance = noisy_or([security_evidence, config.context_strength * candidate.context_score])

    if candidate.lexical_fallback_only:
        relevance = min(relevance, config.lexical_fallback_cap)

    return relevance
