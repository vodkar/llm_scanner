"""Models for the evidence-aware budgeted ranking strategy.

This module defines the operating-point configuration (``BudgetedRankingConfig``),
the role taxonomy (``EvidenceRole``) and its priors, and the internal candidate
type (``RankingCandidate``) that the new ranking pipeline reasons about.

Methodology constants (role priors, role enum) live here as fixed values; only
the operating point in :class:`BudgetedRankingConfig` is intended to be tuned.
"""

from enum import StrEnum
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field

from models.context import CodeContextNode


class EvidenceRole(StrEnum):
    """Role tags assigned to context nodes by the semantic annotator.

    Ordering is fixed by ``ROLE_PRIORS``; tuning may not change which role is
    higher than which.
    """

    ROOT = "root"
    SINK = "sink"
    SOURCE = "source"
    SANITIZER = "sanitizer"
    GUARD = "guard"
    PROPAGATION = "propagation"
    DEFINITION = "definition"
    IMPORT = "import"
    CALLEE = "callee"
    CALLER = "caller"
    ENTRYPOINT = "entrypoint"
    ENCLOSING_CONTEXT = "enclosing_context"
    BOILERPLATE = "boilerplate"


ROLE_PRIORS: Final[dict[EvidenceRole, float]] = {
    EvidenceRole.ROOT: 1.00,
    EvidenceRole.SINK: 0.95,
    EvidenceRole.SOURCE: 0.90,
    EvidenceRole.SANITIZER: 0.85,
    EvidenceRole.GUARD: 0.85,
    EvidenceRole.PROPAGATION: 0.75,
    EvidenceRole.DEFINITION: 0.65,
    EvidenceRole.IMPORT: 0.60,
    EvidenceRole.CALLEE: 0.55,
    EvidenceRole.CALLER: 0.55,
    EvidenceRole.ENTRYPOINT: 0.55,
    EvidenceRole.ENCLOSING_CONTEXT: 0.50,
    EvidenceRole.BOILERPLATE: 0.15,
}


class BudgetedRankingConfig(BaseModel):
    """Compact operating-point configuration tuned by Optuna.

    Every field has a sensible default that produces reasonable behavior without
    tuning. Tuning Spec 2 will sample over the same fields. ``max_candidates_per_node``
    is reserved for Spec 2 (multi-candidate splitting) and unused in Spec 1.
    """

    model_config = ConfigDict(extra="forbid")

    depth_decay: float = Field(default=0.60, ge=0.0, le=2.0)
    context_strength: float = Field(default=0.45, ge=0.0, le=1.0)
    role_prior_temperature: float = Field(default=1.00, gt=0.0, le=5.0)
    finding_evidence_scale: float = Field(default=1.00, ge=0.0, le=5.0)
    taint_evidence_scale: float = Field(default=1.00, ge=0.0, le=5.0)
    cpg_role_evidence_scale: float = Field(default=1.00, ge=0.0, le=5.0)
    lexical_fallback_cap: float = Field(default=0.40, ge=0.0, le=1.0)
    token_cost_power: float = Field(default=0.35, ge=0.0, le=2.0)
    novelty_penalty: float = Field(default=0.40, ge=0.0, le=1.0)
    role_coverage_bonus: float = Field(default=0.20, ge=0.0, le=1.0)
    small_node_token_threshold: int = Field(default=220, ge=1)
    local_window_radius: int = Field(default=3, ge=0)
    max_candidates_per_node: int = Field(default=8, ge=1)
    budget_safety_ratio: float = Field(default=0.95, gt=0.0, le=1.0)

    @classmethod
    def from_yaml(cls, path: Path) -> "BudgetedRankingConfig":
        """Load a config from a YAML file."""

        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"budgeted ranking config YAML must be a mapping: {path}")
        return cls.model_validate(raw)

    def to_yaml(self, path: Path) -> None:
        """Persist this config to a YAML file."""

        path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = self.model_dump()
        path.write_text(
            yaml.safe_dump(payload, sort_keys=False, default_flow_style=False),
            encoding="utf-8",
        )


class RankingCandidate(BaseModel):
    """One ranking candidate the new pipeline reasons about (one per source node).

    The pipeline mutates ``distance_score``, ``context_score``, ``relevance``,
    ``cpg_confidence``, and ``lexical_fallback_only`` as candidates flow through
    the scorers; they are initialized to neutral values so that Pydantic
    validation succeeds when a candidate is first constructed.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    source_node: CodeContextNode
    roles: frozenset[EvidenceRole]
    estimated_token_count: int = Field(..., ge=0)
    clipped_line_start: int = Field(..., ge=1)
    clipped_line_end: int = Field(..., ge=1)
    distance_score: float = Field(default=0.0, ge=0.0, le=1.0)
    context_score: float = Field(default=0.0, ge=0.0, le=1.0)
    relevance: float = Field(default=0.0, ge=0.0, le=1.0)
    cpg_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    lexical_fallback_only: bool = False
