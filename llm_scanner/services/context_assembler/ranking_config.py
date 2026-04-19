"""Tunable coefficient configuration for context-node ranking strategies."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


class CombinerWeights(BaseModel):
    """Top-level weights that combine the four component scores into a final score."""

    model_config = ConfigDict(extra="forbid")

    finding_evidence: float = Field(..., ge=0.0, le=1.0)
    security_path: float = Field(..., ge=0.0, le=1.0)
    taint: float = Field(..., ge=0.0, le=1.0)
    context: float = Field(..., ge=0.0, le=1.0)


class ContextBreakdown(BaseModel):
    """Sub-weights inside the context component score."""

    model_config = ConfigDict(extra="forbid")

    depth: float = Field(..., ge=0.0, le=1.0)
    structure: float = Field(..., ge=0.0, le=1.0)
    file_prior: float = Field(..., ge=0.0, le=1.0)


class FindingEvidenceBreakdown(BaseModel):
    """Sub-weights inside the finding-evidence score."""

    model_config = ConfigDict(extra="forbid")

    severity: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    agreement: float = Field(..., ge=0.0, le=1.0)


class SecurityPathBreakdown(BaseModel):
    """Sub-weights inside the security-path score."""

    model_config = ConfigDict(extra="forbid")

    sink: float = Field(..., ge=0.0, le=1.0)
    source: float = Field(..., ge=0.0, le=1.0)
    guard: float = Field(..., ge=0.0, le=1.0)
    path_evidence: float = Field(..., ge=0.0, le=1.0)
    high_risk_cwe_evidence_base: float = Field(..., ge=0.0, le=1.0)


class StructureBreakdown(BaseModel):
    """Sub-weights inside the structure score."""

    model_config = ConfigDict(extra="forbid")

    render_kind: float = Field(..., ge=0.0, le=1.0)
    repeat_bonus: float = Field(..., ge=0.0, le=1.0)


class FilePriorBreakdown(BaseModel):
    """Sub-weights inside the file-prior score."""

    model_config = ConfigDict(extra="forbid")

    same_file: float = Field(..., ge=0.0, le=1.0)
    same_module: float = Field(..., ge=0.0, le=1.0)
    generated_penalty: float = Field(..., ge=0.0, le=1.0)


class SeverityScoreMap(BaseModel):
    """Score per severity tier (low/medium/high)."""

    model_config = ConfigDict(extra="forbid")

    low: float = Field(..., ge=0.0, le=1.0)
    medium: float = Field(..., ge=0.0, le=1.0)
    high: float = Field(..., ge=0.0, le=1.0)


class EdgeTypeWeights(BaseModel):
    """Per-edge-type relevance weights used by the CPG-structural strategy."""

    model_config = ConfigDict(extra="forbid")

    flows_to: float = Field(..., ge=0.0, le=1.0)
    sanitized_by: float = Field(..., ge=0.0, le=1.0)
    calls: float = Field(..., ge=0.0, le=1.0)
    called_by: float = Field(..., ge=0.0, le=1.0)
    defined_by: float = Field(..., ge=0.0, le=1.0)
    used_by: float = Field(..., ge=0.0, le=1.0)
    contains: float = Field(..., ge=0.0, le=1.0)


class EdgeDecayRates(BaseModel):
    """Per-edge-type exponential decay rates used by the CPG-structural strategy."""

    model_config = ConfigDict(extra="forbid")

    flows_to: float = Field(..., ge=0.0, le=1.0)
    sanitized_by: float = Field(..., ge=0.0, le=1.0)
    calls: float = Field(..., ge=0.0, le=1.0)
    called_by: float = Field(..., ge=0.0, le=1.0)
    defined_by: float = Field(..., ge=0.0, le=1.0)
    used_by: float = Field(..., ge=0.0, le=1.0)
    contains: float = Field(..., ge=0.0, le=1.0)


class RankingCoefficients(BaseModel):
    """All tunable weights for context-node ranking strategies.

    Loaded from YAML. The defaults in ``config/ranking_coefficients_current.yaml``
    reproduce the behavior of the hand-tuned ``Final`` constants in ``ranking.py``.
    """

    model_config = ConfigDict(extra="forbid")

    combiner: CombinerWeights
    context_breakdown: ContextBreakdown
    finding_evidence_breakdown: FindingEvidenceBreakdown
    security_path_breakdown: SecurityPathBreakdown
    structure_breakdown: StructureBreakdown
    file_prior_breakdown: FilePriorBreakdown

    hop_decay_by_depth: dict[int, float] = Field(
        ..., description="Depth -> decay multiplier for generic BFS traversal"
    )
    hop_decay_default: float = Field(..., ge=0.0, le=1.0)

    severity_scores: SeverityScoreMap
    confidence_by_severity: SeverityScoreMap
    render_kind_scores: dict[str, float]

    security_boost_weight: float = Field(..., ge=0.0)
    security_tier_threshold: float = Field(..., ge=0.0, le=2.0)

    edge_type_weights: EdgeTypeWeights
    edge_decay_rates: EdgeDecayRates
    sanitizer_bypass_bonus: float = Field(..., ge=0.0, le=1.0)
    sanitizer_presence_damp: float = Field(..., ge=0.0, le=1.0)
    source_sink_path_max_depth: int = Field(..., ge=0)

    @classmethod
    def from_yaml(cls, path: Path) -> RankingCoefficients:
        """Load coefficients from a YAML file.

        Args:
            path: Path to the YAML coefficients file.

        Returns:
            Parsed coefficients object.
        """

        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"coefficients YAML must be a mapping: {path}")
        return cls.model_validate(raw)

    def to_yaml(self, path: Path) -> None:
        """Persist coefficients to a YAML file.

        Args:
            path: Destination YAML file path.
        """

        path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = self.model_dump()
        path.write_text(
            yaml.safe_dump(payload, sort_keys=False, default_flow_style=False),
            encoding="utf-8",
        )
