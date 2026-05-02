"""Tests for ranking coefficient model and YAML persistence."""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest
from pydantic import ValidationError

from services.context_assembler.ranking_config import RankingCoefficients

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
CURRENT_YAML: Final[Path] = PROJECT_ROOT / "config" / "ranking_coefficients_current.yaml"
CPG_STRUCTURAL_YAML: Final[Path] = (
    PROJECT_ROOT / "config" / "ranking_coefficients_cpg_structural.yaml"
)


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def test_from_yaml_loads_current_config() -> None:
    """The shipped current.yaml must parse into a valid coefficients object."""

    coefficients = RankingCoefficients.from_yaml(CURRENT_YAML)

    assert coefficients.combiner.finding_evidence == 0.25
    assert coefficients.combiner.security_path == 0.20
    assert coefficients.combiner.taint == 0.20
    assert coefficients.combiner.context == 0.35
    assert coefficients.context_breakdown.depth == 0.45
    assert coefficients.hop_decay_by_depth == {0: 1.0, 1: 0.85, 2: 0.70, 3: 0.55, 4: 0.45}
    assert coefficients.hop_decay_default == 0.35
    assert coefficients.severity_scores.high == 1.00
    assert coefficients.render_kind_scores["FunctionNode"] == 1.00
    assert coefficients.security_boost_weight == 1.00
    assert coefficients.security_tier_threshold == 0.5
    assert coefficients.edge_type_weights.flows_to == 1.00
    assert coefficients.edge_type_weights.contains == 0.35
    assert coefficients.edge_decay_rates.flows_to == 0.85
    assert coefficients.sanitizer_bypass_bonus == 0.25
    assert coefficients.source_sink_path_max_depth == 4


def test_from_yaml_loads_cpg_structural_config() -> None:
    """The shipped cpg_structural.yaml must parse into a valid coefficients object."""

    coefficients = RankingCoefficients.from_yaml(CPG_STRUCTURAL_YAML)

    assert coefficients.context_breakdown.depth == 0.55
    assert coefficients.security_path_breakdown.path_evidence == 0.35
    assert coefficients.edge_type_weights.flows_to == 1.00


def test_round_trip_preserves_values(tmp_path: Path) -> None:
    """Saving and loading coefficients must produce an identical object."""

    original = RankingCoefficients.from_yaml(CURRENT_YAML)
    out_path = tmp_path / "roundtrip.yaml"
    original.to_yaml(out_path)

    reloaded = RankingCoefficients.from_yaml(out_path)

    assert reloaded.model_dump() == original.model_dump()


def test_to_yaml_creates_parent_directories(tmp_path: Path) -> None:
    """Saving into a nested path must create intermediate directories."""

    coefficients = RankingCoefficients.from_yaml(CURRENT_YAML)
    out_path = tmp_path / "nested" / "dir" / "coeffs.yaml"

    coefficients.to_yaml(out_path)

    assert out_path.exists()


def test_extra_fields_forbidden(tmp_path: Path) -> None:
    """Unknown top-level keys must raise validation errors, not silently drop."""

    yaml_text = CURRENT_YAML.read_text() + "\nunknown_extra_key: 1.0\n"
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(yaml_text)

    with pytest.raises(ValidationError):
        RankingCoefficients.from_yaml(bad_yaml)


def test_out_of_range_weight_rejected(tmp_path: Path) -> None:
    """Weights outside [0, 1] (for bounded fields) must be rejected."""

    yaml_text = CURRENT_YAML.read_text().replace("finding_evidence: 0.25", "finding_evidence: 1.5")
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(yaml_text)

    with pytest.raises(ValidationError):
        RankingCoefficients.from_yaml(bad_yaml)


def test_from_yaml_requires_mapping(tmp_path: Path) -> None:
    """A YAML file containing a scalar or list must raise a clear error."""

    bad_yaml = tmp_path / "scalar.yaml"
    bad_yaml.write_text("just a string\n")

    with pytest.raises(ValueError, match="must be a mapping"):
        RankingCoefficients.from_yaml(bad_yaml)
