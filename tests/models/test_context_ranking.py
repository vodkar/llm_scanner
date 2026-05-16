"""Tests for the BudgetedRankingConfig model and EvidenceRole role priors."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from models.context import CodeContextNode
from models.context_ranking import (
    ROLE_PRIORS,
    BudgetedRankingConfig,
    EvidenceRole,
    RankingCandidate,
)


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def test_evidence_role_values_match_task_md_spec() -> None:
    """All 13 evidence roles from TASK.md §3 must exist."""

    expected = {
        "ROOT",
        "SINK",
        "SOURCE",
        "SANITIZER",
        "GUARD",
        "PROPAGATION",
        "DEFINITION",
        "IMPORT",
        "CALLEE",
        "CALLER",
        "ENTRYPOINT",
        "ENCLOSING_CONTEXT",
        "BOILERPLATE",
    }
    assert {role.name for role in EvidenceRole} == expected


def test_role_priors_match_task_md_spec() -> None:
    """ROLE_PRIORS values must match the table in TASK.md §3 exactly."""

    assert ROLE_PRIORS[EvidenceRole.ROOT] == 1.00
    assert ROLE_PRIORS[EvidenceRole.SINK] == 0.95
    assert ROLE_PRIORS[EvidenceRole.SOURCE] == 0.90
    assert ROLE_PRIORS[EvidenceRole.SANITIZER] == 0.85
    assert ROLE_PRIORS[EvidenceRole.GUARD] == 0.85
    assert ROLE_PRIORS[EvidenceRole.PROPAGATION] == 0.75
    assert ROLE_PRIORS[EvidenceRole.DEFINITION] == 0.65
    assert ROLE_PRIORS[EvidenceRole.IMPORT] == 0.60
    assert ROLE_PRIORS[EvidenceRole.CALLEE] == 0.55
    assert ROLE_PRIORS[EvidenceRole.CALLER] == 0.55
    assert ROLE_PRIORS[EvidenceRole.ENTRYPOINT] == 0.55
    assert ROLE_PRIORS[EvidenceRole.ENCLOSING_CONTEXT] == 0.50
    assert ROLE_PRIORS[EvidenceRole.BOILERPLATE] == 0.15


def test_role_priors_preserve_strict_ordering() -> None:
    """Role-prior ordering ROOT > SINK > SOURCE > ... > BOILERPLATE must be preserved."""

    assert ROLE_PRIORS[EvidenceRole.ROOT] > ROLE_PRIORS[EvidenceRole.SINK]
    assert ROLE_PRIORS[EvidenceRole.SINK] > ROLE_PRIORS[EvidenceRole.SOURCE]
    assert ROLE_PRIORS[EvidenceRole.SOURCE] > ROLE_PRIORS[EvidenceRole.SANITIZER]
    assert ROLE_PRIORS[EvidenceRole.SANITIZER] >= ROLE_PRIORS[EvidenceRole.GUARD]
    assert ROLE_PRIORS[EvidenceRole.GUARD] > ROLE_PRIORS[EvidenceRole.PROPAGATION]
    assert ROLE_PRIORS[EvidenceRole.PROPAGATION] > ROLE_PRIORS[EvidenceRole.DEFINITION]
    assert ROLE_PRIORS[EvidenceRole.DEFINITION] > ROLE_PRIORS[EvidenceRole.IMPORT]
    assert ROLE_PRIORS[EvidenceRole.ENCLOSING_CONTEXT] > ROLE_PRIORS[EvidenceRole.BOILERPLATE]


def test_default_config_matches_task_md_defaults() -> None:
    """Default BudgetedRankingConfig values must exactly match TASK.md §2."""

    config = BudgetedRankingConfig()

    assert config.depth_decay == 0.60
    assert config.context_strength == 0.45
    assert config.role_prior_temperature == 1.00
    assert config.finding_evidence_scale == 1.00
    assert config.taint_evidence_scale == 1.00
    assert config.cpg_role_evidence_scale == 1.00
    assert config.lexical_fallback_cap == 0.40
    assert config.token_cost_power == 0.35
    assert config.novelty_penalty == 0.40
    assert config.role_coverage_bonus == 0.20
    assert config.small_node_token_threshold == 220
    assert config.local_window_radius == 3
    assert config.max_candidates_per_node == 8
    assert config.budget_safety_ratio == 0.95


def test_yaml_round_trip_preserves_values(tmp_path: Path) -> None:
    """Saving and loading the config must produce an identical object."""

    original = BudgetedRankingConfig(
        depth_decay=0.42,
        context_strength=0.55,
        token_cost_power=0.25,
        small_node_token_threshold=180,
    )
    out_path = tmp_path / "budgeted.yaml"

    original.to_yaml(out_path)
    reloaded = BudgetedRankingConfig.from_yaml(out_path)

    assert reloaded.model_dump() == original.model_dump()


def test_to_yaml_creates_parent_directories(tmp_path: Path) -> None:
    """Saving into a nested path must create intermediate directories."""

    config = BudgetedRankingConfig()
    out_path = tmp_path / "nested" / "dir" / "budgeted.yaml"

    config.to_yaml(out_path)

    assert out_path.exists()


def test_extra_fields_forbidden(tmp_path: Path) -> None:
    """Unknown top-level keys must raise validation errors."""

    yaml_text = "depth_decay: 0.5\nunknown_extra_key: 1.0\n"
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(yaml_text)

    with pytest.raises(ValidationError):
        BudgetedRankingConfig.from_yaml(bad_yaml)


def test_from_yaml_requires_mapping(tmp_path: Path) -> None:
    """A YAML file containing a scalar must raise a clear error."""

    bad_yaml = tmp_path / "scalar.yaml"
    bad_yaml.write_text("just a string\n")

    with pytest.raises(ValueError, match="must be a mapping"):
        BudgetedRankingConfig.from_yaml(bad_yaml)


def test_ranking_candidate_holds_source_node_and_roles() -> None:
    """RankingCandidate must wrap a CodeContextNode plus role/score metadata."""

    node = CodeContextNode(
        identifier="abc",  # type: ignore[arg-type]
        file_path=Path("src/module.py"),
        line_start=10,
        line_end=20,
        depth=0,
    )

    candidate = RankingCandidate(
        source_node=node,
        roles=frozenset({EvidenceRole.ROOT, EvidenceRole.SINK}),
        estimated_token_count=120,
        clipped_line_start=10,
        clipped_line_end=20,
    )

    assert candidate.source_node is node
    assert candidate.roles == frozenset({EvidenceRole.ROOT, EvidenceRole.SINK})
    assert candidate.estimated_token_count == 120
    assert candidate.distance_score == 0.0
    assert candidate.context_score == 0.0
    assert candidate.relevance == 0.0
    assert candidate.cpg_confidence == 0.0
    assert candidate.lexical_fallback_only is False
