"""Tests for prepared-sample cache key sensitivity to run options."""

from pathlib import Path

from models.context import FileSpans
from services.benchmark.prepared_sample import compute_sample_cache_key

_BASE_KWARGS = {
    "repo_url": "https://github.com/example/repo",
    "fix_hash": "abc123",
    "is_vulnerable": True,
    "max_call_depth": 3,
    "files_spans": [FileSpans(Path("pkg/mod.py"), [(1, 5)])],
}


def test_cache_key_is_stable_for_same_inputs() -> None:
    """The same inputs always hash to the same key."""

    assert compute_sample_cache_key(**_BASE_KWARGS) == compute_sample_cache_key(**_BASE_KWARGS)


def test_cache_key_changes_with_exclude_test_nodes() -> None:
    """Toggling exclude_test_nodes yields a different cache key (enables A/B)."""

    with_filter = compute_sample_cache_key(**_BASE_KWARGS, exclude_test_nodes=True)
    without_filter = compute_sample_cache_key(**_BASE_KWARGS, exclude_test_nodes=False)

    assert with_filter != without_filter


def test_cache_key_defaults_to_excluding_test_nodes() -> None:
    """Omitting the flag matches the explicit default (True)."""

    assert compute_sample_cache_key(**_BASE_KWARGS) == compute_sample_cache_key(
        **_BASE_KWARGS, exclude_test_nodes=True
    )


def test_cache_key_changes_with_damp_call_graph_hubs() -> None:
    """Toggling damp_call_graph_hubs yields a different cache key."""

    on = compute_sample_cache_key(**_BASE_KWARGS, damp_call_graph_hubs=True)
    off = compute_sample_cache_key(**_BASE_KWARGS, damp_call_graph_hubs=False)

    assert on != off


def test_cache_key_changes_with_hub_fanin_threshold() -> None:
    """Different hub fan-in thresholds yield different cache keys."""

    assert compute_sample_cache_key(
        **_BASE_KWARGS, hub_fanin_threshold=12
    ) != compute_sample_cache_key(**_BASE_KWARGS, hub_fanin_threshold=20)


def test_cache_key_defaults_match_explicit_hub_defaults() -> None:
    """Omitting the hub flags matches the explicit defaults."""

    assert compute_sample_cache_key(**_BASE_KWARGS) == compute_sample_cache_key(
        **_BASE_KWARGS, damp_call_graph_hubs=True, hub_fanin_threshold=12
    )
