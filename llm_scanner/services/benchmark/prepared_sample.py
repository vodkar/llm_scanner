"""Persistent cache of expensive per-sample inputs for the benchmark loop.

The CleanVul benchmark loop performs work in two distinct stages per sample:

1. **Preparation** — checkout the repo at the commit, parse the CPG, ingest into
   Neo4j, and fetch ``_SharedContextInputs`` + path-fill neighborhood edges from
   the graph. This is deterministic in ``(repo_url, fix_hash, is_vulnerable,
   max_call_depth, files_spans, loader options)`` and independent of the
   ranking coefficients being tuned.
2. **Rendering** — apply a ranking strategy to the prepared inputs and produce
   the final text snippet.

The Optuna tuner reruns step 2 with new coefficients on every trial, but
``build_benchmark_and_score`` today re-runs step 1 too. This module captures the
output of step 1 in ``PreparedSample`` and persists it to disk so subsequent
trials skip the expensive Neo4j ingest.
"""

import hashlib
import logging
import pickle
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from models.base import NodeID
from models.benchmark.cleanvul import CleanVulEntry
from models.context import CodeContextNode
from models.nodes.finding import FindingNode

_LOGGER = logging.getLogger(__name__)

# Bump when ``PreparedSample`` gains a new field that Phase 2 cannot infer
# from existing pickle content. Old cache files are silently ignored.
# v3: PreparedSample.static_findings (analyzer findings for the checkout).
# v4: CleanVulEntry.source_dataset/source_file/source_row_ids.
# v5: non-security analyzer rules (e.g. Bandit B101) dropped from findings and scores.
_CACHE_SCHEMA_VERSION = 5


class PreparedSample(BaseModel):
    """All deterministic per-sample inputs needed by Phase 2 (render + rank).

    Phase 2 reads this entirely from pickle and does not need any Neo4j
    connection or fresh CPG parse — only ``repo_path`` is dereferenced (so the
    checked-out repo must remain on disk).
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    entry: CleanVulEntry
    repo_path: Path
    target_hash: str
    sample_id: str
    root_ids: list[str]
    plain_context_nodes: list[CodeContextNode]
    edge_path_context_nodes: list[CodeContextNode]
    taint_scores: dict[NodeID, float]
    neighborhood_edges: list[tuple[NodeID, NodeID, str]]
    path_fill_edge_types: tuple[str, ...]
    traversal_relationship_types: tuple[str, ...]
    static_findings: list[FindingNode] = []
    cache_key: str


def compute_sample_cache_key(
    *,
    repo_url: str,
    fix_hash: str,
    is_vulnerable: bool,
    max_call_depth: int,
    files_spans: list[Any],
    loader_options: Mapping[str, Any] | None = None,
    exclude_test_nodes: bool = True,
    damp_call_graph_hubs: bool = True,
    hub_fanin_threshold: int = 8,
    semgrep_config: str | None = None,
) -> str:
    """Compute a stable SHA1 cache key for the prepared-sample artefact.

    ``files_spans`` is included because spans are produced by text-matching CSV
    ``func_before`` / ``func_after`` against the checked-out files — different
    row selections at the same commit produce different root IDs.
    ``loader_options`` covers per-run filters such as ``min_score`` so caches
    do not collide across runs with different filtering.
    ``exclude_test_nodes`` is included because it changes the cached neighborhood
    superset, so toggling it must not reuse a stale cache. ``damp_call_graph_hubs``
    and ``hub_fanin_threshold`` are included for the same reason: they prune the
    cached neighborhood, so different values must not collide. ``semgrep_config``
    is the Semgrep rule config when Semgrep ran (None otherwise); it is appended
    only when set so Semgrep-off keys match those from before Semgrep existed.
    """

    spans_repr: list[tuple[str, tuple[tuple[int, int], ...]]] = []
    for fs in files_spans:
        file_path = str(getattr(fs, "file_path", ""))
        line_spans = tuple(sorted(tuple(span) for span in getattr(fs, "line_spans", ())))
        spans_repr.append((file_path, line_spans))
    spans_repr.sort()

    parts = (
        f"v{_CACHE_SCHEMA_VERSION}",
        repo_url,
        fix_hash,
        "vuln" if is_vulnerable else "fixed",
        f"depth={max_call_depth}",
        repr(spans_repr),
        repr(sorted((loader_options or {}).items())),
        f"exclude_test_nodes={exclude_test_nodes}",
        f"damp_call_graph_hubs={damp_call_graph_hubs}",
        f"hub_fanin_threshold={hub_fanin_threshold}",
        *(() if semgrep_config is None else (f"semgrep_config={semgrep_config}",)),
    )
    digest = hashlib.sha1("\x1f".join(parts).encode("utf-8")).hexdigest()
    return digest


def prepared_sample_path(cache_dir: Path, cache_key: str) -> Path:
    """Return the on-disk path for a prepared sample with the given key."""

    return cache_dir / f"{cache_key}.pkl"


def save_prepared_sample(cache_dir: Path, sample: PreparedSample) -> Path:
    """Persist ``sample`` under ``cache_dir`` and return the file path."""

    cache_dir.mkdir(parents=True, exist_ok=True)
    target = prepared_sample_path(cache_dir, sample.cache_key)
    with target.open("wb") as fp:
        pickle.dump(sample, fp, protocol=pickle.HIGHEST_PROTOCOL)
    _LOGGER.debug("Wrote prepared sample cache: %s", target)
    return target


def load_prepared_sample(cache_dir: Path, cache_key: str) -> PreparedSample | None:
    """Load a previously-prepared sample by ``cache_key``, returning None if absent."""

    target = prepared_sample_path(cache_dir, cache_key)
    if not target.exists():
        return None
    with target.open("rb") as fp:
        loaded = pickle.load(fp)
    if not isinstance(loaded, PreparedSample):
        raise RuntimeError(
            f"Cache file {target} did not contain a PreparedSample (got {type(loaded)!r})."
        )
    return loaded


class PreparedSampleRef(BaseModel):
    """On-disk handle to a cached ``PreparedSample``, loaded only when rendered.

    Prepared samples can hold tens of MB of context nodes each, so Phase 1
    hands Phase 2 these handles instead of keeping hundreds of samples in memory.
    """

    model_config = ConfigDict(frozen=True)

    cache_dir: Path
    cache_key: str
    repo_path: Path
    sample_id: str

    def load(self) -> PreparedSample:
        """Unpickle the sample, re-pointed at this handle's repo path and sample id.

        Raises:
            FileNotFoundError: If the cache file no longer exists.
        """

        sample = load_prepared_sample(self.cache_dir, self.cache_key)
        if sample is None:
            raise FileNotFoundError(prepared_sample_path(self.cache_dir, self.cache_key))
        sample.repo_path = self.repo_path
        sample.sample_id = self.sample_id
        return sample


class PreparedSampleManifest(BaseModel):
    """Ordered handles from one completed Phase 1 walk over the dataset.

    Persisting the walk's outcome lets later runs reuse the exact same sample
    set without re-checking out every repo or touching Neo4j.
    """

    refs: list[PreparedSampleRef]


def prepared_manifest_path(cache_dir: Path, manifest_key: str) -> Path:
    """Return the on-disk path for the Phase 1 manifest with the given key."""

    return cache_dir / f"manifest_{manifest_key}.json"


def save_prepared_manifest(
    cache_dir: Path, manifest_key: str, refs: list[PreparedSampleRef]
) -> Path:
    """Persist the ordered Phase 1 handles under ``cache_dir`` and return the file path."""

    cache_dir.mkdir(parents=True, exist_ok=True)
    target = prepared_manifest_path(cache_dir, manifest_key)
    target.write_text(PreparedSampleManifest(refs=refs).model_dump_json(indent=2))
    return target


def load_prepared_manifest(cache_dir: Path, manifest_key: str) -> list[PreparedSampleRef] | None:
    """Load the Phase 1 handles for ``manifest_key``.

    Returns None when the manifest is absent or any sample it lists is no
    longer cached, so the caller falls back to a fresh walk.
    """

    target = prepared_manifest_path(cache_dir, manifest_key)
    if not target.exists():
        return None
    refs = PreparedSampleManifest.model_validate_json(target.read_text()).refs
    missing = [
        ref for ref in refs if not prepared_sample_path(ref.cache_dir, ref.cache_key).exists()
    ]
    if missing:
        _LOGGER.warning(
            "Ignoring manifest %s: %d of its prepared samples are missing", target, len(missing)
        )
        return None
    return refs


def iter_prepared_samples(cache_dir: Path) -> list[PreparedSample]:
    """Load every prepared sample under ``cache_dir`` in file-name order.

    Returns an empty list when the directory does not exist. Files that fail to
    unpickle are skipped with a warning; callers should rerun Phase 1 to
    rebuild them.
    """

    if not cache_dir.exists():
        return []
    samples: list[PreparedSample] = []
    for path in sorted(cache_dir.glob("*.pkl")):
        try:
            with path.open("rb") as fp:
                loaded = pickle.load(fp)
        except Exception:
            _LOGGER.exception("Skipping unreadable prepared-sample cache: %s", path)
            continue
        if not isinstance(loaded, PreparedSample):
            _LOGGER.warning(
                "Skipping cache file %s: expected PreparedSample, got %s",
                path,
                type(loaded).__name__,
            )
            continue
        samples.append(loaded)
    return samples
