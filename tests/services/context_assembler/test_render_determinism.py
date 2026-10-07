"""Rendering must not depend on Python's per-process string hash seed."""

import os
import subprocess
import sys
from pathlib import Path
from typing import Final

from tests.consts import PROJECT_ROOT

HASH_SEEDS: Final[tuple[str, ...]] = ("0", "1", "2", "3", "4", "5")

# A root reaches a high-ranked target only through one of eight interchangeable
# parents; the budget fits the rendered root + target + one parent (6 lines with the
# ROOT, CONTEXT and file markers), so the parent that path-fill pulls in decides the text.
_RENDER_SCRIPT: Final[str] = """
import sys
from pathlib import Path

from models.base import NodeID
from models.context import CodeContextNode
from services.context_assembler.context_assembler import ContextAssemblerService
from services.ranking.ranking import DummyNodeRankingStrategy

repo = Path(sys.argv[1])
parents = [f"p{index}" for index in range(8)]
(repo / "mod.py").write_text(
    "root = 0\\n" "target = 1\\n" + "".join(f"{name} = 2\\n" for name in parents),
    encoding="utf-8",
)


def node(name: str, line: int, depth: int) -> CodeContextNode:
    return CodeContextNode(
        identifier=NodeID(f"VariableNode:{name}"),
        node_kind="VariableNode",
        name=name,
        file_path=Path("mod.py"),
        line_start=line,
        line_end=line,
        depth=depth,
    )


nodes = [node("root", 1, 0), node("target", 2, 2)]
nodes += [node(name, 3 + index, 1) for index, name in enumerate(parents)]
edges = []
for name in parents:
    edges.append((NodeID("VariableNode:root"), NodeID(f"VariableNode:{name}"), "FLOWS_TO"))
    edges.append((NodeID(f"VariableNode:{name}"), NodeID("VariableNode:target"), "FLOWS_TO"))
service = ContextAssemblerService(
    project_root=repo,
    context_repository=None,
    cached_neighborhood_edges=edges,
    max_call_depth=3,
    token_budget=6,
    token_estimator=lambda text: len(text.splitlines()),
    ranking_strategy=DummyNodeRankingStrategy(),
)
print(service.assemble_from_nodes(repo, nodes).context_text)
"""


def _render_with_hash_seed(tmp_path: Path, seed: str) -> str:
    env = {
        **os.environ,
        "PYTHONHASHSEED": seed,
        "PYTHONPATH": os.pathsep.join([str(PROJECT_ROOT / "llm_scanner"), str(PROJECT_ROOT)]),
    }
    repo = tmp_path / f"seed_{seed}"
    repo.mkdir()
    result = subprocess.run(
        [sys.executable, "-c", _RENDER_SCRIPT, str(repo)],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return result.stdout


def test_path_fill_render__is_identical_across_hash_seeds(tmp_path: Path) -> None:
    renders = {seed: _render_with_hash_seed(tmp_path, seed) for seed in HASH_SEEDS}

    assert len(set(renders.values())) == 1, renders


def test_path_fill_render__picks_smallest_id_parent_on_ties(tmp_path: Path) -> None:
    render = _render_with_hash_seed(tmp_path, "0")

    assert "p0 = 2" in render
    assert "target = 1" in render
