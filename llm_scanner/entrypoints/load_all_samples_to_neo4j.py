from __future__ import annotations

from pathlib import Path
from typing import List

from clients.neo4j import Neo4jClient
from entrypoints.base import parse_file_to_cpg
from loaders.yaml_loader import YamlLoader


def main() -> int:
    root = Path(__file__).parents[2]
    tests_dir = root / "tests"
    files: List[Path] = sorted(
        p for p in tests_dir.glob("*.py") if p.name != "__init__.py"
    )

    client = Neo4jClient()
    loader = YamlLoader("output.yaml")

    total_nodes = 0
    total_edges = 0
    result_nodes, result_edges = {}, []
    for path in files:
        nodes, edges = parse_file_to_cpg(path)
        result_edges.extend(edges)
        result_nodes.update(nodes)
        total_nodes += len(nodes)
        total_edges += len(edges)

    loader.load(result_nodes, result_edges)

    client.close()
    print(f"Loaded {total_nodes} nodes and {total_edges} edges from {len(files)} files")
    return 0


if __name__ == "__main__":
    main()
