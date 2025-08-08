from __future__ import annotations

from pathlib import Path
from typing import List

from entrypoints.base import parse_file_to_cpg
from clients.neo4j_client import Neo4jClient
from services.graph_loader import GraphLoader


def main() -> int:
    root = Path(__file__).parents[2]
    tests_dir = root / "tests"
    files: List[Path] = sorted(p for p in tests_dir.glob("*.py") if p.name != "__init__.py")

    client = Neo4jClient()
    loader = GraphLoader(client)

    total_nodes = 0
    total_edges = 0
    for path in files:
        nodes, edges = parse_file_to_cpg(path)
        loader.load(nodes, edges)
        total_nodes += len(nodes)
        total_edges += len(edges)

    client.close()  
    print(f"Loaded {total_nodes} nodes and {total_edges} edges from {len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
