from __future__ import annotations

from pathlib import Path

from clients.neo4j import Neo4jClient
from entrypoints.base import parse_file_to_cpg
from services.graph_loader import GraphLoader


def main() -> int:
    sample = Path(__file__).parents[2] / "tests" / "sample.py"
    nodes, edges = parse_file_to_cpg(sample)

    client = Neo4jClient()
    loader = GraphLoader(client)
    loader.load(nodes, edges)
    client.close()

    print(f"Loaded {len(nodes)} nodes and {len(edges)} edges from {sample}")
    return 0


if __name__ == "__main__":
    main()
