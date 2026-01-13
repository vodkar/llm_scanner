#!/usr/bin/env python3
"""Demonstrate how to work with the tree-sitter CPG parser."""

from collections import Counter
from pathlib import Path

from entrypoints.base import get_parser, parse_file_to_cpg
from models.nodes import CodeBlockNode, FunctionNode, ModuleNode, Node, VariableNode


def summarize_nodes(nodes: dict[str, Node]) -> None:
    """Print a short summary of the structured node distribution."""

    counters = Counter(
        node.__class__.__name__
        for node in nodes.values()
        if isinstance(
            node,
            (ModuleNode, FunctionNode, CodeBlockNode, VariableNode),
        )
    )
    for kind, count in counters.items():
        print(f"  - {kind}: {count}")


def explore_sample() -> None:
    """Parse the sample file and report node/edge counts."""

    sample_file = Path(__file__).parent.parent / "tests" / "sample.py"
    if not sample_file.exists():
        raise SystemExit(f"Sample file not found: {sample_file}")

    nodes, edges = parse_file_to_cpg(sample_file)
    print(f"Parsed {sample_file}")
    print(f"Total nodes: {len(nodes)} | Total edges: {len(edges)}")
    summarize_nodes(nodes)


def explore_project() -> None:
    """Parse the entire tests/sample_project directory using the parser instance."""

    parser = get_parser()
    project_root = Path(__file__).parent.parent / "tests" / "data" / "sample_project"
    nodes, edges = parser.parse_project(project_root)
    print(f"\nParsed project: {project_root}")
    print(f"Total nodes: {len(nodes)} | Total edges: {len(edges)}")
    summarize_nodes(nodes)


def main() -> None:
    explore_sample()
    explore_project()


if __name__ == "__main__":
    main()
