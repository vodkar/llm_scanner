# Tree-sitter CPG Parser

The project now exposes a single, modern tree-sitter based implementation for
building Code Property Graphs (CPGs). The parser produces structured nodes such
as `ModuleNode`, `FunctionNode`, `CodeBlockNode`, and `VariableNode`, keyed by
their deterministic identifiers. Every graph also includes classic
`Edge` objects so existing analyzers continue to work.

## Installation

The parser relies on the upstream tree-sitter runtime and the Python grammar:

```bash
uv pip install tree-sitter tree-sitter-python
```

## Entry Point Helpers

Most callers can rely on the helper functions in `entrypoints.base`:

```python
from pathlib import Path

from entrypoints.base import parse_file_to_cpg, parse_project_to_cpg

nodes, edges = parse_file_to_cpg(Path("example.py"))
project_nodes, project_edges = parse_project_to_cpg(Path("./src"))

for node_id, node in nodes.items():
        print(node_id, node.__class__.__name__)
```

Both helpers return a tuple of `(dict[str, Node], list[Edge])` where `Node` is
the union of the structured Pydantic models defined in `llm_scanner/models/nodes`.

## Direct Parser Usage

```python
from pathlib import Path

from services.cpg_parser.tree_sitter_cpg_parser import TreeSitterCPGParser

parser = TreeSitterCPGParser()
nodes, edges = parser.parse_file(Path("tests/sample.py"))
project_nodes, project_edges = parser.parse_project(Path("tests/data/sample_project"))
```

## Parser Interface

`TreeSitterCPGParser` implements `CPGParserProtocol`:

```python
class CPGParserProtocol(Protocol):
        def parse_file(self, path: Path, ignore_magic: bool = True) -> tuple[dict[str, Node], list[Edge]]:
                """Parse a single file into structured nodes and edges."""

        def parse_project(self, root: Path, ignore_magic: bool = True) -> tuple[dict[str, Node], list[Edge]]:
                """Parse an entire project tree into structured nodes and edges."""
```

## Structured Nodes Overview

- **ModuleNode**: Captures imports, exports, entry-point detection, and file
    paths for each parsed module or package.
- **FunctionNode**: Stores qualified names, signatures, token counts, and
    cyclomatic complexity metrics for every function or method.
- **CodeBlockNode**: Describes loop/conditional regions with nesting levels and
    code snippets for UI display or LLM summarisation.
- **VariableNode**: Records variable scopes, type hints, and sensitivity flags,
    enabling taint-tracking or secret detection tasks.

Additional node types can be added in `llm_scanner/models/nodes` and will flow
through the pipeline automatically because nodes are serialized generically.

## Testing

Run the full suite to validate parser and loader integrations:

```bash
uv run pytest tests/
```

Useful targeted runs:

- `uv run pytest tests/test_tree_sitter_structured.py -v` to validate structured
    node coverage.
- `uv run pytest tests/test_both_parsers.py -v` to smoke-test legacy edge
    expectations against the new structured nodes.

## Architecture

```
services/cpg_parser/
├── cpg_parser_interface.py    # Protocol definition returning structured nodes
└── tree_sitter_cpg_parser.py  # Tree-sitter implementation + builders

entrypoints/
└── base.py                    # Helper functions that wrap the parser

loaders/
├── graph_loader.py            # Neo4j ingestion using structured payloads
├── json_loader.py             # JSON serialization helper
└── yaml_loader.py             # YAML serialization helper

examples/
└── parser_comparison.py       # Quick-start script demonstrating usage
```

## Troubleshooting

- Ensure `tree-sitter` native dependencies are installed before invoking the
    parser. Missing bindings raise `ImportError` with installation hints.
- `ignore_magic=True` skips dunder methods. Set it to `False` if you need
    constructor or special-method coverage.

With the single tree-sitter implementation, all tooling—CLI entry points,
loaders, and analyzers—now consume the same structured node set, eliminating the
need for `DeprecatedNode` in public APIs.
