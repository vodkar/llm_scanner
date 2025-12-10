# CPG Parser Implementations

This project now supports two different implementations for parsing Python code into Code Property Graphs (CPGs):

## Available Parsers

### 1. AST Parser (Default)

- **Implementation**: `AstCPGParser`
- **Backend**: Python's built-in `ast` module
- **Availability**: Always available (part of Python standard library)
- **Performance**: Fast parsing, well-tested
- **Features**: Full support for Python syntax analysis

### 2. Tree-sitter Parser

- **Implementation**: `TreeSitterCPGParser`
- **Backend**: [py-tree-sitter](https://github.com/tree-sitter/py-tree-sitter) bindings
- **Availability**: Optional (requires installation)
- **Performance**: Very fast parsing, incremental parsing support
- **Features**: Language-agnostic parsing framework

## Installation

### AST Parser

No additional installation required - uses Python's built-in `ast` module.

### Tree-sitter Parser

```bash
pip install tree-sitter tree-sitter-python
```

## Usage

### Using the Entry Point Functions

```python
from pathlib import Path
from entrypoints.base import parse_file_to_cpg, parse_project_to_cpg, ParserType

# Parse with AST parser (default)
nodes, edges = parse_file_to_cpg(Path("example.py"))

# Parse with tree-sitter parser
nodes, edges = parse_file_to_cpg(Path("example.py"), parser_type=ParserType.TREE_SITTER)

# Parse entire project
nodes, edges = parse_project_to_cpg(Path("./src"), parser_type=ParserType.AST)
```

### Using Parser Instances Directly

```python
from entrypoints.base import get_parser, ParserType

# Get parser instance
parser = get_parser(ParserType.AST)  # or ParserType.TREE_SITTER
nodes, edges = parser.parse_file(Path("example.py"))
```

### Using Specific Parser Classes

```python
from services.ast_cpg_parser import AstCPGParser
from services.tree_sitter_cpg_parser import TreeSitterCPGParser

# Direct instantiation
ast_parser = AstCPGParser()
ts_parser = TreeSitterCPGParser()  # May raise ImportError if not installed

nodes, edges = ast_parser.parse_file(Path("example.py"))
```

## Common Interface

Both parsers implement the same interface (`CPGParserProtocol`):

```python
class CPGParserProtocol(Protocol):
    def parse_file(self, path: Path, ignore_magic: bool = True) -> tuple[dict[str, Node], list[Edge]]:
        """Parse a single file into a CPG."""
        ...

    def parse_project(self, root: Path, ignore_magic: bool = True) -> tuple[dict[str, Node], list[Edge]]:
        """Parse a project directory into a CPG."""
        ...
```

## Error Handling

If tree-sitter dependencies are not installed, attempting to use the tree-sitter parser will raise an `ImportError` with installation instructions:

```python
try:
    parser = get_parser(ParserType.TREE_SITTER)
except ImportError as e:
    print(e)  # "tree-sitter dependencies not available. Install with: pip install tree-sitter tree-sitter-python"
```

## Testing

Run tests for both implementations:

```bash
# Test both parsers (tree-sitter tests skipped if not installed)
python -m pytest tests/test_both_parsers.py -v

# Test existing AST parser functionality
python -m pytest tests/test_cpg_parser.py -v

# Run comparison example
python examples/parser_comparison.py
```

## Architecture

```
services/
├── cpg_parser_interface.py     # Common interface and protocol
├── cpg_parser.py               # Original AST implementation classes
├── ast_cpg_parser.py           # AST parser wrapper
└── tree_sitter_cpg_parser.py   # Tree-sitter implementation

entrypoints/
└── base.py                     # Updated entry points with parser selection

tests/
├── test_cpg_parser.py          # Original tests
└── test_both_parsers.py        # Tests for both implementations

examples/
└── parser_comparison.py       # Usage comparison example
```

## Benefits of Multiple Implementations

1. **Flexibility**: Choose the best parser for your use case
2. **Fallback**: AST parser always available, tree-sitter as enhancement
3. **Performance**: Tree-sitter can be faster for large codebases
4. **Compatibility**: Common interface ensures easy switching
5. **Future-proofing**: Easy to add more parser implementations
