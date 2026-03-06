# Code Property Graph Construction for Python Source Code

## Abstract

This document describes the construction of Code Property Graphs (CPGs) from Python source files within the `llm-scanner` project. The CPG unifies three complementary program representations — an abstract syntax tree (AST), a call graph (CG), and a data-flow graph (DFG) — into a single property graph suitable for static vulnerability analysis and LLM-assisted security reasoning. The implementation is split across two modules: `cpg_builder.py`, which orchestrates file and directory scoping, and `node_processor.py`, which performs the recursive tree traversal and graph emission.

---

## 1. Background

A Code Property Graph, as originally proposed by Yamaguchi et al. (2014), combines the structural properties of an AST with control-flow and data-flow edges into one queryable graph. This project adapts the concept to Python by using `tree-sitter-python` as the concrete syntax tree (CST) frontend and deriving data-flow and call-graph edges through a single-pass (with pre-binding) traversal of that CST.

The output of the construction pipeline is a `ParserResult`, defined as:

```python
type ParserResult = tuple[dict[NodeID, Node], list[RelationshipBase]]
```

That is, a dictionary mapping unique identifiers to graph nodes, and a list of typed directed edges.

---

## 2. Entry Points and Scoping

### 2.1 Single-File Construction: `CPGFileBuilder`

`CPGFileBuilder` handles one Python source file. On initialization it:

1. Reads the raw file bytes and decodes them to UTF-8 (with replacement for malformed bytes).
2. Parses the source using a `tree_sitter.Parser` configured with the `tree-sitter-python` grammar, obtaining a `Tree` (CST root).
3. Normalizes the display path relative to an optional project `root`, so all node identifiers use portable, root-relative paths regardless of where the tool is invoked.
4. Instantiates a `NodeProcessor`, injecting the CST source bytes, split lines, and any pre-bound cross-module symbols.

The `build()` method delegates immediately to `NodeProcessor.process(tree.root_node)`.

### 2.2 Directory-Level Construction: `CPGDirectoryBuilder`

`CPGDirectoryBuilder` extends the single-file builder to an entire directory tree. Its `build()` method proceeds in three stages:

**Stage 1 – File discovery.** All `.py` files are collected via `os.walk` (or a flat scan when `recursive=False`). Directories named `__pycache__`, `.git`, `.venv`, `venv`, `.mypy_cache`, `.pytest_cache`, `tests`, and `test` are skipped. The resulting list is sorted for deterministic ordering.

**Stage 2 – Symbol index construction (optional).** When `link_imports=True` (the default), each file is parsed a first time using Python's built-in `ast` module to extract module-level exported names — functions, classes, and annotated or plain variable assignments. A first full `CPGFileBuilder` pass is then run (without any pre-bound symbols) on each file, and the resulting node dictionary is searched to correlate exported names with their `NodeID`s. The final index maps `module_name → {symbol_name → NodeID}`.

**Stage 3 – Per-file CPG construction and merging.** Each file is built a second time, this time with pre-bound symbols derived by examining its `from X import Y` statements and resolving them against the symbol index. The resulting nodes and edges are merged into flat `merged_nodes` and `merged_edges` collections, with a collision check to catch unexpected duplicate node IDs.

#### Import Resolution

Relative imports (e.g., `from ..utils import helper`) are resolved through `_resolve_import_from_module`, which computes the target module name by walking up the package hierarchy by the number of leading dots (`level`) and then appending any explicit module suffix. Absolute imports (`level=0`) are passed through unchanged. Wildcard imports (`from X import *`) are silently ignored.

---

## 3. Node Processor: Core Traversal Logic

`NodeProcessor` performs a recursive descent over the CST, maintaining two runtime stacks:

- **Scope stack** (`__scope_stack`): a list of `dict[str, NodeID]` frames, one per lexical scope. The global frame is always present; a new frame is pushed on function entry and popped on exit.
- **Caller stack** (`__caller_stack`): a list of `NodeID` values representing the enclosing callable (function, method, or top-level code block) at each point of the traversal. The top of the stack is the "current caller" to which any discovered call site is attributed.

### 3.1 Module-Level Processing: Three-Pass Algorithm

When the processor encounters the CST `module` root, it executes three sequential passes over the module's direct children:

**Pass 0 – Top-level block grouping.** Imperative statements at module level (i.e., not function/class definitions, imports, or decorator wrappers) are grouped into contiguous `CodeBlockNode` sequences. Each group becomes a single `CodeBlockNode` with a `line_start` and `line_end` spanning the group. This represents "script-style" code such as `if __name__ == "__main__":` blocks or global initialization logic.

**Pass 1 – Class pre-binding.** Each top-level `class_definition` (including those wrapped in a `decorated_definition`) is visited without full processing. The class name and all method names found in the class body are registered in the global scope frame. This ensures that method calls appearing anywhere in the file — even before the class definition — can be resolved.

**Pass 2 – Function pre-binding.** Each top-level `function_definition` is similarly registered in the global scope without full processing, enabling forward references to top-level functions.

**Pass 3 – Full recursive processing.** All non-imperative children are processed recursively. After this, each previously identified `CodeBlockNode` group is processed with the code block's node ID pushed onto the caller stack, so that any calls within module-level imperative code are attributed to the correct `CodeBlockNode`.

This three-pass strategy eliminates the need for a separate forward-declaration phase or a fixup step and allows the processor to resolve intra-file forward references during the single recursive traversal.

---

## 4. Node Types and Their Construction

### 4.1 `FunctionNode`

Triggered by CST nodes of type `function_definition`. Construction proceeds as follows:

1. The function name is extracted from the `name` field of the CST node.
2. A `FunctionNode` is created with `identifier`, `name`, `file_path`, `line_start`, and `line_end`.
3. The function name is bound in the **enclosing** scope (so that calls within sibling functions can resolve it).
4. A **new scope frame** is pushed, and the function's `NodeID` is pushed onto the **caller stack**.
5. Parameters are extracted from the `parameters` field. For each parameter identifier: a `VariableNode` is created, bound in the new scope, and linked to the function via a `DataFlowDefinedBy(function → param, operation=PARAMETER)` edge.
6. The function body is processed recursively.
7. The caller and scope are popped.

Async function definitions (`async_function_definition` in the CST) are handled identically by tree-sitter's Python grammar, which represents them as `function_definition` nodes with an async keyword.

### 4.2 `ClassNode`

Triggered by `class_definition` nodes. A `ClassNode` is created spanning the class name line through the superclass list (if present). The class body is then processed — only children whose CST type appears in `ProcessableNodeTypes` (assignments, function definitions, calls, blocks, imports) are recursed into. For every node emitted by child processing, a `DataFlowDefinedBy(class → child, operation=ASSIGNMENT)` edge is added, modelling the containment relationship in data-flow terms.

### 4.3 `CodeBlockNode`

Represents a contiguous block of top-level imperative statements. The block's name is taken from the first line of source text in the block and is used (after compaction) as part of the node identifier. These nodes serve as the callers for call sites discovered within module-level script code.

### 4.4 `VariableNode`

Created for:
- **Function parameters**: one node per parameter identifier, typed with the annotation if present.
- **Assignment targets**: one node per LHS identifier, attribute, or destructuring element. A variable is only created once per scope entry — subsequent references to the same name in the same scope resolve to the existing node.

The node stores `name`, `type_hint`, `file_path`, `line_start`, and `line_end`.

### 4.5 `CallNode`

Created for every resolved call site. A call is resolved only when its caller context is known (non-empty caller stack) and its callee can be identified (see Section 5.1). The node records `caller_id`, `callee_id`, `file_path`, `line_start`, and `line_end`. The `NodeID` encodes the call snippet and byte offset to make co-located calls distinguishable.

---

## 5. Edge Types and Their Emission

### 5.1 Call Graph Edges

Call resolution is performed by `__resolve_call_target`:

- **Direct calls** (`identifier` callee): the name is looked up in the scope chain from innermost to outermost. A match is accepted only if the resolved `NodeID` has a `function:` or `class:` prefix.
- **Method calls** (`attribute` callee, e.g., `obj.method()`): only the attribute name (method name) is resolved. The scope chain is checked first; if not found, the global `__all_functions` index (populated during class and function pre-binding) is consulted and the first matching `NodeID` is returned. This is an approximation that does not perform type inference.

When a call is resolved, two edges are emitted:

| Edge type | Source | Destination | Semantics |
|---|---|---|---|
| `CallGraphCalls` | Caller (`FunctionNode` or `CodeBlockNode`) | `CallNode` | The caller invokes this call site |
| `CallGraphCalledBy` | `CallNode` | Callee (`FunctionNode` or `ClassNode`) | The call site targets this definition |

### 5.2 Data-Flow Edges

#### `DataFlowDefinedBy` (`DEFINED_BY`)

Emitted whenever a value flows into a binding:

- **Parameter binding**: `function → variable` with `operation=PARAMETER`.
- **Assignment**: `source → target_variable` with `operation=ASSIGNMENT`. The source may be an existing `VariableNode` (RHS identifier resolved in scope), a `CallNode` (RHS call expression), or absent (pure literal assignment with no linkable source).
- **Augmented assignment** (`x += expr`): additionally links the previous binding of `x` as a source, capturing the read-modify-write dependency.
- **Class membership**: `class → child_node` for each definition within the class body.

#### `DataFlowFlowsTo` (`FLOWS_TO`)

Emitted for each argument atom that flows into a call site:

- Resolved `identifier` or `attribute` arguments → `DataFlowFlowsTo(variable → call)`.
- Nested call arguments → `DataFlowFlowsTo(nested_call → outer_call)`.
- Unresolved identifiers are silently dropped; no stub nodes are created.

---

## 6. Node Identity and Naming

Every node in the graph is assigned a `NodeID` computed as:

```
NodeID.create(type_prefix, name, file_path, start_byte)
```

The type prefix distinguishes node categories (`function`, `class`, `variable`, `call`, `code_block`). The `start_byte` field ensures uniqueness for same-named symbols within the same file. Names longer than 256 characters are truncated to 246 characters and appended with an 8-hex-digit SHA-1 digest to preserve uniqueness while satisfying Neo4j index constraints.

---

## 7. Scope and Lifetime Rules

| Event | Scope stack | Caller stack |
|---|---|---|
| Enter `module` | (global frame already present) | (empty) |
| Process code block | — | push `CodeBlockNode.identifier` |
| Enter `function_definition` | push new frame | push `FunctionNode.identifier` |
| Exit `function_definition` | pop frame | pop |
| Exit code block processing | — | pop |

Symbol lookup (`__resolve_symbol`) iterates the scope stack from innermost to outermost, implementing Python's LEGB-like resolution within the graph model (Local → Enclosing → Global; built-ins are not modelled).

---

## 8. Limitations and Design Choices

1. **No type inference**: method call resolution uses name matching only. Multiple methods with the same name across different classes resolve to the first registered candidate.
2. **No control-flow graph**: branch and loop structures are not explicitly represented; the graph captures which code block or function contains a call, but not the conditional paths to reach it.
3. **Intra-file cross-module linking only**: the directory builder resolves `from X import Y` statements but does not model `import X` (namespace) usage patterns or dynamic imports.
4. **Single-ownership variable model**: each name in a given scope maps to exactly one `VariableNode`. Reassignment does not create a new SSA-style node; instead, subsequent assignments link the same node as the target.
5. **Files are parsed twice** during directory-level construction when `link_imports=True` (once for the symbol index, once with pre-bound symbols). This is a design trade-off for correctness of cross-file edge resolution at the cost of doubled parse time.

---

## 9. Summary

The CPG construction pipeline parses Python files with `tree-sitter`, extracts structural entities (functions, classes, code blocks, variables, call sites) as graph nodes, and links them with typed directed edges encoding call-graph and data-flow relationships. A three-pass module traversal resolves forward references without a separate fixup phase. At directory scale, a pre-build symbol indexing step enables lightweight cross-file data-flow linking via pre-bound symbol tables. The resulting property graph serves as the foundation for subsequent static analysis and LLM-based vulnerability detection passes.
