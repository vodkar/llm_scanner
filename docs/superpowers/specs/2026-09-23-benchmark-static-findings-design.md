# Benchmark Static-Analysis Findings — Design

Date: 2026-09-23
Status: Draft (awaiting review)

## Goal

Optionally enrich every generated CleanVul benchmark sample with the static-analysis
reports (Bandit, Dlint) that land inside its rendered code snippet, so a downstream
LLM prompt can be told *what the analyzers flagged and exactly where in the snippet*.
This reduces ambiguity and explains why the code region is interesting.

The database (and analyzers) only know **repo locations** (`file`, `line_number`).
The rendered snippet is a concatenation of kept lines from several files with blank
lines, comment-only lines and duplicate boilerplate removed, so a repo location
cannot be mapped to a snippet line after the fact. The renderer must therefore emit
a source map, and each finding must carry its resolved snippet line.

## Decisions (agreed)

- **Scope:** only findings whose line is actually rendered in the snippet are attached.
- **Format:** structured fields on `BenchmarkSample`; `code` is left unchanged, so
  rankings, token counts and judge scores stay comparable.
- **Opt-in:** controlled by a CLI flag `--include-static-findings` (default off).
  With the flag off, the dataset JSON is byte-identical to today's output.

## Current state

- `GeneralScannerPipeline.build_cpg()` already runs Bandit + Dlint on every benchmark
  sample and returns `(findings, edges)`, but `CleanVulBenchmarkService._prepare_one_side`
  and `_scan_repository_for_entry` discard the return value.
- `FindingNode` drops the analyzer message (`StaticAnalyzerIssue.reason`) and column;
  Bandit's `test_id` (e.g. `B605`) and `line_range` are never parsed/kept; Dlint's
  code (`DUO102`) is reduced to an int `issue_id`.
- `ContextAssemblerService._render_text` produces a plain string with no provenance.

## Design

### 1. Keep full analyzer data

`models/nodes/finding.py`:

- `FindingNode` gains `reason: str = ""`, `rule_id: str = ""`, `column_number: int = 0`,
  `line_end: int | None = None` (last line of the reported range; `None` = single line).
- `BanditIssue` gains `test_id: str`; `BanditStaticAnalyzer` parses `report["test_id"]`.
- `BanditAnalyzerService._issue_payload`: `rule_id = test_id`, keep `column_number`,
  `line_end = max(line_range)` when `line_range` is non-empty.
- `DlintAnalyzerService._issue_payload`: `rule_id = code`, keep `column_number`.
- Defaults keep existing constructors/tests valid. Neo4j repositories are unchanged
  (new fields are not persisted to the graph — not needed).

### 2. Source map from the renderer

`models/context.py`:

```python
class SnippetSegment(BaseModel):
    """Maps a run of consecutive snippet lines back to consecutive-ish repo lines."""
    file_path: Path
    snippet_line_start: int   # 1-based, inclusive, index into code.split("\n")
    snippet_line_end: int     # inclusive
    repo_lines: tuple[int, ...]  # repo line for each snippet line in the run
```

`repo_lines` is explicit per line (not `repo_line_start` + offset) because dropped
blank/comment lines make repo lines non-contiguous within a same-file run.
A segment covers a maximal run of snippet lines coming from the same file.

`Context` gains `source_map: list[SnippetSegment] = []`.

`ContextAssemblerService._render_text` is split: a new classmethod
`_render_lines(read_lines, lines_to_keep) -> list[tuple[Path, int, str]]` does the
current filtering (empty-line skip, boilerplate dedup) and returns provenance per
output line; `_render_text` becomes `"\n".join(text for _, _, text in _render_lines(...))`
so the token-budget path is unchanged. `_render_context` returns
`(text, token_count, source_map)`; `assemble_from_nodes` fills `Context.source_map`.
The map is always computed (cheap bookkeeping).

Invariant: for every segment and index `i`,
`code.split("\n")[snippet_line_start - 1 + i]` is the sanitized text of
`repo_lines[i]` in `file_path`.

New module `services/context_assembler/source_map.py` (pure functions):
`build_source_map(rendered_lines) -> list[SnippetSegment]` and
`resolve_snippet_line(source_map, file_path, repo_line) -> int | None`.

### 3. Attaching findings

New model module `models/static_finding.py` (kept out of `models/benchmark/` so
`models/context.py` can reference it without an import cycle) and new service module
`services/benchmark/static_findings.py` (pure functions, no I/O):

```python
class AnalyzerTool(StrEnum):
    BANDIT = "bandit"
    DLINT = "dlint"

class StaticFinding(BaseModel):          # lives in models/static_finding.py
    tool: AnalyzerTool
    rule_id: str
    cwe_id: int | None
    severity: str | None                 # Bandit only
    message: str
    file_path: Path                      # repo-relative
    repo_line: int
    snippet_line: int                    # 1-based line in BenchmarkSample.code
    is_root: bool                        # line inside a depth-0 (changed-function) node

def attach_findings(
    findings: Sequence[FindingNode],
    source_map: Sequence[SnippetSegment],
    root_nodes: Sequence[CodeContextNode],
) -> list[StaticFinding]: ...
```

`Context` gains `static_findings: list[StaticFinding] = []`, filled by the benchmark
right after each strategy's context is assembled (root nodes are known there). This
keeps `_scan_repository_for_entry`'s return type (`dict[str, Context]`) unchanged.

Resolution per finding:
1. `resolve_snippet_line(file, line_number)`; if `None` and `line_end` is set, the
   first rendered line in `[line_number, line_end]`.
2. Unresolved findings are dropped (not rendered → out of scope).
3. `is_root` = `line_number` within `[line_start, line_end]` of any root node in the
   same file.

Output sorted by `(snippet_line, tool, rule_id)`; exact duplicates (same tool, rule,
repo line) are removed.

### 4. Benchmark wiring

- `CleanVulBenchmarkService.include_static_findings: bool = False`.
- `_scan_repository_for_entry` / `_prepare_one_side` capture `findings, _ = build_cpg()`.
- `PreparedSample.static_findings: list[FindingNode] = []`; `_CACHE_SCHEMA_VERSION`
  bumped to `3` so stale pickles (without findings) are rebuilt. Findings are always
  stored, so the flag is **not** part of the cache key.
- `_render_contexts_from_shared_inputs(..., findings=())` attaches findings to every
  rendered `Context` (root nodes = depth-0 nodes of that strategy's node list);
  filtering to rendered lines happens in `attach_findings`.
- `_to_sample(entry, context, sample_id)`: when `include_static_findings` is true,
  sets `static_findings=context.static_findings` and `source_map=context.source_map`;
  otherwise both stay `None`.

`BenchmarkSample` gains:

```python
static_findings: list[StaticFinding] | None = None
source_map: list[SnippetSegment] | None = None
```

with a `model_serializer(mode="wrap")` that drops these two keys when they are
`None`, so flag-off JSON is byte-identical to today (and `exclude_none` is not
applied to unrelated fields such as `cwe_number`). Old dataset JSON still loads.

### 5. CLI

`--include-static-findings` (bool, default `False`, help: "Attach Bandit/Dlint
findings located in each rendered snippet plus a snippet→repo source map.") on:

- `build-cleanvul-benchmark`
- `build-cleanvul-benchmark-compare-rankings` (via `_run_compare_rankings`)
- `build-cleanvul-benchmark-compare-rankings-all`

Not added to `tune-ranking-coefficients` (the judge scores `code` only).

## Error handling

- A finding whose file is unreadable/missing from the render simply resolves to
  `None` and is dropped; no exceptions.
- `attach_findings` validates `snippet_line >= 1` implicitly via the map; a
  `ValueError` is raised if `SnippetSegment` is constructed with
  `len(repo_lines) != snippet_line_end - snippet_line_start + 1`.

## Testing

- Renderer: multi-file render with blank lines, stripped comments and duplicated
  boilerplate → source map satisfies the invariant; `_render_text` output unchanged.
- `resolve_snippet_line`: hit, miss, non-contiguous repo lines.
- `attach_findings`: rendered vs dropped, `line_end` fallback, `is_root`, sort/dedup.
- Bandit client parses `test_id`; analyzer payloads fill `rule_id`/`reason`/`line_end`.
- `BenchmarkSample` serialization: fields omitted when `None`, present when set.
- `CleanVulBenchmarkService._to_sample` with flag on/off.
- `PreparedSample` pickle round-trip with findings; cache key contains `v3`.

## Out of scope

- Scanner pipeline (`ScanFinding.static_tool_messages`) and LLM-judge prompt changes.
- Persisting new finding fields to Neo4j.
- CVEFixes loader.
