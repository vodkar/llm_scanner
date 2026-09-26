# Benchmark Static-Analysis Findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Behind an opt-in `--include-static-findings` flag, attach the Bandit/Dlint findings that land inside each rendered CleanVul benchmark snippet, with their exact snippet line, plus a snippet→repo source map.

**Architecture:** The context renderer records the `(file, repo_line)` provenance of every output line and exposes it as `Context.source_map`. A pure `attach_findings` function resolves each analyzer finding's repo location to a snippet line through that map. The benchmark service keeps the findings `build_cpg()` already produces (also persisted in the Phase-1 `PreparedSample` cache), attaches them per strategy, and copies them into `BenchmarkSample` only when the flag is on; a wrap-serializer drops the new keys when unset so flag-off output is byte-identical to today.

**Tech Stack:** Python 3.12, Pydantic v2, Typer, pytest, uv.

**Spec:** `docs/superpowers/specs/2026-09-23-benchmark-static-findings-design.md`

## Global Constraints

- Follow `CLAUDE.md`: explicit type hints everywhere, built-in generics, `X | None`, `Final`/`ClassVar`, `StrEnum` for constant sets, Google-style docstrings on public functions/classes, no new `@staticmethod` (use `@classmethod` or module functions), imports sorted stdlib → third-party → local.
- Tests import modules without the `llm_scanner.` prefix (`pythonpath = "llm_scanner"`), e.g. `from models.context import Context`.
- Run checks with `uv run` (no venv activation).
- **Do NOT create git commits** (user preference). Each task ends with a verification step instead of a commit.
- Flag-off dataset JSON must be byte-identical to today's output: no new keys, no `null` values.
- `snippet_line` is 1-based and indexes `BenchmarkSample.code.split("\n")`.
- `_CACHE_SCHEMA_VERSION` becomes `3`; the flag is **not** part of the cache key.

## Review Focus

1. **Finding on a line that is not rendered** (blank line, comment-only line, collapsed duplicate boilerplate, or cut by token budget) → the finding is dropped, never attached to a wrong line. Pinned in Task 4 (`test_attach_drops_unrendered_finding`) and Task 3 (`test_source_map_skips_blank_and_comment_lines`).
2. **Multi-line Bandit finding whose primary line is not rendered but a later line of its range is** → attached at the first rendered line of the range. Pinned in Task 4 (`test_attach_falls_back_to_first_rendered_line_in_range`).
3. **Same line number in two different files** → resolved by file, not by line only. Pinned in Task 2 (`test_resolve_distinguishes_files`).
4. **Old dataset JSON (without the new keys) loaded into the new `BenchmarkSample`** → loads, fields are `None`. Pinned in Task 5 (`test_old_payload_still_loads`).
5. **Stale Phase-1 pickle from schema v2** → cache key changes so it is not reused. Pinned in Task 6 (`test_cache_key_uses_schema_v3`).

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `llm_scanner/models/nodes/finding.py` | modify | `FindingNode` keeps `reason`, `rule_id`, `column_number`, `line_end` |
| `llm_scanner/models/bandit_report.py` | modify | `BanditIssue.test_id` |
| `llm_scanner/clients/analyzers/bandit.py` | modify | parse `test_id` |
| `llm_scanner/services/analyzer/bandit.py`, `.../dlint.py` | modify | payloads fill `rule_id` / `line_end` / keep column |
| `llm_scanner/models/context.py` | modify | `SnippetSegment`; `Context.source_map`, `Context.static_findings` |
| `llm_scanner/services/context_assembler/source_map.py` | create | `RenderedLine`, `build_source_map`, `resolve_snippet_line` |
| `llm_scanner/services/context_assembler/context_assembler.py` | modify | `_render_lines`; `_render_context` returns source map |
| `llm_scanner/models/static_finding.py` | create | `AnalyzerTool`, `StaticFinding` |
| `llm_scanner/services/benchmark/static_findings.py` | create | `attach_findings` |
| `llm_scanner/models/benchmark/benchmark.py` | modify | `BenchmarkSample.static_findings`/`source_map` + serializer |
| `llm_scanner/services/benchmark/prepared_sample.py` | modify | `static_findings` field, schema v3 |
| `llm_scanner/services/benchmark/cleanvul_benchmark.py` | modify | flag, capture findings, attach, `_to_sample` |
| `llm_scanner/cli.py` | modify | `--include-static-findings` on 3 commands |

---

### Task 1: Keep full analyzer data on findings

**Files:**
- Modify: `llm_scanner/models/nodes/finding.py`
- Modify: `llm_scanner/models/bandit_report.py`
- Modify: `llm_scanner/clients/analyzers/bandit.py:40-48`
- Modify: `llm_scanner/services/analyzer/bandit.py` (`_issue_payload`)
- Modify: `llm_scanner/services/analyzer/dlint.py` (`_issue_payload`)
- Test: `tests/services/analyzer/test_bandit_analyzer_service.py`, `tests/services/analyzer/test_dlint_analyzer_service.py`
- Create test: `tests/clients/test_bandit_static_analyzer.py`

**Interfaces:**
- Produces: `FindingNode` fields `line_end: int | None = None`, `column_number: int = 0`, `rule_id: str = ""`, `reason: str = ""` (inherited by `BanditFindingNode`, `DlintFindingNode`). `BanditIssue.test_id: str = ""`.

- [ ] **Step 1: Write/replace the failing tests**

In `tests/services/analyzer/test_bandit_analyzer_service.py`, **replace** `test_issue_payload_removes_column_number_and_line_range` with:

```python
def test_issue_payload_keeps_column_and_converts_line_range(
    bandit_service: BanditAnalyzerService,
) -> None:
    issue = BanditIssue(
        cwe=22,
        file=Path("test.py"),
        line_number=1,
        column_number=4,
        line_range=[1, 5],
        severity=IssueSeverity.LOW,
        reason="test",
        test_id="B605",
    )

    payload = bandit_service._issue_payload(issue)

    assert payload["column_number"] == 4
    assert payload["line_end"] == 5
    assert payload["rule_id"] == "B605"
    assert "line_range" not in payload
    assert "test_id" not in payload


def test_issue_payload_empty_line_range_gives_no_line_end(
    bandit_service: BanditAnalyzerService,
) -> None:
    issue = BanditIssue(
        cwe=22,
        file=Path("test.py"),
        line_number=3,
        column_number=0,
        line_range=[],
        severity=IssueSeverity.LOW,
        reason="test",
    )

    payload = bandit_service._issue_payload(issue)

    assert payload["line_end"] is None
    assert payload["rule_id"] == ""


def test_bandit_finding_node_keeps_reason_and_rule(
    bandit_service: BanditAnalyzerService,
) -> None:
    issue = BanditIssue(
        cwe=78,
        file=Path("app.py"),
        line_number=7,
        column_number=2,
        line_range=[7],
        severity=IssueSeverity.HIGH,
        reason="shell=True",
        test_id="B602",
    )

    finding = BanditFindingNode(**bandit_service._issue_payload(issue))

    assert finding.reason == "shell=True"
    assert finding.rule_id == "B602"
    assert finding.line_end == 7
    assert finding.column_number == 2
```

In `tests/services/analyzer/test_dlint_analyzer_service.py`, in `test_issue_payload_includes_issue_id` **replace** the last two assertions (`assert "code" not in payload` / `assert "column_number" not in payload`) with:

```python
    assert payload["rule_id"] == "DUO123"
    assert payload["column_number"] == 5
    assert "code" not in payload
```

and **replace** `test_issue_payload_removes_code_and_column_number` with:

```python
def test_issue_payload_moves_code_to_rule_id(dlint_service: DlintAnalyzerService) -> None:
    issue = DlintIssue(
        code="DUO105",
        file=Path("test.py"),
        line_number=1,
        column_number=0,
        reason="test",
    )

    payload = dlint_service._issue_payload(issue)

    assert "code" not in payload
    assert payload["rule_id"] == "DUO105"
    assert payload["issue_id"] == 105
```

Create `tests/clients/test_bandit_static_analyzer.py`:

```python
"""Tests for Bandit JSON report parsing."""

import json
import subprocess
from pathlib import Path

import pytest

from clients.analyzers.bandit import BanditStaticAnalyzer


def test_run_parses_test_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    report: dict[str, object] = {
        "results": [
            {
                "filename": str(tmp_path / "app.py"),
                "issue_cwe": {"id": 78},
                "issue_severity": "HIGH",
                "issue_text": "subprocess call with shell=True",
                "line_number": 3,
                "col_offset": 4,
                "line_range": [3, 4],
                "test_id": "B602",
            }
        ]
    }

    def _fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        Path(args[args.index("-o") + 1]).write_text(json.dumps(report), encoding="utf-8")
        return subprocess.CompletedProcess(args=args, returncode=1)

    monkeypatch.setattr("clients.analyzers.bandit.subprocess.run", _fake_run)

    result = BanditStaticAnalyzer(src=tmp_path).run()

    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.test_id == "B602"
    assert issue.reason == "subprocess call with shell=True"
    assert issue.line_range == [3, 4]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/services/analyzer tests/clients/test_bandit_static_analyzer.py -v`
Expected: FAIL (`test_id` unexpected keyword / missing `rule_id`, `line_end` keys).

- [ ] **Step 3: Implement**

`llm_scanner/models/nodes/finding.py` — replace `FindingNode`:

```python
class FindingNode(BaseModel):
    identifier: UUID = Field(default_factory=uuid4)
    file: Path
    line_number: int
    line_end: int | None = Field(
        default=None,
        description="Last line of the reported range; None for single-line findings",
    )
    column_number: int = Field(default=0, ge=0, description="Reported column offset")
    rule_id: str = Field(default="", description="Analyzer rule id, e.g. B602 or DUO102")
    reason: str = Field(default="", description="Analyzer message")
```

`llm_scanner/models/bandit_report.py` — add to `BanditIssue` (after `line_range`):

```python
    test_id: str = ""
```

`llm_scanner/clients/analyzers/bandit.py` — in the `BanditIssue(...)` call add:

```python
                    test_id=report.get("test_id", ""),
```

`llm_scanner/services/analyzer/bandit.py` — replace the body of `_issue_payload` (keep the docstring, update it to say "Finding payload with cwe_id, rule_id and line_end."):

```python
        payload = issue.model_dump()
        payload["cwe_id"] = payload.pop("cwe", None)
        payload["rule_id"] = payload.pop("test_id", "")
        line_range: list[int] = payload.pop("line_range", [])
        payload["line_end"] = max(line_range) if line_range else None
        return payload
```

`llm_scanner/services/analyzer/dlint.py` — replace the body of `_issue_payload` (docstring: "Finding payload with issue_id and rule_id."):

```python
        payload = issue.model_dump()
        payload["issue_id"] = issue.id
        payload["rule_id"] = payload.pop("code")
        return payload
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/services/analyzer tests/clients tests/repositories -v`
Expected: PASS (repository tests still pass — they don't touch new fields).

---

### Task 2: Source-map model and helpers

**Files:**
- Modify: `llm_scanner/models/context.py`
- Create: `llm_scanner/services/context_assembler/source_map.py`
- Test: `tests/services/context_assembler/test_source_map.py`

**Interfaces:**
- Produces:
  - `models.context.SnippetSegment(file_path: Path, snippet_line_start: int, snippet_line_end: int, repo_lines: tuple[int, ...])` — validates `snippet_line_start >= 1` and `len(repo_lines) == snippet_line_end - snippet_line_start + 1` (raises `ValueError`, surfaced by Pydantic as `ValidationError`).
  - `services.context_assembler.source_map.RenderedLine: TypeAlias = tuple[Path, int, str]` — `(file_path, repo_line, text)`.
  - `build_source_map(rendered_lines: Sequence[RenderedLine]) -> list[SnippetSegment]`
  - `resolve_snippet_line(source_map: Sequence[SnippetSegment], file_path: Path, repo_line: int) -> int | None`

- [ ] **Step 1: Write the failing tests**

Create `tests/services/context_assembler/test_source_map.py`:

```python
"""Tests for snippet ↔ repo source-map helpers."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from models.context import SnippetSegment
from services.context_assembler.source_map import (
    RenderedLine,
    build_source_map,
    resolve_snippet_line,
)


def test_build_groups_consecutive_lines_per_file() -> None:
    rendered: list[RenderedLine] = [
        (Path("a.py"), 1, "def a():"),
        (Path("a.py"), 3, "    return 1"),
        (Path("b.py"), 10, "def b():"),
    ]

    segments = build_source_map(rendered)

    assert segments == [
        SnippetSegment(
            file_path=Path("a.py"), snippet_line_start=1, snippet_line_end=2, repo_lines=(1, 3)
        ),
        SnippetSegment(
            file_path=Path("b.py"), snippet_line_start=3, snippet_line_end=3, repo_lines=(10,)
        ),
    ]


def test_build_empty_input_gives_empty_map() -> None:
    assert build_source_map([]) == []


def test_resolve_hit_and_miss() -> None:
    segments = build_source_map(
        [(Path("a.py"), 1, "x"), (Path("a.py"), 3, "y"), (Path("a.py"), 4, "z")]
    )

    assert resolve_snippet_line(segments, Path("a.py"), 3) == 2
    assert resolve_snippet_line(segments, Path("a.py"), 2) is None
    assert resolve_snippet_line(segments, Path("c.py"), 1) is None


def test_resolve_distinguishes_files() -> None:
    segments = build_source_map([(Path("a.py"), 5, "x"), (Path("b.py"), 5, "y")])

    assert resolve_snippet_line(segments, Path("a.py"), 5) == 1
    assert resolve_snippet_line(segments, Path("b.py"), 5) == 2


def test_segment_rejects_length_mismatch() -> None:
    with pytest.raises(ValidationError):
        SnippetSegment(
            file_path=Path("a.py"), snippet_line_start=1, snippet_line_end=3, repo_lines=(1,)
        )


def test_segment_rejects_zero_start() -> None:
    with pytest.raises(ValidationError):
        SnippetSegment(
            file_path=Path("a.py"), snippet_line_start=0, snippet_line_end=0, repo_lines=(1,)
        )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/services/context_assembler/test_source_map.py -v`
Expected: FAIL with `ImportError` (`SnippetSegment` / `source_map` missing).

- [ ] **Step 3: Implement**

`llm_scanner/models/context.py` — change imports to:

```python
from pathlib import Path
from typing import NamedTuple, Self

from pydantic import BaseModel, Field, model_validator

from models.base import NodeID
```

Add before `class Context`:

```python
class SnippetSegment(BaseModel):
    """Maps a run of consecutive snippet lines from one file back to repo lines.

    ``repo_lines[i]`` is the repository line rendered at snippet line
    ``snippet_line_start + i``. Repo lines may be non-contiguous because blank
    and comment-only lines are dropped during rendering.
    """

    file_path: Path = Field(..., description="Repo-relative source file")
    snippet_line_start: int = Field(..., ge=1, description="1-based first snippet line")
    snippet_line_end: int = Field(..., ge=1, description="1-based last snippet line (inclusive)")
    repo_lines: tuple[int, ...] = Field(..., description="Repo line for each snippet line")

    @model_validator(mode="after")
    def _check_lengths(self) -> Self:
        expected = self.snippet_line_end - self.snippet_line_start + 1
        if len(self.repo_lines) != expected:
            raise ValueError(
                f"repo_lines has {len(self.repo_lines)} entries, expected {expected}"
            )
        return self
```

Add to `Context` (after `token_count`):

```python
    source_map: list[SnippetSegment] = Field(
        default_factory=list, description="Snippet line → repo location mapping"
    )
```

Create `llm_scanner/services/context_assembler/source_map.py`:

```python
"""Helpers mapping rendered snippet lines back to repository locations."""

from collections.abc import Sequence
from pathlib import Path
from typing import TypeAlias

from models.context import SnippetSegment

RenderedLine: TypeAlias = tuple[Path, int, str]


def build_source_map(rendered_lines: Sequence[RenderedLine]) -> list[SnippetSegment]:
    """Group rendered lines into per-file runs of consecutive snippet lines.

    Args:
        rendered_lines: ``(file_path, repo_line, text)`` in snippet order.

    Returns:
        Segments covering every rendered line exactly once, in snippet order.
    """

    segments: list[SnippetSegment] = []
    run_file: Path | None = None
    run_start = 1
    run_lines: list[int] = []
    for index, (file_path, repo_line, _) in enumerate(rendered_lines, start=1):
        if file_path != run_file and run_lines:
            segments.append(_segment(run_file, run_start, run_lines))
            run_lines = []
        if not run_lines:
            run_file = file_path
            run_start = index
        run_lines.append(repo_line)
    if run_lines:
        segments.append(_segment(run_file, run_start, run_lines))
    return segments


def resolve_snippet_line(
    source_map: Sequence[SnippetSegment], file_path: Path, repo_line: int
) -> int | None:
    """Return the 1-based snippet line showing ``file_path:repo_line``, if rendered.

    Args:
        source_map: Segments produced by ``build_source_map``.
        file_path: Repo-relative file path.
        repo_line: 1-based repository line.

    Returns:
        Snippet line number, or ``None`` when that repo line is not in the snippet.
    """

    for segment in source_map:
        if segment.file_path != file_path or repo_line not in segment.repo_lines:
            continue
        return segment.snippet_line_start + segment.repo_lines.index(repo_line)
    return None


def _segment(file_path: Path | None, start: int, repo_lines: list[int]) -> SnippetSegment:
    if file_path is None:
        raise ValueError("Cannot build a segment without a file path")
    return SnippetSegment(
        file_path=file_path,
        snippet_line_start=start,
        snippet_line_end=start + len(repo_lines) - 1,
        repo_lines=tuple(repo_lines),
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/services/context_assembler/test_source_map.py -v`
Expected: PASS.

---

### Task 3: Renderer emits the source map

**Files:**
- Modify: `llm_scanner/services/context_assembler/context_assembler.py` (`assemble_from_nodes` ~L328, `_render_context` ~L359, `_render_text` ~L544)
- Test: `tests/services/context_assembler/test_render_source_map.py`

**Interfaces:**
- Consumes: `RenderedLine`, `build_source_map` (Task 2), `Context.source_map` (Task 2).
- Produces: `ContextAssemblerService.assemble_from_nodes(...)` returns `Context` with `source_map` populated; `ContextAssemblerService._render_lines(read_lines, lines_to_keep) -> list[RenderedLine]` (classmethod); `_render_context(...) -> tuple[str, int, list[SnippetSegment]]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/services/context_assembler/test_render_source_map.py`:

```python
"""The rendered snippet must carry an exact snippet → repo source map."""

from pathlib import Path

from models.base import NodeID
from models.context import CodeContextNode
from services.context_assembler.context_assembler import ContextAssemblerService
from services.context_assembler.source_map import resolve_snippet_line
from services.ranking.ranking import DummyNodeRankingStrategy

_A_BODY = (
    "logger = logging.getLogger(__name__)\n"
    "def handler(cmd):\n"
    "\n"
    "    # only a comment\n"
    "    os.system(cmd)  # trailing comment\n"
)
_B_BODY = "logger = logging.getLogger(__name__)\ndef other():\n    return eval(x)\n"


def _node(name: str, file_path: str, line_end: int) -> CodeContextNode:
    return CodeContextNode(
        identifier=NodeID(f"function:{name}"),
        node_kind="FunctionNode",
        name=name,
        file_path=Path(file_path),
        line_start=1,
        line_end=line_end,
        depth=0,
    )


def _assemble(tmp_path: Path) -> tuple[str, list[str], ContextAssemblerService]:
    (tmp_path / "a.py").write_text(_A_BODY, encoding="utf-8")
    (tmp_path / "b.py").write_text(_B_BODY, encoding="utf-8")
    service = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=None,
        cached_neighborhood_edges=[],
        max_call_depth=2,
        token_budget=10_000,
        ranking_strategy=DummyNodeRankingStrategy(),
    )
    context = service.assemble_from_nodes(
        tmp_path, [_node("handler", "a.py", 5), _node("other", "b.py", 3)]
    )
    return context.context_text, context.context_text.split("\n"), service


def test_every_mapped_line_matches_sanitized_repo_line(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(_A_BODY, encoding="utf-8")
    (tmp_path / "b.py").write_text(_B_BODY, encoding="utf-8")
    service = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=None,
        cached_neighborhood_edges=[],
        max_call_depth=2,
        token_budget=10_000,
        ranking_strategy=DummyNodeRankingStrategy(),
    )
    context = service.assemble_from_nodes(
        tmp_path, [_node("handler", "a.py", 5), _node("other", "b.py", 3)]
    )
    code_lines = context.context_text.split("\n")

    covered = sum(len(segment.repo_lines) for segment in context.source_map)
    assert covered == len(code_lines)
    for segment in context.source_map:
        repo_text = (tmp_path / segment.file_path).read_text(encoding="utf-8").splitlines()
        for offset, repo_line in enumerate(segment.repo_lines):
            expected = ContextAssemblerService._sanitize_line(repo_text[repo_line - 1])
            assert code_lines[segment.snippet_line_start - 1 + offset] == expected


def test_source_map_skips_blank_and_comment_lines(tmp_path: Path) -> None:
    text, code_lines, _ = _assemble(tmp_path)

    assert "" not in code_lines
    assert "# only a comment" not in text


def test_duplicate_boilerplate_is_mapped_once(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(_A_BODY, encoding="utf-8")
    (tmp_path / "b.py").write_text(_B_BODY, encoding="utf-8")
    service = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=None,
        cached_neighborhood_edges=[],
        max_call_depth=2,
        token_budget=10_000,
        ranking_strategy=DummyNodeRankingStrategy(),
    )
    context = service.assemble_from_nodes(
        tmp_path, [_node("handler", "a.py", 5), _node("other", "b.py", 3)]
    )

    first = resolve_snippet_line(context.source_map, Path("a.py"), 1)
    second = resolve_snippet_line(context.source_map, Path("b.py"), 1)
    assert (first is None) != (second is None)
    assert resolve_snippet_line(context.source_map, Path("a.py"), 3) is None
    assert resolve_snippet_line(context.source_map, Path("a.py"), 4) is None
    sink = resolve_snippet_line(context.source_map, Path("a.py"), 5)
    assert sink is not None
    assert context.context_text.split("\n")[sink - 1] == "    os.system(cmd)"


def test_empty_render_has_empty_source_map(tmp_path: Path) -> None:
    service = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=None,
        cached_neighborhood_edges=[],
        max_call_depth=2,
        token_budget=10_000,
        ranking_strategy=DummyNodeRankingStrategy(),
    )

    context = service.assemble_from_nodes(tmp_path, [])

    assert context.context_text == ""
    assert context.source_map == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/services/context_assembler/test_render_source_map.py -v`
Expected: FAIL — `context.source_map` is always `[]` (coverage assertion fails).

- [ ] **Step 3: Implement**

In `context_assembler.py` add imports (local group, alphabetical):

```python
from models.context import CodeContextNode, Context, FileSpans, SnippetSegment
from services.context_assembler.source_map import RenderedLine, build_source_map
```

(adjust the existing `models.context` import line rather than adding a duplicate).

Replace `assemble_from_nodes` body:

```python
        cloned_nodes: list[CodeContextNode] = [node.model_copy(deep=True) for node in nodes]
        context_text, token_count, source_map = self._render_context(repo_path, cloned_nodes)

        return Context(
            description="Finding from spans query",
            context_text=context_text,
            token_count=token_count,
            source_map=source_map,
        )
```

In `_render_context`: change the signature return type to `tuple[str, int, list[SnippetSegment]]`, update the docstring "Returns:" to "Tuple of rendered context text, token count and snippet source map.", change `return "", 0` to `return "", 0, []`, and replace

```python
        candidate_text = self._render_text(read_lines, lines_to_keep)

        if not candidate_text:
            _LOGGER.warning("Empty snippet for project %s", repo_path)

        return candidate_text, self._estimate_tokens(candidate_text)
```

with

```python
        rendered_lines = self._render_lines(read_lines, lines_to_keep)
        candidate_text = "\n".join(text for _, _, text in rendered_lines)

        if not candidate_text:
            _LOGGER.warning("Empty snippet for project %s", repo_path)

        return (
            candidate_text,
            self._estimate_tokens(candidate_text),
            build_source_map(rendered_lines),
        )
```

Replace the `_render_text` staticmethod with:

```python
    @classmethod
    def _render_lines(
        cls,
        read_lines: dict[Path, dict[int, str]],
        lines_to_keep: dict[Path, set[int]],
    ) -> list[RenderedLine]:
        """Return rendered lines with provenance, in output order.

        Empty lines are skipped and exact-duplicate module-level boilerplate
        lines (e.g. repeated ``logger = logging.getLogger(__name__)``) are
        collapsed to their first occurrence; all other lines are kept verbatim.
        """

        rendered: list[RenderedLine] = []
        seen_boilerplate: set[str] = set()
        for file_path, lines in lines_to_keep.items():
            file_lines = read_lines.get(file_path, {})
            for line_number in sorted(lines):
                line = file_lines.get(line_number, "").rstrip()
                if not line:
                    continue
                if any(pattern.match(line) for pattern in _BOILERPLATE_LINE_PATTERNS):
                    if line in seen_boilerplate:
                        continue
                    seen_boilerplate.add(line)
                rendered.append((file_path, line_number, line))
        return rendered

    @classmethod
    def _render_text(
        cls,
        read_lines: dict[Path, dict[int, str]],
        lines_to_keep: dict[Path, set[int]],
    ) -> str:
        """Render the final text from the chosen line set per file."""

        return "\n".join(text for _, _, text in cls._render_lines(read_lines, lines_to_keep))
```

- [ ] **Step 4: Run tests to verify they pass (and nothing regressed)**

Run: `uv run pytest tests/services/context_assembler -v`
Expected: PASS, including existing `test_render_dedupe.py`, `test_render_sanitize.py`, `test_cached_neighborhood_edges.py`, `test_path_fill.py`.

---

### Task 4: `StaticFinding` model and `attach_findings`

**Files:**
- Create: `llm_scanner/models/static_finding.py`
- Modify: `llm_scanner/models/context.py` (add `Context.static_findings`)
- Create: `llm_scanner/services/benchmark/static_findings.py`
- Test: `tests/services/benchmark/test_static_findings.py`

**Interfaces:**
- Consumes: `FindingNode`/`BanditFindingNode`/`DlintFindingNode` (Task 1), `SnippetSegment`, `build_source_map`, `resolve_snippet_line` (Task 2).
- Produces:
  - `models.static_finding.AnalyzerTool(StrEnum)`: `BANDIT = "bandit"`, `DLINT = "dlint"`.
  - `models.static_finding.StaticFinding` with fields `tool: AnalyzerTool`, `rule_id: str`, `cwe_id: int | None`, `severity: IssueSeverity | None`, `message: str`, `file_path: Path`, `repo_line: int`, `snippet_line: int (ge=1)`, `is_root: bool`.
  - `Context.static_findings: list[StaticFinding]` (default `[]`).
  - `services.benchmark.static_findings.attach_findings(findings: Sequence[FindingNode], source_map: Sequence[SnippetSegment], root_nodes: Sequence[CodeContextNode]) -> list[StaticFinding]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/services/benchmark/test_static_findings.py`:

```python
"""Tests for attaching analyzer findings to rendered snippets."""

from pathlib import Path

from models.bandit_report import IssueSeverity
from models.base import NodeID
from models.context import CodeContextNode
from models.nodes.finding import BanditFindingNode, DlintFindingNode
from models.static_finding import AnalyzerTool
from services.benchmark.static_findings import attach_findings
from services.context_assembler.source_map import build_source_map

_SOURCE_MAP = build_source_map(
    [
        (Path("app.py"), 10, "def run(cmd):"),
        (Path("app.py"), 12, "    os.system(cmd)"),
        (Path("util.py"), 3, "def helper():"),
        (Path("util.py"), 4, "    return eval(x)"),
    ]
)
_ROOT = CodeContextNode(
    identifier=NodeID("function:run"),
    file_path=Path("app.py"),
    line_start=10,
    line_end=12,
    depth=0,
)


def _bandit(line: int, *, file: str = "app.py", line_end: int | None = None) -> BanditFindingNode:
    return BanditFindingNode(
        file=Path(file),
        line_number=line,
        line_end=line_end,
        cwe_id=78,
        severity=IssueSeverity.HIGH,
        rule_id="B605",
        reason="Starting a process with a shell",
    )


def test_attach_bandit_finding_on_root_line() -> None:
    [finding] = attach_findings([_bandit(12)], _SOURCE_MAP, [_ROOT])

    assert finding.tool is AnalyzerTool.BANDIT
    assert finding.rule_id == "B605"
    assert finding.cwe_id == 78
    assert finding.severity is IssueSeverity.HIGH
    assert finding.message == "Starting a process with a shell"
    assert finding.file_path == Path("app.py")
    assert finding.repo_line == 12
    assert finding.snippet_line == 2
    assert finding.is_root is True


def test_attach_dlint_finding_outside_root() -> None:
    dlint = DlintFindingNode(
        file=Path("util.py"), line_number=4, issue_id=104, rule_id="DUO104", reason="eval"
    )

    [finding] = attach_findings([dlint], _SOURCE_MAP, [_ROOT])

    assert finding.tool is AnalyzerTool.DLINT
    assert finding.cwe_id is None
    assert finding.severity is None
    assert finding.snippet_line == 4
    assert finding.is_root is False


def test_attach_drops_unrendered_finding() -> None:
    assert attach_findings([_bandit(11)], _SOURCE_MAP, [_ROOT]) == []
    assert attach_findings([_bandit(12, file="other.py")], _SOURCE_MAP, [_ROOT]) == []


def test_attach_falls_back_to_first_rendered_line_in_range() -> None:
    [finding] = attach_findings([_bandit(11, line_end=12)], _SOURCE_MAP, [_ROOT])

    assert finding.snippet_line == 2
    assert finding.repo_line == 11


def test_attach_sorts_and_dedupes() -> None:
    dlint = DlintFindingNode(
        file=Path("app.py"), line_number=10, issue_id=102, rule_id="DUO102", reason="x"
    )

    findings = attach_findings([_bandit(12), dlint, _bandit(12)], _SOURCE_MAP, [_ROOT])

    assert [(f.snippet_line, f.rule_id) for f in findings] == [(1, "DUO102"), (2, "B605")]


def test_attach_with_empty_inputs() -> None:
    assert attach_findings([], _SOURCE_MAP, [_ROOT]) == []
    assert attach_findings([_bandit(12)], [], [_ROOT]) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/services/benchmark/test_static_findings.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'models.static_finding'`.

- [ ] **Step 3: Implement**

Create `llm_scanner/models/static_finding.py`:

```python
"""Static-analysis finding resolved to a location inside a rendered snippet."""

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from models.bandit_report import IssueSeverity


class AnalyzerTool(StrEnum):
    """Static analyzers whose findings can be attached to a snippet."""

    BANDIT = "bandit"
    DLINT = "dlint"


class StaticFinding(BaseModel):
    """Analyzer report located both in the repository and in the rendered snippet."""

    tool: AnalyzerTool = Field(..., description="Analyzer that produced the report")
    rule_id: str = Field(..., description="Analyzer rule id, e.g. B602 or DUO102")
    cwe_id: int | None = Field(default=None, description="CWE id (Bandit only)")
    severity: IssueSeverity | None = Field(default=None, description="Severity (Bandit only)")
    message: str = Field(..., description="Analyzer message")
    file_path: Path = Field(..., description="Repo-relative file path")
    repo_line: int = Field(..., ge=1, description="1-based line in the repository file")
    snippet_line: int = Field(..., ge=1, description="1-based line in the rendered snippet")
    is_root: bool = Field(..., description="True if the line lies inside a root node")
```

`llm_scanner/models/context.py` — add import `from models.static_finding import StaticFinding` (local group, after `models.base`) and add to `Context` after `source_map`:

```python
    static_findings: list[StaticFinding] = Field(
        default_factory=list, description="Analyzer findings located in the snippet"
    )
```

Create `llm_scanner/services/benchmark/static_findings.py`:

```python
"""Attach static-analysis findings to a rendered snippet via its source map."""

from collections.abc import Sequence

from models.context import CodeContextNode, SnippetSegment
from models.nodes.finding import BanditFindingNode, DlintFindingNode, FindingNode
from models.static_finding import AnalyzerTool, StaticFinding
from services.context_assembler.source_map import resolve_snippet_line


def attach_findings(
    findings: Sequence[FindingNode],
    source_map: Sequence[SnippetSegment],
    root_nodes: Sequence[CodeContextNode],
) -> list[StaticFinding]:
    """Resolve analyzer findings to snippet lines, dropping unrendered ones.

    A finding resolves to the snippet line of its reported line; when that line
    is not rendered, to the first rendered line of ``[line_number, line_end]``.

    Args:
        findings: Bandit/Dlint findings with repo-relative locations.
        source_map: Source map of the rendered snippet.
        root_nodes: Depth-0 context nodes, used to compute ``is_root``.

    Returns:
        Unique findings sorted by ``(snippet_line, tool, rule_id)``.
    """

    resolved: dict[tuple[AnalyzerTool, str, str, int], StaticFinding] = {}
    for finding in findings:
        static_finding = _to_static_finding(finding, source_map, root_nodes)
        if static_finding is None:
            continue
        key = (
            static_finding.tool,
            static_finding.rule_id,
            str(static_finding.file_path),
            static_finding.repo_line,
        )
        resolved.setdefault(key, static_finding)
    return sorted(resolved.values(), key=lambda f: (f.snippet_line, f.tool, f.rule_id))


def _to_static_finding(
    finding: FindingNode,
    source_map: Sequence[SnippetSegment],
    root_nodes: Sequence[CodeContextNode],
) -> StaticFinding | None:
    snippet_line = _resolve_range(finding, source_map)
    if snippet_line is None:
        return None
    return StaticFinding(
        tool=_tool_for(finding),
        rule_id=finding.rule_id,
        cwe_id=finding.cwe_id if isinstance(finding, BanditFindingNode) else None,
        severity=finding.severity if isinstance(finding, BanditFindingNode) else None,
        message=finding.reason,
        file_path=finding.file,
        repo_line=finding.line_number,
        snippet_line=snippet_line,
        is_root=any(
            node.file_path == finding.file
            and node.line_start <= finding.line_number <= node.line_end
            for node in root_nodes
        ),
    )


def _resolve_range(finding: FindingNode, source_map: Sequence[SnippetSegment]) -> int | None:
    last_line = max(finding.line_number, finding.line_end or finding.line_number)
    for repo_line in range(finding.line_number, last_line + 1):
        snippet_line = resolve_snippet_line(source_map, finding.file, repo_line)
        if snippet_line is not None:
            return snippet_line
    return None


def _tool_for(finding: FindingNode) -> AnalyzerTool:
    if isinstance(finding, BanditFindingNode):
        return AnalyzerTool.BANDIT
    if isinstance(finding, DlintFindingNode):
        return AnalyzerTool.DLINT
    raise TypeError(f"Unsupported finding type: {type(finding).__name__}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/services/benchmark/test_static_findings.py tests/services/context_assembler tests/models -v`
Expected: PASS.

---

### Task 5: `BenchmarkSample` optional fields + serializer

**Files:**
- Modify: `llm_scanner/models/benchmark/benchmark.py`
- Test: `tests/models/test_benchmark_sample.py`

**Interfaces:**
- Consumes: `StaticFinding` (Task 4), `SnippetSegment` (Task 2).
- Produces: `BenchmarkSample.static_findings: list[StaticFinding] | None = None`, `BenchmarkSample.source_map: list[SnippetSegment] | None = None`; both keys absent from `model_dump()` when `None`.

- [ ] **Step 1: Write the failing tests**

Create `tests/models/test_benchmark_sample.py`:

```python
"""Serialization tests for the optional BenchmarkSample enrichment fields."""

from pathlib import Path

from models.benchmark.benchmark import BenchmarkSample, CleanVulSampleMetadata
from models.context import SnippetSegment
from models.static_finding import AnalyzerTool, StaticFinding

_BASE: dict[str, object] = {
    "id": "s-1",
    "code": "def f():\n    os.system(x)",
    "label": 1,
    "metadata": CleanVulSampleMetadata(commit_url="https://x/commit/1"),
    "severity": "unknown",
}


def test_absent_fields_are_omitted() -> None:
    dumped = BenchmarkSample.model_validate(_BASE).model_dump(by_alias=True)

    assert "static_findings" not in dumped
    assert "source_map" not in dumped
    assert dumped["metadata"]["cwe_number"] is None


def test_present_fields_are_serialized() -> None:
    sample = BenchmarkSample.model_validate(
        {
            **_BASE,
            "static_findings": [
                StaticFinding(
                    tool=AnalyzerTool.BANDIT,
                    rule_id="B605",
                    message="shell",
                    file_path=Path("a.py"),
                    repo_line=7,
                    snippet_line=2,
                    is_root=True,
                )
            ],
            "source_map": [
                SnippetSegment(
                    file_path=Path("a.py"),
                    snippet_line_start=1,
                    snippet_line_end=2,
                    repo_lines=(6, 7),
                )
            ],
        }
    )

    dumped = sample.model_dump(by_alias=True)

    assert dumped["static_findings"][0]["snippet_line"] == 2
    assert dumped["static_findings"][0]["tool"] == "bandit"
    assert dumped["source_map"][0]["repo_lines"] == (6, 7)


def test_empty_lists_are_kept() -> None:
    sample = BenchmarkSample.model_validate({**_BASE, "static_findings": [], "source_map": []})

    dumped = sample.model_dump()

    assert dumped["static_findings"] == []
    assert dumped["source_map"] == []


def test_old_payload_still_loads() -> None:
    payload = {**_BASE, "metadata": {"commit_url": "https://x/commit/1"}}

    sample = BenchmarkSample.model_validate(payload)

    assert sample.static_findings is None
    assert sample.source_map is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/models/test_benchmark_sample.py -v`
Expected: FAIL (`static_findings` unknown/ignored → `sample.static_findings` AttributeError, present-fields test KeyError).

- [ ] **Step 3: Implement**

In `llm_scanner/models/benchmark/benchmark.py` replace imports with:

```python
from typing import ClassVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
)

from models.context import SnippetSegment
from models.static_finding import StaticFinding
```

Add to `BenchmarkSample` (after `severity`):

```python
    static_findings: list[StaticFinding] | None = Field(
        default=None,
        description="Analyzer findings located in `code` (only with --include-static-findings)",
    )
    source_map: list[SnippetSegment] | None = Field(
        default=None,
        description="`code` line → repo location mapping (only with --include-static-findings)",
    )

    _OPTIONAL_ENRICHMENT_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {"static_findings", "source_map"}
    )

    @model_serializer(mode="wrap")
    def _drop_absent_enrichment(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, object]:
        """Omit enrichment keys that were not requested, keeping legacy output unchanged."""

        data: dict[str, object] = handler(self)
        return {
            key: value
            for key, value in data.items()
            if not (key in self._OPTIONAL_ENRICHMENT_FIELDS and value is None)
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/models tests/services/benchmark -v`
Expected: PASS (existing benchmark tests unaffected).

---

### Task 6: Benchmark service wiring + prepared-sample cache

**Files:**
- Modify: `llm_scanner/services/benchmark/prepared_sample.py`
- Modify: `llm_scanner/services/benchmark/cleanvul_benchmark.py` (field list ~L60-110, `_prepare_one_side` ~L249, `build_all_from_prepared` ~L327, `_scan_repository_for_entry` ~L658, `_render_contexts_from_shared_inputs` ~L755, `_to_sample` ~L815)
- Test: `tests/services/benchmark/test_cleanvul_benchmark_static_findings.py`, `tests/services/benchmark/test_prepared_sample_cache_key.py`

**Interfaces:**
- Consumes: `attach_findings` (Task 4), `Context.static_findings`/`Context.source_map` (Tasks 2, 4), `BenchmarkSample` fields (Task 5).
- Produces: `CleanVulBenchmarkService.include_static_findings: bool = False`; `PreparedSample.static_findings: list[FindingNode] = []`; `_render_contexts_from_shared_inputs(..., findings: Sequence[FindingNode] = ())`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/services/benchmark/test_prepared_sample_cache_key.py`:

```python
def test_cache_key_uses_schema_v3() -> None:
    """Schema v3 adds static findings; v2 pickles must not be reused."""

    from services.benchmark import prepared_sample

    assert prepared_sample._CACHE_SCHEMA_VERSION == 3
```

Create `tests/services/benchmark/test_cleanvul_benchmark_static_findings.py`:

```python
"""Static-findings enrichment in the CleanVul benchmark service."""

import pickle
from pathlib import Path

from models.bandit_report import IssueSeverity
from models.base import NodeID
from models.benchmark.cleanvul import CleanVulEntry
from models.context import CodeContextNode, Context, FileSpans
from models.nodes.finding import BanditFindingNode
from services.benchmark.cleanvul_benchmark import CleanVulBenchmarkService, _SharedContextInputs
from services.benchmark.prepared_sample import (
    PreparedSample,
    load_prepared_sample,
    save_prepared_sample,
)
from services.benchmark.static_findings import attach_findings
from services.context_assembler.source_map import build_source_map
from services.ranking.ranking import DummyNodeRankingStrategy

_FINDING = BanditFindingNode(
    file=Path("app.py"),
    line_number=2,
    cwe_id=78,
    severity=IssueSeverity.HIGH,
    rule_id="B605",
    reason="shell",
)


def _entry() -> CleanVulEntry:
    return CleanVulEntry(
        commit_url="https://github.com/o/r/commit/abc",
        repo_url="https://github.com/o/r",
        fix_hash="abc",
        file_name="app.py",
        func_code="def run(cmd):\n    os.system(cmd)",
        files_spans=[FileSpans(Path("app.py"), [(1, 2)])],
        vulnerability_score=4,
        is_vulnerable=True,
    )


def _service(tmp_path: Path, *, include: bool) -> CleanVulBenchmarkService:
    return CleanVulBenchmarkService.model_validate(
        {
            "dataset_path": tmp_path / "cleanvul.csv",
            "output_dir": tmp_path / "out",
            "repo_cache_dir": tmp_path / "repos",
            "sample_count": 2,
            "max_call_depth": 2,
            "token_budget": 10_000,
            "include_static_findings": include,
            "strategy_factories": {"dummy": lambda _p: DummyNodeRankingStrategy()},
        }
    )


def _context_with_findings() -> Context:
    source_map = build_source_map(
        [(Path("app.py"), 1, "def run(cmd):"), (Path("app.py"), 2, "    os.system(cmd)")]
    )
    return Context(
        description="d",
        context_text="def run(cmd):\n    os.system(cmd)",
        token_count=5,
        source_map=source_map,
    )


def test_render_attaches_findings(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def run(cmd):\n    os.system(cmd)\n", encoding="utf-8")
    root = CodeContextNode(
        identifier=NodeID("function:run"),
        node_kind="FunctionNode",
        name="run",
        file_path=Path("app.py"),
        line_start=1,
        line_end=2,
        depth=0,
    )
    service = _service(tmp_path, include=True)

    contexts = service._render_contexts_from_shared_inputs(
        repo_path=tmp_path,
        context_repository=None,
        strategies={"dummy": DummyNodeRankingStrategy()},
        shared_inputs=_SharedContextInputs(
            root_ids=[str(root.identifier)],
            plain_context_nodes=[root],
            edge_path_context_nodes=[],
            taint_scores={},
        ),
        cached_neighborhood_edges=[],
        findings=[_FINDING],
    )

    [finding] = contexts["dummy"].static_findings
    assert finding.snippet_line == 2
    assert finding.is_root is True
    assert contexts["dummy"].context_text.split("\n")[finding.snippet_line - 1] == (
        "    os.system(cmd)"
    )


def test_to_sample_includes_enrichment_when_enabled(tmp_path: Path) -> None:
    service = _service(tmp_path, include=True)
    context = _context_with_findings()
    context = context.model_copy(
        update={"static_findings": attach_findings([_FINDING], context.source_map, [])}
    )
    assert len(context.static_findings) == 1

    sample = service._to_sample(_entry(), context, "s-1")

    assert sample.source_map == context.source_map
    assert sample.static_findings == context.static_findings


def test_to_sample_omits_enrichment_when_disabled(tmp_path: Path) -> None:
    service = _service(tmp_path, include=False)

    sample = service._to_sample(_entry(), _context_with_findings(), "s-1")
    dumped = sample.model_dump(by_alias=True)

    assert "static_findings" not in dumped
    assert "source_map" not in dumped


def test_prepared_sample_round_trips_findings(tmp_path: Path) -> None:
    sample = PreparedSample(
        entry=_entry(),
        repo_path=tmp_path,
        target_hash="abc",
        sample_id="s-1",
        root_ids=[],
        plain_context_nodes=[],
        edge_path_context_nodes=[],
        taint_scores={},
        neighborhood_edges=[],
        path_fill_edge_types=(),
        traversal_relationship_types=(),
        static_findings=[_FINDING],
        cache_key="k",
    )

    save_prepared_sample(tmp_path, sample)
    loaded = load_prepared_sample(tmp_path, "k")

    assert loaded is not None
    assert loaded.static_findings == [_FINDING]
    assert isinstance(loaded.static_findings[0], BanditFindingNode)
    assert pickle.dumps(loaded)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/services/benchmark/test_cleanvul_benchmark_static_findings.py tests/services/benchmark/test_prepared_sample_cache_key.py -v`
Expected: FAIL (`include_static_findings` rejected/ignored, unexpected `findings` kwarg, `static_findings` not a `PreparedSample` field, schema version is 2).

- [ ] **Step 3: Implement**

`llm_scanner/services/benchmark/prepared_sample.py`:
- Add import `from models.nodes.finding import FindingNode` (local group, after `models.context`).
- Change `_CACHE_SCHEMA_VERSION = 2` to `_CACHE_SCHEMA_VERSION = 3` and extend its comment: `# v3: PreparedSample.static_findings (analyzer findings for the checkout).`
- Add field to `PreparedSample` after `traversal_relationship_types`:

```python
    static_findings: list[FindingNode] = []
```

`llm_scanner/services/benchmark/cleanvul_benchmark.py`:
- Imports (local group, alphabetical): add `from models.nodes.finding import FindingNode` and `from services.benchmark.static_findings import attach_findings`.
- Add service field after `hub_fanin_threshold`:

```python
    include_static_findings: bool = Field(
        default=False,
        description=(
            "Attach Bandit/Dlint findings located in each rendered snippet plus a "
            "snippet→repo source map to every BenchmarkSample."
        ),
    )
```

- `_prepare_one_side`: replace
  `GeneralScannerPipeline(src=repo_path, neo4j_client=neo4j_client).build_cpg()`
  with
  `findings, _ = GeneralScannerPipeline(src=repo_path, neo4j_client=neo4j_client).build_cpg()`
  and pass `static_findings=findings,` in the `PreparedSample(...)` constructor.
- `build_all_from_prepared`: in the `_render_contexts_from_shared_inputs(...)` call add `findings=prepared.static_findings,`.
- `_scan_repository_for_entry`: same `findings, _ = ...build_cpg()` change, and pass `findings=findings,` to `_render_contexts_from_shared_inputs(...)`.
- `_render_contexts_from_shared_inputs`: add keyword parameter `findings: Sequence[FindingNode] = (),` after `cached_neighborhood_edges`, add to the docstring "``findings`` are resolved against each rendered snippet and stored on ``Context.static_findings``.", and replace

```python
            contexts[strategy_name] = context_service.assemble_from_nodes(repo_path, context_nodes)
```

with

```python
            context = context_service.assemble_from_nodes(repo_path, context_nodes)
            root_nodes = [node for node in context_nodes if node.depth == 0]
            contexts[strategy_name] = context.model_copy(
                update={
                    "static_findings": attach_findings(findings, context.source_map, root_nodes)
                }
            )
```

- `_to_sample`: replace the body with

```python
        return BenchmarkSample(
            id=sample_id,
            code=context.context_text,
            label=int(entry.is_vulnerable),
            metadata=self._entry_metadata(entry),
            cwe_types=[f"CWE-{n}" for n in entry.cwe_ids],
            severity="unknown",
            static_findings=context.static_findings if self.include_static_findings else None,
            source_map=context.source_map if self.include_static_findings else None,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/services/benchmark -v`
Expected: PASS, including the unchanged `test_cleanvul_benchmark_service.py` (its stubbed `_scan_repository_for_entry` still returns `dict[str, Context]`).

---

### Task 7: CLI flag

**Files:**
- Modify: `llm_scanner/cli.py` (`_run_compare_rankings` ~L164, `build_cleanvul_benchmark` ~L471, `build_cleanvul_benchmark_compare_rankings` ~L524, `build_cleanvul_benchmark_compare_rankings_all` ~L597)
- Test: `tests/test_cli_static_findings.py`

**Interfaces:**
- Consumes: `CleanVulBenchmarkService.include_static_findings` (Task 6).
- Produces: `--include-static-findings` option on the three commands.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli_static_findings.py`:

```python
"""The --include-static-findings flag reaches CleanVulBenchmarkService."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

import cli
from services.benchmark.cleanvul_benchmark import CleanVulBenchmarkService


@pytest.mark.parametrize(
    ("extra_args", "expected"),
    [([], False), (["--include-static-findings"], True)],
)
def test_build_cleanvul_benchmark_passes_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    extra_args: list[str],
    expected: bool,
) -> None:
    dataset = tmp_path / "cleanvul.csv"
    dataset.write_text("x\n", encoding="utf-8")
    seen: list[bool] = []

    def _fake_build(self: CleanVulBenchmarkService) -> tuple[Path, Path]:
        seen.append(self.include_static_findings)
        return tmp_path / "d.json", tmp_path / "e.json"

    monkeypatch.setattr(CleanVulBenchmarkService, "build", _fake_build)

    result = CliRunner().invoke(
        cli.app,
        [
            "build-cleanvul-benchmark",
            str(dataset),
            "--output-dir",
            str(tmp_path / "out"),
            "--repo-cache-dir",
            str(tmp_path / "repos"),
            *extra_args,
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen == [expected]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli_static_findings.py -v`
Expected: the `--include-static-findings` case FAILS with "No such option"; the default case may already pass.

- [ ] **Step 3: Implement**

In `llm_scanner/cli.py` add near the other module constants (after `DEFAULT_BENCHMARK_DIR`):

```python
_INCLUDE_STATIC_FINDINGS_HELP: Final[str] = (
    "Attach Bandit/Dlint findings located in each rendered snippet plus a "
    "snippet→repo source map to every benchmark sample."
)
```

Add this parameter as the **last** parameter of `build_cleanvul_benchmark`, `build_cleanvul_benchmark_compare_rankings`, and `build_cleanvul_benchmark_compare_rankings_all`:

```python
    include_static_findings: Annotated[
        bool,
        typer.Option("--include-static-findings", help=_INCLUDE_STATIC_FINDINGS_HELP),
    ] = False,
```

Pass it through:
- `build_cleanvul_benchmark`: add `include_static_findings=include_static_findings,` to its `CleanVulBenchmarkService(...)` call.
- `_run_compare_rankings`: add parameter `include_static_findings: bool` (last), add `include_static_findings=include_static_findings,` to its `CleanVulBenchmarkService(...)` call; in `build_cleanvul_benchmark_compare_rankings` pass `include_static_findings=include_static_findings,` to `_run_compare_rankings(...)`.
- `build_cleanvul_benchmark_compare_rankings_all`: add `include_static_findings=include_static_findings,` to its `CleanVulBenchmarkService(...)` call.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_cli_static_findings.py -v && uv run llm-scanner build-cleanvul-benchmark --help | grep -- --include-static-findings`
Expected: PASS; help output shows the option.

---

### Task 8: Full verification

- [ ] **Step 1: Run the full pipeline**

Run: `uv run pre-commit run --all-files`
Expected: ruff / format / isort / mypy / pytest / coverage all pass. The only tolerated mypy error is the pre-existing `scripts/concat_compare_rankings.py:349`. Fix any lint/format/type issues introduced by Tasks 1–7 (e.g. `mypy` on `finding.cwe_id` access is guarded by `isinstance`).

- [ ] **Step 2: Byte-identical flag-off check**

Run the existing benchmark tests once more and confirm no JSON key changes:
`uv run pytest tests/services/benchmark/test_cleanvul_benchmark_service.py -v`
Expected: PASS; additionally in `test_build_writes_dataset` payloads there are no `static_findings`/`source_map` keys (Task 5 serializer).
