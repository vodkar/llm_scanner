"""Attach static-analysis findings to a rendered snippet via its source map."""

from collections.abc import Sequence
from typing import Final

from models.context import CodeContextNode, SnippetSegment
from models.nodes.finding import (
    BanditFindingNode,
    DlintFindingNode,
    FindingNode,
    SemgrepFindingNode,
)
from models.static_finding import AnalyzerTool, StaticFinding
from services.context_assembler.source_map import resolve_snippet_line

_SEVERITY_FINDINGS: Final[tuple[type[BanditFindingNode], type[SemgrepFindingNode]]] = (
    BanditFindingNode,
    SemgrepFindingNode,
)


def attach_findings(
    findings: Sequence[FindingNode],
    source_map: Sequence[SnippetSegment],
    root_nodes: Sequence[CodeContextNode],
) -> list[StaticFinding]:
    """Resolve analyzer findings to snippet lines, dropping unrendered ones.

    A finding resolves to the snippet line of its reported line; when that line
    is not rendered, to the first rendered line of ``[line_number, line_end]``.

    Args:
        findings: Bandit/Dlint/Semgrep findings with repo-relative locations.
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
        cwe_id=finding.cwe_id if isinstance(finding, _SEVERITY_FINDINGS) else None,
        severity=finding.severity if isinstance(finding, _SEVERITY_FINDINGS) else None,
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
    if isinstance(finding, SemgrepFindingNode):
        return AnalyzerTool.SEMGREP
    raise TypeError(f"Unsupported finding type: {type(finding).__name__}")
