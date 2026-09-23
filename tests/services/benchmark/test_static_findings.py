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
