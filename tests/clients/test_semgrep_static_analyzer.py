"""Tests for Semgrep JSON report parsing."""

import json
import logging
import subprocess
from pathlib import Path

import pytest

from clients.analyzers.semgrep import (
    SemgrepExecutionError,
    SemgrepStaticAnalyzer,
    semgrep_rules_fingerprint,
)
from models.bandit_report import IssueSeverity


def _result(
    path: Path,
    *,
    severity: str = "ERROR",
    cwe: object = None,
    start_line: int = 5,
    end_line: int = 6,
) -> dict[str, object]:
    metadata: dict[str, object] = {} if cwe is None else {"cwe": cwe}
    return {
        "check_id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
        "path": str(path),
        "start": {"line": start_line, "col": 32, "offset": 74},
        "end": {"line": end_line, "col": 36, "offset": 78},
        "extra": {"severity": severity, "message": "shell=True is dangerous", "metadata": metadata},
    }


def _patch_run(
    monkeypatch: pytest.MonkeyPatch, report: dict[str, object], returncode: int = 0
) -> list[list[str]]:
    calls: list[list[str]] = []

    def _fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(args)
        Path(args[args.index("--output") + 1]).write_text(json.dumps(report), encoding="utf-8")
        return subprocess.CompletedProcess(args=args, returncode=returncode, stderr="boom")

    monkeypatch.setattr("clients.analyzers.semgrep.subprocess.run", _fake_run)
    return calls


def test_run_parses_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cwe = ["CWE-78: Improper Neutralization of Special Elements used in an OS Command"]
    _patch_run(monkeypatch, {"results": [_result(tmp_path / "app.py", cwe=cwe)], "errors": []})

    result = SemgrepStaticAnalyzer(src=tmp_path).run()

    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.check_id.endswith("subprocess-shell-true")
    assert issue.file == tmp_path / "app.py"
    assert issue.line_number == 5
    assert issue.line_end == 6
    assert issue.column_number == 31
    assert issue.cwe == 78
    assert issue.severity == IssueSeverity.HIGH
    assert issue.reason == "shell=True is dangerous"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ERROR", IssueSeverity.HIGH),
        ("CRITICAL", IssueSeverity.HIGH),
        ("WARNING", IssueSeverity.MEDIUM),
        ("INFO", IssueSeverity.LOW),
        ("INVENTORY", IssueSeverity.LOW),
    ],
)
def test_run_maps_severity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw: str, expected: IssueSeverity
) -> None:
    _patch_run(monkeypatch, {"results": [_result(tmp_path / "a.py", severity=raw)], "errors": []})

    issue = SemgrepStaticAnalyzer(src=tmp_path).run().issues[0]

    assert issue.severity == expected


@pytest.mark.parametrize(
    ("cwe", "expected"),
    [(None, None), ("CWE-89: SQL Injection", 89), (["not a cwe"], None), ([], None)],
)
def test_run_parses_cwe_variants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cwe: object, expected: int | None
) -> None:
    _patch_run(monkeypatch, {"results": [_result(tmp_path / "a.py", cwe=cwe)], "errors": []})

    issue = SemgrepStaticAnalyzer(src=tmp_path).run().issues[0]

    assert issue.cwe == expected


def test_run_passes_config_and_disables_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_run(monkeypatch, {"results": [], "errors": []})

    SemgrepStaticAnalyzer(src=tmp_path, config="p/django").run()

    args = calls[0]
    assert args[args.index("--config") + 1] == "p/django"
    assert "--metrics=off" in args
    assert args[-1] == str(tmp_path)


def test_run_raises_on_fatal_exit_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, {"results": [], "errors": [{"message": "bad config"}]}, returncode=7)

    with pytest.raises(SemgrepExecutionError, match="bad config"):
        SemgrepStaticAnalyzer(src=tmp_path).run()


def test_run_logs_config_and_finding_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _patch_run(monkeypatch, {"results": [_result(tmp_path / "a.py")], "errors": []})

    with caplog.at_level(logging.INFO, logger="clients.analyzers.semgrep"):
        SemgrepStaticAnalyzer(src=tmp_path, config="p/django").run()

    assert f"semgrep (p/django) reported 1 findings in {tmp_path}" in caplog.text


def test_run_removes_report_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_run(monkeypatch, {"results": [], "errors": []})

    SemgrepStaticAnalyzer(src=tmp_path).run()

    report_path = Path(calls[0][calls[0].index("--output") + 1])
    assert not report_path.exists()


def test_run_raises_on_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _hang(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=args, timeout=float(str(kwargs["timeout"])))

    monkeypatch.setattr("clients.analyzers.semgrep.subprocess.run", _hang)

    with pytest.raises(SemgrepExecutionError, match="timed out"):
        SemgrepStaticAnalyzer(src=tmp_path, timeout_seconds=5).run()


def test_fatal_exit_without_json_reports_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _crash(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        Path(args[args.index("--output") + 1]).write_text('{"results": [', encoding="utf-8")
        return subprocess.CompletedProcess(args=args, returncode=2, stderr="engine crashed")

    monkeypatch.setattr("clients.analyzers.semgrep.subprocess.run", _crash)

    with pytest.raises(SemgrepExecutionError, match="engine crashed"):
        SemgrepStaticAnalyzer(src=tmp_path).run()


def test_real_semgrep_with_local_rule(tmp_path: Path) -> None:
    """Runs the real Semgrep binary offline against a local rule file."""

    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - id: no-eval\n"
        "    pattern: eval(...)\n"
        "    message: eval is dangerous\n"
        "    languages: [python]\n"
        "    severity: WARNING\n"
        "    metadata:\n"
        '      cwe: ["CWE-95: Eval Injection"]\n',
        encoding="utf-8",
    )
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("x = 1\ny = eval(input())\n", encoding="utf-8")

    [issue] = SemgrepStaticAnalyzer(src=project, config=str(rules)).run().issues

    assert issue.check_id.endswith("no-eval")
    assert issue.file.resolve() == (project / "app.py").resolve()
    assert (issue.line_number, issue.line_end, issue.column_number) == (2, 2, 4)
    assert issue.severity == IssueSeverity.MEDIUM
    assert issue.cwe == 95
    assert issue.reason == "eval is dangerous"


def test_rules_fingerprint_tracks_local_rule_content(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    rule_file = rules / "a.yaml"
    rule_file.write_text("rules: []\n", encoding="utf-8")

    before = semgrep_rules_fingerprint(str(rules))
    rule_file.write_text("rules: [] # edited\n", encoding="utf-8")
    after = semgrep_rules_fingerprint(str(rules))

    assert before != after
    assert semgrep_rules_fingerprint(str(rule_file)) != semgrep_rules_fingerprint(str(rules))


def test_rules_fingerprint_pins_semgrep_version_for_registry_configs() -> None:
    fingerprint = semgrep_rules_fingerprint("p/python")

    assert fingerprint.startswith("p/python|semgrep=")
    assert fingerprint != semgrep_rules_fingerprint("p/django")
