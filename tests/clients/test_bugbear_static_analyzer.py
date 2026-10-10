"""Tests for running the security-relevant flake8-bugbear rules."""

import subprocess
from pathlib import Path

import pytest

from clients.analyzers.bugbear_scanner import BUGBEAR_SECURITY_RULES, BugbearStaticAnalyzer


def test_run_selects_security_rules_and_parses_flake8_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[list[str]] = []

    def _fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        captured.append(args)
        stdout = (
            f"{tmp_path}/app/audit.py:11:56: B006 Do not use mutable data structures "
            "for argument defaults.\n"
            "not a finding line\n"
        )
        return subprocess.CompletedProcess(args=args, returncode=1, stdout=stdout)

    monkeypatch.setattr("clients.analyzers.bugbear_scanner.subprocess.run", _fake_run)

    issues = BugbearStaticAnalyzer(src=tmp_path).run().issues

    assert [(issue.code, issue.line_number, issue.column_number) for issue in issues] == [
        ("B006", 11, 56)
    ]
    assert issues[0].file == tmp_path / "app/audit.py"
    assert f"--select={','.join(BUGBEAR_SECURITY_RULES)}" in captured[0]
    assert any(arg.startswith("--extend-immutable-calls=") for arg in captured[0])


def test_run_reports_shared_mutable_default_but_not_style_issues(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def context(user, ctx={}):\n    for unused in range(3):\n        pass\n    return ctx\n"
    )

    issues = BugbearStaticAnalyzer(src=tmp_path).run().issues

    assert [(issue.code, issue.line_number) for issue in issues] == [("B006", 1)]
