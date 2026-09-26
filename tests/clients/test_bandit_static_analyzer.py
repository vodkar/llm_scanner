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
    assert issue.column_number == 4
