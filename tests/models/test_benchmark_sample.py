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
