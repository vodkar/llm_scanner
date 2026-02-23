from pathlib import Path

from models.benchmark.cvefixes import CVEFixesEntry
from models.context import FindingContext
from services.analyzer.cvefixes_benchmark import CVEFixesBenchmarkService


def _service() -> CVEFixesBenchmarkService:
    return CVEFixesBenchmarkService(
        db_path=Path("/tmp/cvefixes.db"),
        output_dir=Path("/tmp/out"),
        repo_cache_dir=Path("/tmp/cache"),
        sample_count=1,
    )


def _entry() -> CVEFixesEntry:
    return CVEFixesEntry(
        cve_id="CVE-2026-0001",
        repo_url="https://example.com/repo.git",
        fix_hash="abc123",
        file_path=Path("pkg/module.py"),
        start_line=10,
        end_line=20,
        description="sample",
        cwe_id=79,
        severity="high",
    )


def _context(*, finding_id: str, text: str, line_number: int) -> FindingContext:
    return FindingContext(
        finding_id=finding_id,
        finding_type="BanditFindingNode",
        file=Path("pkg/module.py"),
        line_number=line_number,
        description="ctx",
        context_text=text,
        token_count=max(1, len(text.split())),
    )


def test_select_sample_prefers_non_associated_over_fallback() -> None:
    service = _service()
    entry = _entry()
    non_associated = [
        _context(finding_id="f-neg", text="def safe():\n    return 1", line_number=90)
    ]
    fallback = _context(finding_id="fb", text="def vuln():\n    pass", line_number=10)

    sample, unassociated = service._select_sample_for_entry(
        entry=entry,
        associated=[],
        non_associated=non_associated,
        fallback_context=fallback,
        sample_id="ContextAssembler-1",
    )

    assert sample is not None
    assert sample.label == 0
    assert sample.code == non_associated[0].context_text
    assert unassociated
    assert unassociated[0].reason == "no_file_line_match"


def test_select_sample_uses_associated_first() -> None:
    service = _service()
    entry = _entry()
    associated = [_context(finding_id="f-pos", text="def vuln():\n    eval(x)", line_number=12)]
    non_associated = [
        _context(finding_id="f-neg", text="def safe():\n    return 1", line_number=90)
    ]

    sample, unassociated = service._select_sample_for_entry(
        entry=entry,
        associated=associated,
        non_associated=non_associated,
        fallback_context=None,
        sample_id="ContextAssembler-1",
    )

    assert sample is not None
    assert sample.label == 1
    assert sample.code == associated[0].context_text
    assert unassociated == []


def test_select_sample_uses_fallback_when_no_contexts() -> None:
    service = _service()
    entry = _entry()
    fallback = _context(finding_id="fb", text="def vuln():\n    pass", line_number=10)

    sample, unassociated = service._select_sample_for_entry(
        entry=entry,
        associated=[],
        non_associated=[],
        fallback_context=fallback,
        sample_id="ContextAssembler-1",
    )

    assert sample is not None
    assert sample.label == 1
    assert sample.code == fallback.context_text
    assert unassociated
    assert unassociated[0].reason == "used_cvefixes_fallback_context"
