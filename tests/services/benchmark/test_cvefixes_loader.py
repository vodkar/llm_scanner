from pathlib import Path

from pytest import MonkeyPatch

from services.benchmark.cvefixes_loader import CVEFixesLoaderService


def test_fetch_python_entries_aggregates_spans_and_vulnerability_labels(
    monkeypatch: MonkeyPatch,
) -> None:
    rows: list[dict[str, object | None]] = [
        {
            "cve_id": "CVE-2024-0001",
            "fix_hash": "abc123",
            "repo_url": "https://example.com/repo.git",
            "old_path": "src/vuln.py",
            "new_path": "src/safe.py",
            "filename": "src/vuln.py",
            "diff_parsed": (
                "{'added': [(30, 'safe_call()'), (31, 'return')], "
                "'deleted': [(10, 'bad_call()'), (11, 'x=1'), (12, 'y=2')]}"
            ),
            "description": "sample",
            "cvss3_base_severity": "HIGH",
            "severity": None,
            "cwe_id": "CWE-79",
        },
        {
            "cve_id": "CVE-2024-0001",
            "fix_hash": "abc123",
            "repo_url": "https://example.com/repo.git",
            "old_path": "src/vuln.py",
            "new_path": "src/safe.py",
            "filename": "src/vuln.py",
            "diff_parsed": (
                "{'added': [], 'deleted': [(20, 'var = user_input'), (21, 'sink(var)')]}"
            ),
            "description": "sample",
            "cvss3_base_severity": "HIGH",
            "severity": None,
            "cwe_id": "79",
        },
        {
            "cve_id": "CVE-2024-0001",
            "fix_hash": "abc123",
            "repo_url": "https://example.com/repo.git",
            "old_path": "src/vuln.py",
            "new_path": "src/safe.py",
            "filename": "src/vuln.py",
            "diff_parsed": "{'added': [(30, 'safe_call()')], 'deleted': []}",
            "description": "sample",
            "cvss3_base_severity": "HIGH",
            "severity": None,
            "cwe_id": "79",
        },
    ]

    service = CVEFixesLoaderService(db_path=Path("/tmp/cvefixes.db"))

    def _fetch_rows() -> list[dict[str, object | None]]:
        return rows

    monkeypatch.setattr(service, "_fetch_candidate_rows", _fetch_rows)

    entries = service.fetch_python_entries()

    assert len(entries) == 2
    vulnerable_entry = next(entry for entry in entries if entry.is_vulnerable)
    non_vulnerable_entry = next(entry for entry in entries if not entry.is_vulnerable)

    assert vulnerable_entry.files_spans == [
        (
            Path("src/vuln.py"),
            [(10, 12), (20, 21)],
        )
    ]
    assert non_vulnerable_entry.files_spans == [
        (
            Path("src/safe.py"),
            [(30, 31)],
        )
    ]


def test_fetch_python_entries_deduplicates_identical_spans(monkeypatch: MonkeyPatch) -> None:
    rows: list[dict[str, object | None]] = [
        {
            "cve_id": "CVE-2024-0002",
            "fix_hash": "def456",
            "repo_url": "https://example.com/repo.git",
            "old_path": "pkg/a.py",
            "new_path": "pkg/a.py",
            "filename": "pkg/a.py",
            "diff_parsed": "{'added': [], 'deleted': [(3, 'x = 1'), (4, 'do(x)')]}",
            "description": "dup test",
            "cvss3_base_severity": "LOW",
            "severity": None,
            "cwe_id": "20",
        },
        {
            "cve_id": "CVE-2024-0002",
            "fix_hash": "def456",
            "repo_url": "https://example.com/repo.git",
            "old_path": "pkg/a.py",
            "new_path": "pkg/a.py",
            "filename": "pkg/a.py",
            "diff_parsed": "{'added': [], 'deleted': [(3, 'x = 1'), (4, 'do(x)')]}",
            "description": "dup test",
            "cvss3_base_severity": "LOW",
            "severity": None,
            "cwe_id": "20",
        },
    ]

    service = CVEFixesLoaderService(db_path=Path("/tmp/cvefixes.db"))

    def _fetch_rows() -> list[dict[str, object | None]]:
        return rows

    monkeypatch.setattr(service, "_fetch_candidate_rows", _fetch_rows)

    entries = service.fetch_python_entries()

    assert len(entries) == 1
    assert entries[0].files_spans == [(Path("pkg/a.py"), [(3, 4)])]
