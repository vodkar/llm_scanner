"""Unit tests for sarif_exporter.SARIFExporter."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "llm_scanner"))

from datetime import UTC, datetime  # noqa: E402

from models.scan import ScanFinding, ScanReport, ScanSeverity  # noqa: E402
from sarif_exporter import SARIFExporter  # noqa: E402


def _make_report(findings: list[ScanFinding] | None = None) -> ScanReport:
    return ScanReport(
        src=Path("/repo"),
        mode="full",
        strategy="cpg_structural",
        findings=findings or [],
        total_contexts_scanned=1,
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
    )


def _make_finding(
    *,
    vulnerable: bool = True,
    severity: ScanSeverity = ScanSeverity.HIGH,
    cwe_id: int | None = 89,
    description: str | None = "SQL injection",
) -> ScanFinding:
    return ScanFinding(
        root_id="abc123",
        file_path=Path("src/main.py"),
        line_start=10,
        line_end=15,
        vulnerable=vulnerable,
        severity=severity,
        cwe_id=cwe_id,
        description=description,
        context_text="code here",
    )


class TestSARIFExporter:
    def test_schema_and_version(self) -> None:
        doc = SARIFExporter().export(_make_report())
        assert doc["version"] == "2.1.0"
        assert "json.schemastore.org" in doc["$schema"]

    def test_runs_structure(self) -> None:
        doc = SARIFExporter().export(_make_report())
        assert len(doc["runs"]) == 1
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "llm-scanner"
        assert "results" in run

    def test_only_vulnerable_findings_emitted(self) -> None:
        findings = [
            _make_finding(vulnerable=True),
            _make_finding(vulnerable=False),
        ]
        doc = SARIFExporter().export(_make_report(findings))
        assert len(doc["runs"][0]["results"]) == 1

    def test_result_level_high_is_error(self) -> None:
        findings = [_make_finding(severity=ScanSeverity.HIGH)]
        doc = SARIFExporter().export(_make_report(findings))
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_result_level_critical_is_error(self) -> None:
        findings = [_make_finding(severity=ScanSeverity.CRITICAL)]
        doc = SARIFExporter().export(_make_report(findings))
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_result_level_medium_is_warning(self) -> None:
        findings = [_make_finding(severity=ScanSeverity.MEDIUM)]
        doc = SARIFExporter().export(_make_report(findings))
        assert doc["runs"][0]["results"][0]["level"] == "warning"

    def test_result_level_low_is_note(self) -> None:
        findings = [_make_finding(severity=ScanSeverity.LOW)]
        doc = SARIFExporter().export(_make_report(findings))
        assert doc["runs"][0]["results"][0]["level"] == "note"

    def test_cwe_rule_id(self) -> None:
        findings = [_make_finding(cwe_id=89)]
        doc = SARIFExporter().export(_make_report(findings))
        assert doc["runs"][0]["results"][0]["ruleId"] == "CWE-89"

    def test_unknown_rule_id_when_no_cwe(self) -> None:
        findings = [_make_finding(cwe_id=None)]
        doc = SARIFExporter().export(_make_report(findings))
        assert "UNKNOWN" in doc["runs"][0]["results"][0]["ruleId"]

    def test_location_line_numbers(self) -> None:
        findings = [_make_finding()]
        doc = SARIFExporter().export(_make_report(findings))
        region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 10
        assert region["endLine"] == 15

    def test_empty_report_yields_empty_results(self) -> None:
        doc = SARIFExporter().export(_make_report([]))
        assert doc["runs"][0]["results"] == []

    def test_to_file(self, tmp_path: Path) -> None:
        import json

        out = tmp_path / "sub" / "report.sarif"
        SARIFExporter().to_file(_make_report([_make_finding()]), out)
        assert out.exists()
        loaded = json.loads(out.read_text())
        assert loaded["version"] == "2.1.0"
