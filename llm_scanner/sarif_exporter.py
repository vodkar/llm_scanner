"""Export ScanReport to SARIF 2.1.0 format."""

import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

from models.scan import ScanFinding, ScanReport, ScanSeverity

_SARIF_SCHEMA: Final[str] = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_VERSION: Final[str] = "2.1.0"
_TOOL_NAME: Final[str] = "llm-scanner"
_TOOL_INFO_URI: Final[str] = "https://github.com/vodkar/llm_scanner"

_SARIF_LEVEL: Final = MappingProxyType(
    {
        ScanSeverity.CRITICAL: "error",
        ScanSeverity.HIGH: "error",
        ScanSeverity.MEDIUM: "error",
        ScanSeverity.LOW: "note",
    }
)


class SARIFExporter:
    """Convert a ScanReport to SARIF 2.1.0 format.

    Only findings where ``vulnerable=True`` are emitted as SARIF results.
    """

    def export(self, report: ScanReport) -> dict[str, Any]:
        """Return a SARIF 2.1.0 document as a plain Python dict.

        Args:
            report: The scan report to convert.

        Returns:
            SARIF 2.1.0 document ready for JSON serialisation.
        """
        results = [self._finding_to_result(f, report.src) for f in report.findings if f.vulnerable]
        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": _TOOL_NAME,
                            "informationUri": _TOOL_INFO_URI,
                            "rules": [],
                        }
                    },
                    "results": results,
                    "properties": {
                        "scanMode": report.mode,
                        "strategy": report.strategy,
                        "scanId": report.scan_id,
                        "timestamp": report.timestamp.isoformat(),
                    },
                }
            ],
        }

    def to_file(self, report: ScanReport, path: Path) -> None:
        """Write a SARIF 2.1.0 document to a file.

        Args:
            report: The scan report to export.
            path: Destination file path; parent directories are created if needed.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.export(report), f, indent=2)

    def _artifact_uri(self, file_path: Path, src: Path) -> str:
        """Return ``file_path`` relative to ``src`` so it resolves against ``%SRCROOT%``."""
        if file_path.is_absolute() and file_path.is_relative_to(src):
            return file_path.relative_to(src).as_posix()
        return file_path.as_posix()

    def _finding_to_result(self, finding: ScanFinding, src: Path) -> dict[str, Any]:
        level = _SARIF_LEVEL.get(finding.severity or ScanSeverity.MEDIUM, "warning")
        message_text = finding.description or "Potential security vulnerability detected."
        rule_id = f"CWE-{finding.cwe_id}" if finding.cwe_id else "SCANNER/UNKNOWN"

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": self._artifact_uri(finding.file_path, src),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line_start,
                            "endLine": finding.line_end,
                        },
                    }
                }
            ],
        }
        if finding.cwe_id:
            result["taxa"] = [{"id": f"CWE-{finding.cwe_id}", "toolComponent": {"name": "CWE"}}]
        return result
