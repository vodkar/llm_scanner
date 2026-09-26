import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path
from tempfile import mkstemp
from types import MappingProxyType
from typing import Any, Final

from pydantic import Field

from clients.analyzers.base import IStaticAnalyzer
from models.bandit_report import IssueSeverity
from models.base import StaticAnalyzerReport
from models.semgrep_report import SemgrepIssue

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

DEFAULT_SEMGREP_CONFIG: Final[str] = "p/python"
DEFAULT_SEMGREP_TIMEOUT_SECONDS: Final[float] = 1800.0

# Semgrep exits 0 on success and 1 when findings trip ``--error``; anything else is fatal.
# Unknown levels (e.g. INVENTORY, EXPERIMENT) are informational and map to LOW.
_OK_EXIT_CODES: Final[frozenset[int]] = frozenset({0, 1})
_CWE_PATTERN: Final[re.Pattern[str]] = re.compile(r"CWE-(\d+)")
_SEVERITY_BY_LEVEL: Final[MappingProxyType[str, IssueSeverity]] = MappingProxyType(
    {
        "CRITICAL": IssueSeverity.HIGH,
        "ERROR": IssueSeverity.HIGH,
        "HIGH": IssueSeverity.HIGH,
        "WARNING": IssueSeverity.MEDIUM,
        "MEDIUM": IssueSeverity.MEDIUM,
        "INFO": IssueSeverity.LOW,
        "LOW": IssueSeverity.LOW,
    }
)


class SemgrepExecutionError(RuntimeError):
    """Raised when Semgrep fails to run or cannot produce a report."""


class SemgrepStaticAnalyzer(IStaticAnalyzer):
    """Run Semgrep with a rule config and parse its JSON report.

    Registry configs such as ``p/python`` are downloaded on each run, so the
    scan needs network access unless ``config`` points at local rule files.
    Semgrep only scans files tracked by version control and skips files above
    its size limit.
    """

    src: Path
    config: str = DEFAULT_SEMGREP_CONFIG
    timeout_seconds: float = Field(default=DEFAULT_SEMGREP_TIMEOUT_SECONDS, gt=0)

    def run(self) -> StaticAnalyzerReport[SemgrepIssue]:  # type: ignore
        """Scan ``src`` and return the parsed findings.

        Returns:
            Report with one issue per Semgrep result.

        Raises:
            SemgrepExecutionError: If Semgrep is missing, times out, exits with a
                fatal code, or writes an unreadable report.
        """

        report_fd, raw_report_path = mkstemp(suffix="_semgrep_report.json")
        os.close(report_fd)
        report_path = Path(raw_report_path)
        try:
            result = self._execute(report_path)
            report_text = report_path.read_text(encoding="utf-8")
        finally:
            report_path.unlink(missing_ok=True)

        if result.returncode not in _OK_EXIT_CODES:
            raise SemgrepExecutionError(
                f"semgrep exited with {result.returncode}: "
                f"{_error_messages(report_text) or result.stderr.strip()}"
            )
        report_data = _parse_report(report_text)
        for error in report_data.get("errors", []):
            _LOGGER.warning("semgrep: %s", error.get("message", error))

        issues = [_to_issue(raw) for raw in report_data.get("results", [])]
        _LOGGER.info("semgrep (%s) reported %d findings in %s", self.config, len(issues), self.src)
        return StaticAnalyzerReport(issues=issues)

    def _execute(self, report_path: Path) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [
                    _semgrep_executable(),
                    "scan",
                    "--config",
                    self.config,
                    "--json",
                    "--output",
                    str(report_path),
                    "--metrics=off",
                    "--quiet",
                    "--disable-version-check",
                    str(self.src),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            raise SemgrepExecutionError(
                f"semgrep timed out after {self.timeout_seconds}s on {self.src}"
            ) from error


def _parse_report(report_text: str) -> dict[str, Any]:
    try:
        report: dict[str, Any] = json.loads(report_text)
    except json.JSONDecodeError as error:
        raise SemgrepExecutionError("semgrep wrote an unreadable JSON report") from error
    return report


def _error_messages(report_text: str) -> str:
    try:
        errors: list[dict[str, Any]] = json.loads(report_text).get("errors", [])
    except json.JSONDecodeError:
        return ""
    return "; ".join(str(error.get("message", "")) for error in errors)


def semgrep_rules_fingerprint(config: str) -> str:
    """Identify the rules a Semgrep run applies, for use in cache keys.

    Combines the config string with the installed Semgrep version and, when the
    config is a local file or directory, a hash of its contents. Registry
    configs (e.g. ``p/python``) are identified by name only: their upstream
    rules can still change between runs.

    Args:
        config: Semgrep ``--config`` value.

    Returns:
        Stable fingerprint string.
    """

    parts = [config, f"semgrep={version('semgrep')}"]
    local_rules = Path(config)
    if local_rules.exists():
        parts.append(f"rules={_hash_rules(local_rules)}")
    return "|".join(parts)


def _hash_rules(path: Path) -> str:
    files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    digest = hashlib.sha1()
    for file in files:
        digest.update(file.relative_to(path).as_posix().encode() if path.is_dir() else b"")
        digest.update(file.read_bytes())
    return digest.hexdigest()


def _semgrep_executable() -> str:
    bundled = Path(sys.executable).with_name("semgrep")
    if bundled.exists():
        return str(bundled)
    found = shutil.which("semgrep")
    if found is None:
        raise SemgrepExecutionError("semgrep executable not found")
    return found


def _to_issue(raw: dict[str, Any]) -> SemgrepIssue:
    extra: dict[str, Any] = raw.get("extra", {})
    return SemgrepIssue(
        check_id=raw["check_id"],
        file=Path(raw["path"]),
        line_number=raw["start"]["line"],
        line_end=raw["end"]["line"],
        column_number=max(raw["start"].get("col", 1) - 1, 0),
        severity=_SEVERITY_BY_LEVEL.get(str(extra.get("severity", "")).upper(), IssueSeverity.LOW),
        cwe=_parse_cwe(extra.get("metadata", {}).get("cwe")),
        reason=extra.get("message", ""),
    )


def _parse_cwe(raw: object) -> int | None:
    candidates = raw if isinstance(raw, list) else [raw]
    for candidate in candidates:
        match = _CWE_PATTERN.search(str(candidate)) if candidate is not None else None
        if match is not None:
            return int(match.group(1))
    return None
