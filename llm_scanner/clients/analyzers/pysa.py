import json
import logging
import shutil
import subprocess
from pathlib import Path

from clients.analyzers.base import IStaticAnalyzer
from models.base import StaticAnalyzerReport
from models.pysa_report import FLOW_CODE_TO_SINK_TYPE, PysaIssue, infer_source_type

logger = logging.getLogger(__name__)

# Resolved at import time so the path remains valid regardless of cwd changes.
_PYSA_MODELS_DIR: Path = Path(__file__).resolve().parent.parent.parent / "pysa_models"

_MINIMAL_PYRE_CONFIG: dict = {
    "source_directories": ["."],
    "taint_models_path": "",  # filled at runtime
    "search_path": [],
    "exclude": ["**/__pycache__/**"],
    "strict": False,
}


class PysaStaticAnalyzer(IStaticAnalyzer):
    """Run Meta's Pysa taint analysis and parse the results.

    Lifecycle:
      1. Verify ``pyre`` is on PATH; return an empty report if not.
      2. Write a minimal ``.pyre_configuration`` if one does not already exist.
      3. Run ``pyre analyze`` and capture stdout.
      4. Parse the JSON output into ``PysaIssue`` instances.
      5. Remove the config file if we created it (even on error).
    """

    src: Path

    def run(self) -> StaticAnalyzerReport[PysaIssue]:  # type: ignore
        if not shutil.which("pyre"):
            logger.warning(
                "pyre not found on PATH; skipping Pysa taint analysis. "
                "Install on Linux with: pip install pyre-check"
            )
            return StaticAnalyzerReport(issues=[])

        pyre_config_path = self.src / ".pyre_configuration"
        config_created_by_us = not pyre_config_path.exists()

        try:
            if config_created_by_us:
                self._write_pyre_config(pyre_config_path)

            result = subprocess.run(
                ["pyre", "analyze"],
                cwd=str(self.src),
                capture_output=True,
                text=True,
                check=False,
            )

            # Exit code 1 means findings were found — that is non-fatal.
            if result.returncode not in (0, 1):
                logger.error(
                    "pyre analyze failed (exit %d):\n%s",
                    result.returncode,
                    result.stderr,
                )
                return StaticAnalyzerReport(issues=[])

            return self._parse_output(result.stdout)

        finally:
            if config_created_by_us and pyre_config_path.exists():
                pyre_config_path.unlink()

    def _write_pyre_config(self, config_path: Path) -> None:
        config = dict(_MINIMAL_PYRE_CONFIG)
        config["taint_models_path"] = str(_PYSA_MODELS_DIR)
        config_path.write_text(json.dumps(config, indent=2))

    def _parse_output(self, stdout: str) -> StaticAnalyzerReport[PysaIssue]:
        issues: list[PysaIssue] = []

        if not stdout.strip():
            return StaticAnalyzerReport(issues=issues)

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning("Could not parse pyre analyze output as JSON")
            return StaticAnalyzerReport(issues=issues)

        # Pysa output is {"errors": [...]} or a bare list depending on version.
        raw_findings = data.get("errors", data) if isinstance(data, dict) else data

        for entry in raw_findings:
            code: int = int(entry.get("code", 0))
            sink_type = FLOW_CODE_TO_SINK_TYPE.get(code)
            if sink_type is None:
                logger.debug("Skipping unknown Pysa flow code %d", code)
                continue

            description: str = entry.get("description", "")
            issues.append(
                PysaIssue(
                    file=Path(entry["path"]),
                    line_number=int(entry["line"]),
                    column_number=int(entry.get("column", 0)),
                    stop_line=int(entry.get("stop_line", entry["line"])),
                    stop_column=int(entry.get("stop_column", 0)),
                    reason=description,
                    flow_code=code,
                    flow_name=entry.get("name", ""),
                    sink_type=sink_type,
                    source_type=infer_source_type(description),
                )
            )

        return StaticAnalyzerReport(issues=issues)
