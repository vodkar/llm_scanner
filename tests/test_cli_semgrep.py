"""The --enable-semgrep / --semgrep-config options reach the services that run analyzers."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

import cli
from clients.neo4j import Neo4jClient
from models.scan import ScanReport
from pipeline import GeneralScannerPipeline
from services.benchmark.cleanvul_benchmark import CleanVulBenchmarkService

_BENCHMARK_COMMANDS = (
    "build-cleanvul-benchmark",
    "build-cleanvul-benchmark-compare-rankings",
    "build-cleanvul-benchmark-compare-rankings-all",
)
_SEMGREP_CASES = [
    ([], (False, "p/python")),
    (["--enable-semgrep"], (True, "p/python")),
    (["--enable-semgrep", "--semgrep-config", "p/django"], (True, "p/django")),
]


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


@pytest.mark.parametrize("command", _BENCHMARK_COMMANDS)
@pytest.mark.parametrize(("extra_args", "expected"), _SEMGREP_CASES)
def test_benchmark_commands_pass_semgrep_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    extra_args: list[str],
    expected: tuple[bool, str],
) -> None:
    dataset = tmp_path / "cleanvul.csv"
    dataset.write_text("x\n", encoding="utf-8")
    seen: list[tuple[bool, str]] = []

    def _record(self: CleanVulBenchmarkService) -> tuple[object, Path]:
        seen.append((self.enable_semgrep, self.semgrep_config))
        return {}, tmp_path / "e.json"

    monkeypatch.setattr(CleanVulBenchmarkService, "build", _record)
    monkeypatch.setattr(CleanVulBenchmarkService, "build_all_ranking_strategies", _record)

    result = CliRunner().invoke(
        cli.app,
        [
            command,
            str(dataset),
            "--output-dir",
            str(tmp_path / "out"),
            "--repo-cache-dir",
            str(tmp_path / "repos"),
            *extra_args,
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen == [expected]


@pytest.mark.parametrize(("extra_args", "expected"), _SEMGREP_CASES)
def test_scan_passes_semgrep_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    extra_args: list[str],
    expected: tuple[bool, str],
) -> None:
    seen: list[tuple[bool, str]] = []

    @contextmanager
    def _fake_client(*args: object, **kwargs: object) -> Iterator[MagicMock]:
        del args, kwargs
        yield MagicMock(spec=Neo4jClient)

    def _fake_run(self: GeneralScannerPipeline, **kwargs: object) -> ScanReport:
        del kwargs
        seen.append((self.enable_semgrep, self.semgrep_config))
        return ScanReport(src=tmp_path, mode="full", strategy="x", findings=[])

    monkeypatch.setattr(cli, "build_client", _fake_client)
    monkeypatch.setattr(GeneralScannerPipeline, "run", _fake_run)

    result = CliRunner().invoke(cli.app, ["scan", str(tmp_path), *extra_args])

    assert result.exit_code == 0, result.output
    assert seen == [expected]
