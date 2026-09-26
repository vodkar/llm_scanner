"""Context-assembly token budget defaults to 4096 across commands."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

import cli
from clients.neo4j import Neo4jClient
from models.scan import ScanReport
from pipeline import DEFAULT_TOKEN_BUDGET, GeneralScannerPipeline
from services.benchmark.cleanvul_benchmark import CleanVulBenchmarkService


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def test_default_token_budget_is_4096() -> None:
    assert DEFAULT_TOKEN_BUDGET == 4096
    assert cli.DEFAULT_TOKEN_BUDGET == 4096


@pytest.mark.parametrize(
    "command",
    [
        "build-cleanvul-benchmark",
        "build-cleanvul-benchmark-compare-rankings",
        "build-cleanvul-benchmark-compare-rankings-all",
    ],
)
def test_benchmark_commands_default_to_4096(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    dataset = tmp_path / "cleanvul.csv"
    dataset.write_text("x\n", encoding="utf-8")
    seen: list[int] = []

    def _record(self: CleanVulBenchmarkService) -> tuple[object, Path]:
        seen.append(self.token_budget)
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
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen == [4096]


def test_scan_defaults_to_4096(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[object] = []

    @contextmanager
    def _fake_client(*args: object, **kwargs: object) -> Iterator[MagicMock]:
        del args, kwargs
        yield MagicMock(spec=Neo4jClient)

    def _fake_run(self: GeneralScannerPipeline, **kwargs: object) -> ScanReport:
        del self
        seen.append(kwargs["token_budget"])
        return ScanReport(src=tmp_path, mode="full", strategy="x", findings=[])

    monkeypatch.setattr(cli, "build_client", _fake_client)
    monkeypatch.setattr(GeneralScannerPipeline, "run", _fake_run)

    result = CliRunner().invoke(cli.app, ["scan", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert seen == [4096]
