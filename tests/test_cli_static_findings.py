"""The --include-static-findings flag reaches CleanVulBenchmarkService."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

import cli
from services.benchmark.cleanvul_benchmark import CleanVulBenchmarkService


@pytest.mark.parametrize(
    ("extra_args", "expected"),
    [([], False), (["--include-static-findings"], True)],
)
def test_build_cleanvul_benchmark_passes_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    extra_args: list[str],
    expected: bool,
) -> None:
    dataset = tmp_path / "cleanvul.csv"
    dataset.write_text("x\n", encoding="utf-8")
    seen: list[bool] = []

    def _fake_build(self: CleanVulBenchmarkService) -> tuple[Path, Path]:
        seen.append(self.include_static_findings)
        return tmp_path / "d.json", tmp_path / "e.json"

    monkeypatch.setattr(CleanVulBenchmarkService, "build", _fake_build)

    result = CliRunner().invoke(
        cli.app,
        [
            "build-cleanvul-benchmark",
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
