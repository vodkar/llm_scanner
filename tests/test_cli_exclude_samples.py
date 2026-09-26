"""The --exclude-samples option reaches CleanVulBenchmarkService."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import cli
from services.benchmark.cleanvul_benchmark import CleanVulBenchmarkService


def _invoke(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra_args: list[str]
) -> tuple[int, str, list[frozenset[int]]]:
    dataset = tmp_path / "cleanvul.csv"
    dataset.write_text("x\n", encoding="utf-8")
    seen: list[frozenset[int]] = []

    def _fake_build(self: CleanVulBenchmarkService) -> tuple[Path, Path]:
        seen.append(self.excluded_row_ids)
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
    return result.exit_code, result.output, seen


def _exclusions(tmp_path: Path, source_csv: str) -> Path:
    path = tmp_path / "wrong.json"
    path.write_text(
        json.dumps(
            {
                "source_csv": source_csv,
                "samples": [{"cleanvul_source_row_ids": [3, 4]}],
                "disputed": [{"cleanvul_source_row_ids": [9]}],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_no_exclusions_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exit_code, output, seen = _invoke(tmp_path, monkeypatch, [])

    assert exit_code == 0, output
    assert seen == [frozenset()]


@pytest.mark.parametrize(
    ("section_args", "expected"),
    [
        ([], {3, 4}),
        (["--exclude-section", "samples", "--exclude-section", "disputed"], {3, 4, 9}),
    ],
)
def test_exclusions_file_is_loaded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    section_args: list[str],
    expected: set[int],
) -> None:
    path = _exclusions(tmp_path, "benchmarks/cleanvul.csv")

    exit_code, output, seen = _invoke(
        tmp_path, monkeypatch, ["--exclude-samples", str(path), *section_args]
    )

    assert exit_code == 0, output
    assert seen == [expected]


def test_mismatched_dataset_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _exclusions(tmp_path, "benchmarks/other.csv")

    exit_code, _output, seen = _invoke(tmp_path, monkeypatch, ["--exclude-samples", str(path)])

    assert exit_code == 2
    assert seen == []
