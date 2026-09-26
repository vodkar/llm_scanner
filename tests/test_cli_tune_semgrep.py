"""tune-ranking-coefficients prepares samples with the requested Semgrep options."""

from pathlib import Path

import optuna
import pytest
from click.testing import Result
from typer.testing import CliRunner

import cli
from services.benchmark.cleanvul_benchmark import CleanVulBenchmarkService


class _StopAfterPrepareError(Exception):
    """Ends the command once Phase 1 has been configured."""


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


@pytest.fixture
def study_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "studies"
    monkeypatch.setattr(cli, "DEFAULT_STUDY_DIR", directory)
    return directory


def _invoke(tmp_path: Path, *extra_args: str) -> Result:
    dataset = tmp_path / "cleanvul.csv"
    dataset.write_text("x\n", encoding="utf-8")
    return CliRunner().invoke(
        cli.app,
        [
            "tune-ranking-coefficients",
            "--strategy",
            "cpg_structural",
            "--judge-model",
            "m",
            "--dataset",
            str(dataset),
            "--output-dir",
            str(tmp_path / "out"),
            "--repo-cache-dir",
            str(tmp_path / "repos"),
            "--study-name",
            "s",
            *extra_args,
        ],
    )


@pytest.mark.parametrize(
    ("extra_args", "expected"),
    [
        ([], (False, "p/python")),
        (["--enable-semgrep"], (True, "p/python")),
        (["--enable-semgrep", "--semgrep-config", "p/django"], (True, "p/django")),
    ],
)
def test_tune_prepares_samples_with_semgrep_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    study_dir: Path,
    extra_args: list[str],
    expected: tuple[bool, str],
) -> None:
    seen: list[tuple[bool, str]] = []

    def _record(self: CleanVulBenchmarkService, cache_dir: Path) -> list[object]:
        del cache_dir
        seen.append((self.enable_semgrep, self.semgrep_config))
        raise _StopAfterPrepareError

    monkeypatch.setattr(CleanVulBenchmarkService, "prepare_samples", _record)

    result = _invoke(tmp_path, *extra_args)

    assert isinstance(result.exception, _StopAfterPrepareError)
    assert seen == [expected]


def test_tune_refuses_to_resume_study_with_other_semgrep_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, study_dir: Path
) -> None:
    def _stop(self: CleanVulBenchmarkService, cache_dir: Path) -> list[object]:
        del self, cache_dir
        raise _StopAfterPrepareError

    monkeypatch.setattr(CleanVulBenchmarkService, "prepare_samples", _stop)

    first = _invoke(tmp_path)
    resumed = _invoke(tmp_path, "--enable-semgrep")

    assert isinstance(first.exception, _StopAfterPrepareError)
    assert resumed.exit_code == 2
    assert "was created with Semgrep off" in resumed.output
    study = optuna.load_study(study_name="s", storage=f"sqlite:///{study_dir / 's.db'}")
    assert study.user_attrs["semgrep_config"] is None


def test_tune_treats_legacy_study_with_trials_as_semgrep_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, study_dir: Path
) -> None:
    study_dir.mkdir()
    legacy = optuna.create_study(study_name="s", storage=f"sqlite:///{study_dir / 's.db'}")
    legacy.add_trial(optuna.trial.create_trial(value=0.5, params={}, distributions={}))

    def _stop(self: CleanVulBenchmarkService, cache_dir: Path) -> list[object]:
        del self, cache_dir
        raise _StopAfterPrepareError

    monkeypatch.setattr(CleanVulBenchmarkService, "prepare_samples", _stop)

    enabled = _invoke(tmp_path, "--enable-semgrep")
    disabled = _invoke(tmp_path)

    assert enabled.exit_code == 2
    assert "was created with Semgrep off" in enabled.output
    assert isinstance(disabled.exception, _StopAfterPrepareError)


@pytest.mark.parametrize(
    ("attrs", "expected"),
    [({"semgrep_config": "p/python"}, "Semgrep config 'p/python'"), ({}, "Semgrep off")],
)
def test_export_reports_study_semgrep_setting(
    tmp_path: Path, study_dir: Path, attrs: dict[str, str], expected: str
) -> None:
    study_dir.mkdir()
    study = optuna.create_study(study_name="s", storage=f"sqlite:///{study_dir / 's.db'}")
    study.add_trial(optuna.trial.create_trial(value=0.5, params={}, distributions={}))
    for key, value in attrs.items():
        study.set_user_attr(key, value)

    result = CliRunner().invoke(
        cli.app,
        [
            "export-best-coefficients",
            "--strategy",
            "cpg_structural",
            "--study-name",
            "s",
            "--output-best",
            str(tmp_path / "best.yaml"),
            "--output-last",
            str(tmp_path / "last.yaml"),
            "--study-dir",
            str(study_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    assert f"tuned with {expected}" in result.output
