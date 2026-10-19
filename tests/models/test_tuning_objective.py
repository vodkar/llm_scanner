"""Optuna direction for each tuning objective."""

import pytest

from models.tuning_objective import TuningObjective


@pytest.mark.parametrize(
    ("objective", "direction"),
    [(TuningObjective.ACCURACY, "maximize"), (TuningObjective.FNR, "minimize")],
)
def test_direction_favors_better_metric(objective: TuningObjective, direction: str) -> None:
    assert objective.direction == direction
