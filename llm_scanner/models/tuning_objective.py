from enum import StrEnum


class TuningObjective(StrEnum):
    """Judge metric an Optuna ranking study optimizes."""

    ACCURACY = "accuracy"
    FNR = "fnr"

    @property
    def direction(self) -> str:
        """Return the Optuna study direction: higher accuracy, lower FNR is better."""

        return "maximize" if self is TuningObjective.ACCURACY else "minimize"
