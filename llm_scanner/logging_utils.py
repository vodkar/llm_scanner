import logging
from typing import Literal


def configure_logging(log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]) -> None:
    """Configure application logging.

    Args:
        log_level: Desired logging level.
    """

    level_name = log_level.upper()
    level = getattr(logging, level_name)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
