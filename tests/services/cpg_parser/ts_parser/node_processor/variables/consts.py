from pathlib import Path
from typing import Final

from tests.consts import TEST_DATA_DIR


VARIABLES_DATA_DIR: Final[Path] = TEST_DATA_DIR / "variables"
TEST_VARIABLES_FILE: Final[Path] = VARIABLES_DATA_DIR / "first.py"
TEST_SIMPLE_VARIABLES_FILE: Final[Path] = VARIABLES_DATA_DIR / "simple.py"
TEST_FUNCTION_PARAMS_FILE: Final[Path] = VARIABLES_DATA_DIR / "function_params.py"
