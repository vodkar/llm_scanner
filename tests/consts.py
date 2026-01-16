"""Shared test path constants."""

from pathlib import Path
from typing import Final

TESTS_DIR: Final[Path] = Path("tests")
PROJECT_ROOT: Final[Path] = TESTS_DIR.parent
TEST_DATA_DIR: Final[Path] = TESTS_DIR / "data"
SAMPLE_FILE: Final[Path] = TEST_DATA_DIR / "sample.py"
TEST_CLASS_FILE: Final[Path] = TEST_DATA_DIR / "classes.py"
TEST_IMPORTS_FILE: Final[Path] = TEST_DATA_DIR / "imports.py"
VARIABLES_DATA_DIR: Final[Path] = TEST_DATA_DIR / "variables"
TEST_VARIABLES_FILE: Final[Path] = VARIABLES_DATA_DIR / "first.py"
TEST_SIMPLE_VARIABLES_FILE: Final[Path] = VARIABLES_DATA_DIR / "simple.py"
TEST_FUNCTION_FILE: Final[Path] = TEST_DATA_DIR / "function.py"
SAMPLE_PROJECT_ROOT: Final[Path] = TEST_DATA_DIR / "sample_project"
SRC_DIR: Final[Path] = PROJECT_ROOT / "src"
