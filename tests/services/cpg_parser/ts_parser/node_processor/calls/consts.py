from tests.consts import TEST_DATA_DIR


from pathlib import Path
from typing import Final

TEST_CALLS_DATA_DIR: Final[Path] = TEST_DATA_DIR / "calls"
TEST_MAIN_FUNCTION_FILE: Final[Path] = TEST_CALLS_DATA_DIR / "main_function.py"
TEST_FUNCTION_CALLS_FILE: Final[Path] = TEST_CALLS_DATA_DIR / "function_calls.py"
TEST_FUNCTION_CALLS_WITH_ARGS_FILE: Final[Path] = (
    TEST_CALLS_DATA_DIR / "function_calls_with_args.py"
)
