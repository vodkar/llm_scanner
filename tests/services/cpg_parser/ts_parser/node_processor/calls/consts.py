from pathlib import Path
from typing import Final

from tests.consts import TEST_DATA_DIR

TEST_CALLS_DATA_DIR: Final[Path] = TEST_DATA_DIR / "calls"
TEST_MAIN_FUNCTION_FILE: Final[Path] = TEST_CALLS_DATA_DIR / "main_function.py"
TEST_FUNCTION_CALLS_FILE: Final[Path] = TEST_CALLS_DATA_DIR / "function_calls.py"
TEST_FUNCTION_CALLS_WITH_ARGS_FILE: Final[Path] = (
    TEST_CALLS_DATA_DIR / "function_calls_with_args.py"
)

TEST_CLASS_PASSED_AS_ARG_FILE: Final[Path] = TEST_CALLS_DATA_DIR / "class_passed_as_arg.py"
TEST_METHOD_CALLS_FILE: Final[Path] = TEST_CALLS_DATA_DIR / "method_calls.py"
