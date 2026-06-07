"""Unit tests for test-code detection predicates."""

import pytest

from services.context_assembler.node_filters import (
    is_test_path,
    text_uses_test_framework,
)


@pytest.mark.parametrize(
    ("file_path", "name", "expected"),
    [
        ("shuup_tests/front/test_basket.py", "test_basket", True),
        ("app/tests/util.py", "build_helper", True),
        ("pkg/test_x.py", "do_thing", True),
        ("pkg/x_test.py", "do_thing", True),
        ("conftest.py", "fixture_factory", True),
        ("pkg/sub/conftest.py", None, True),
        ("redash/query_runner/csv.py", "run_query", False),
        ("redash/query_runner/csv.py", "test_connection", True),
        ("shuup/testing/factories.py", "get_default_shop", False),
        ("shuup/xtheme/views/command.py", "command_dispatch", False),
    ],
)
def test_is_test_path(file_path: str, name: str | None, expected: bool) -> None:
    """Path/name signal flags conventional test locations and test_* names."""

    assert is_test_path(file_path, name) is expected


@pytest.mark.parametrize(
    "text",
    [
        "import pytest\n\ndef f():\n    pass\n",
        "import unittest\n",
        "from unittest import TestCase\n",
        "from unittest.mock import patch\n",
        "from django.test import TestCase\n",
        "@pytest.fixture\ndef thing():\n    return 1\n",
        "@pytest.mark.parametrize('x', [1])\ndef test_x(x):\n    pass\n",
        "class MyCase(unittest.TestCase):\n    pass\n",
        "class MyCase(TestCase):\n    pass\n",
    ],
)
def test_text_uses_test_framework_positive(text: str) -> None:
    """Content signal detects pytest/unittest usage in source text."""

    assert text_uses_test_framework(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "def run_query(self, query):\n    return self.execute(query)\n",
        "import json\nimport logging\n\nLOGGER = logging.getLogger(__name__)\n",
        "# this comment mentions pytest but is not an import\nx = 1\n",
        "",
    ],
)
def test_text_uses_test_framework_negative(text: str) -> None:
    """Content signal does not fire on ordinary production source."""

    assert text_uses_test_framework(text) is False
