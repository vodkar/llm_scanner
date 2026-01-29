"""Pytest configuration and shared fixtures."""

import logging
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Generator
from pathlib import Path
from typing import Final, LiteralString

import pytest

from clients.neo4j import Neo4jClient, Neo4jConfig
from tests.consts import PROJECT_ROOT, SRC_DIR

LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

NEO4J_BOLT_URI: Final[str] = "bolt://localhost:7687"
NEO4J_HTTP_URL: Final[str] = "http://localhost:7474"
NEO4J_PASSWORD: Final[str] = "test"
NEO4J_USER: Final[str] = "neo4j"
NEO4J_START_TIMEOUT_SECONDS: Final[float] = 60.0
NEO4J_POLL_INTERVAL_SECONDS: Final[float] = 1.0

DOCKER_COMPOSE_FILE: Final[Path] = PROJECT_ROOT / "docker-compose.yml"
LLM_SCANNER_SRC_DIR: Final[Path] = PROJECT_ROOT / "llm_scanner"
CLEAR_DATABASE_QUERY: Final[LiteralString] = "MATCH (n) DETACH DELETE n"


def _ensure_importable_paths() -> None:
    """Ensure project source directories are importable."""

    for path in (SRC_DIR, LLM_SCANNER_SRC_DIR):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def _run_docker_compose(args: list[str]) -> None:
    """Run a docker compose command for the project.

    Args:
        args: Additional docker compose arguments.

    Raises:
        RuntimeError: If docker compose exits with a non-zero status.
    """

    command: list[str] = ["docker", "compose", "-f", str(DOCKER_COMPOSE_FILE), *args]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        LOGGER.exception("Docker compose command failed")
        raise RuntimeError(exc.stderr) from exc


def _wait_for_http_ready(url: str, timeout_seconds: float) -> None:
    """Wait until an HTTP endpoint responds successfully.

    Args:
        url: HTTP URL to poll.
        timeout_seconds: Maximum time to wait before failing.

    Raises:
        RuntimeError: If the endpoint does not respond before timeout.
    """

    deadline: float = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if 200 <= response.status < 400:
                    return
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            last_error = exc
        time.sleep(NEO4J_POLL_INTERVAL_SECONDS)

    message: str = f"Neo4j did not become ready at {url} within {timeout_seconds} seconds"
    if last_error:
        raise RuntimeError(message) from last_error
    raise RuntimeError(message)


_ensure_importable_paths()


@pytest.fixture(scope="session")
def neo4j_docker_compose() -> Generator[None, None, None]:
    """Start and stop Neo4j using docker compose for the test session."""

    _run_docker_compose(["up", "-d", "neo4j"])
    _wait_for_http_ready(NEO4J_HTTP_URL, NEO4J_START_TIMEOUT_SECONDS)
    yield
    _run_docker_compose(["down", "-v"])


@pytest.fixture(scope="session")
def neo4j_client(neo4j_docker_compose: None) -> Generator[Neo4jClient, None, None]:
    """Provide a Neo4j client connected to the test database."""

    cfg: Neo4jConfig = Neo4jConfig(uri=NEO4J_BOLT_URI, user=NEO4J_USER, password=NEO4J_PASSWORD)
    client: Neo4jClient = Neo4jClient(cfg)
    yield client
    client.close()


@pytest.fixture(autouse=True)
def clear_neo4j_database(neo4j_client: Neo4jClient) -> Generator[None, None, None]:
    """Ensure the Neo4j database is empty before each test."""

    neo4j_client.run_write(CLEAR_DATABASE_QUERY)
    yield
