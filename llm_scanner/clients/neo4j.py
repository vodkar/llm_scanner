from __future__ import annotations

from contextlib import contextmanager
import os
from pydantic import BaseModel
from typing import Any, Generator, Iterable, LiteralString, Optional

from neo4j import GraphDatabase, Driver


class Neo4jConfig(BaseModel):
    uri: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user: str = os.getenv("NEO4J_USER", "neo4j")
    password: str = os.getenv("NEO4J_PASSWORD", "test")


class Neo4jClient:
    def __init__(self, cfg: Optional[Neo4jConfig] = None):
        self.cfg = cfg or Neo4jConfig()
        self._driver: Driver = GraphDatabase.driver(
            self.cfg.uri, auth=(self.cfg.user, self.cfg.password)
        )

    def close(self) -> None:
        self._driver.close()

    def run_write(
        self, query: LiteralString, params: Optional[dict[str, Any]] = None
    ) -> None:
        with self._driver.session() as session:
            session.execute_write(lambda tx: tx.run(query, **(params or {})))

    def run_read(
        self, query: LiteralString, params: Optional[dict[str, Any]] = None
    ) -> Iterable[dict[str, Any]]:
        with self._driver.session() as session:
            result = session.execute_read(lambda tx: tx.run(query, **(params or {})))
            for rec in result:
                yield rec.data()


@contextmanager
def build_client(
    uri: str, user: str, password: str, /, *, cfg: Neo4jConfig | None = None
) -> Generator[Neo4jClient, None, None]:
    """Create a Neo4j client with provided or environment-backed config.

    Args:
        uri: Bolt URI for the Neo4j instance.
        user: Username for authentication.
        password: Password for authentication.
        cfg: Optional pre-built configuration to reuse.

    Returns:
        Neo4jClient: Configured Neo4j client ready for queries.
    """
    if cfg is None:
        cfg = Neo4jConfig(uri=uri, user=user, password=password)
    client = Neo4jClient(cfg)

    yield client

    client.close()
