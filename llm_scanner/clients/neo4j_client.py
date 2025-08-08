from __future__ import annotations

import os
from pydantic import BaseModel
from typing import Any, Dict, Iterable, LiteralString, Optional

from neo4j import GraphDatabase, Driver


class Neo4jConfig(BaseModel):
    uri: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user: str = os.getenv("NEO4J_USER", "neo4j")
    password: str = os.getenv("NEO4J_PASSWORD", "test")


class Neo4jClient:
    def __init__(self, cfg: Optional[Neo4jConfig] = None):
        self.cfg = cfg or Neo4jConfig()
        self._driver: Driver = GraphDatabase.driver(self.cfg.uri, auth=(self.cfg.user, self.cfg.password))

    def close(self) -> None:
        self._driver.close()

    def run_write(self, query: LiteralString, params: Optional[Dict[str, Any]] = None) -> None:
        with self._driver.session() as session:
            session.execute_write(lambda tx: tx.run(query, **(params or {})))

    def run_read(self, query: LiteralString, params: Optional[Dict[str, Any]] = None) -> Iterable[Dict[str, Any]]:
        with self._driver.session() as session:
            result = session.execute_read(lambda tx: tx.run(query, **(params or {})))
            for rec in result:
                yield rec.data()
