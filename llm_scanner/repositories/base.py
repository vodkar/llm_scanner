from typing import Any, Final

from pydantic import BaseModel, ConfigDict

from clients.neo4j import Neo4jClient


class Neo4jRepository(BaseModel):
    client: Neo4jClient
    model_config = ConfigDict(arbitrary_types_allowed=True)

    _INDEX_QUERIES: Final[list[str]] = [
        "CREATE INDEX finding_id IF NOT EXISTS FOR (f:Finding) ON (f.id)",
        "CREATE INDEX finding_file IF NOT EXISTS FOR (f:Finding) ON (f.file)",
        "CREATE INDEX code_id IF NOT EXISTS FOR (c:Code) ON (c.id)",
        "CREATE INDEX code_file_path IF NOT EXISTS FOR (c:Code) ON (c.file_path)",
    ]

    def _ensure_indexes(self) -> None:
        """Ensure core indexes are available for graph ingestion."""
        for query in self._INDEX_QUERIES:
            self.client.run_write(query)

    def model_post_init(self, context: Any) -> None:
        self._ensure_indexes()
        return super().model_post_init(context)
