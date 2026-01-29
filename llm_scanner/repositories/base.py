from typing import Any

from pydantic import BaseModel, ConfigDict

from clients.neo4j import Neo4jClient


class Neo4jRepository(BaseModel):
    client: Neo4jClient
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def _ensure_indexes(self) -> None:
        """Ensure core indexes are available for graph ingestion."""
        pass

    def model_post_init(self, context: Any) -> None:
        self._ensure_indexes()
        return super().model_post_init(context)
