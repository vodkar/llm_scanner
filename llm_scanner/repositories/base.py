from typing import Any, Final, LiteralString

from pydantic import BaseModel, ConfigDict

from clients.neo4j import Neo4jClient

CORE_INDEX_QUERIES: Final[tuple[LiteralString, ...]] = (
    "CREATE INDEX code_id IF NOT EXISTS FOR (c:Code) ON (c.id)",
    "CREATE INDEX code_file_path IF NOT EXISTS FOR (c:Code) ON (c.file_path)",
    "CREATE INDEX finding_id IF NOT EXISTS FOR (f:Finding) ON (f.id)",
)

_INDEXED_URIS: set[str] = set()


def ensure_core_indexes(client: Neo4jClient) -> None:
    """Ensure indexes required by the current query set exist.

    The work is idempotent on the Neo4j side, but ``CREATE INDEX IF NOT EXISTS``
    still emits an INFO notification each time it runs against existing indexes.
    Per-URI memoization avoids the per-sample log spam in long-running tuning
    sessions while keeping the call cheap for first-time callers.

    Args:
        client: Neo4j client used to execute schema updates.
    """

    uri: str | None
    try:
        uri = client.cfg.uri
    except AttributeError:
        # Mocked clients in tests may not expose ``cfg`` — fall through and
        # run the queries unconditionally. Production clients always have it.
        uri = None
    if uri is not None and uri in _INDEXED_URIS:
        return
    for query in CORE_INDEX_QUERIES:
        client.run_write(query)
    if uri is not None:
        _INDEXED_URIS.add(uri)


class Neo4jRepository(BaseModel):
    client: Neo4jClient
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def _ensure_indexes(self) -> None:
        """Ensure core indexes are available for graph ingestion."""

        ensure_core_indexes(self.client)

    def model_post_init(self, context: Any) -> None:
        self._ensure_indexes()
        return super().model_post_init(context)
