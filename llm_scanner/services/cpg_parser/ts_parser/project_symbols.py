import io
from dataclasses import dataclass, field
from typing import Final

from models.base import NodeID

# Methods of builtin types: a call like ``data.items()`` almost never targets a
# repository method that happens to share the name, so these names never resolve
# through the repository-unique fallback.
BUILTIN_TYPE_METHOD_NAMES: Final[frozenset[str]] = frozenset(
    name
    for builtin_type in (
        str,
        bytes,
        bytearray,
        list,
        dict,
        set,
        frozenset,
        tuple,
        int,
        float,
        io.TextIOWrapper,
        io.BufferedReader,
        io.BufferedWriter,
    )
    for name in dir(builtin_type)
)


@dataclass(frozen=True)
class ProjectSymbols:
    """Project-wide class and method tables used to resolve attribute calls.

    Attributes:
        class_methods: Methods defined directly in each class body, by name.
        class_bases: Base classes of each class that resolve to repository classes.
        unique_methods: Method names defined exactly once in the repository.
    """

    class_methods: dict[NodeID, dict[str, NodeID]] = field(default_factory=dict)
    class_bases: dict[NodeID, tuple[NodeID, ...]] = field(default_factory=dict)
    unique_methods: dict[str, NodeID] = field(default_factory=dict)

    def lookup_method(self, class_id: NodeID, method_name: str) -> NodeID | None:
        """Find ``method_name`` on ``class_id`` or its bases (depth-first, left to right).

        Args:
            class_id: Class to start the lookup from.
            method_name: Method name to find.

        Returns:
            The first matching method identifier, or ``None``.
        """

        pending: list[NodeID] = [class_id]
        visited: set[NodeID] = set()
        while pending:
            current = pending.pop(0)
            if current in visited:
                continue
            visited.add(current)
            method_id = self.class_methods.get(current, {}).get(method_name)
            if method_id is not None:
                return method_id
            pending[0:0] = self.class_bases.get(current, ())
        return None

    def lookup_base_method(self, class_id: NodeID, method_name: str) -> NodeID | None:
        """Find ``method_name`` on the bases of ``class_id``, as ``super()`` does.

        Args:
            class_id: Class whose bases are searched.
            method_name: Method name to find.

        Returns:
            The first matching method identifier, or ``None``.
        """

        for base_id in self.class_bases.get(class_id, ()):
            method_id = self.lookup_method(base_id, method_name)
            if method_id is not None:
                return method_id
        return None
