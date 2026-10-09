"""Link class field declarations to the code that writes and reads them.

Attribute accesses (``user.preferred_sort = value``, ``f(current_user().preferred_sort)``)
are recorded per file while parsing; once the whole project is parsed, each access
is matched to a field declared in a class body (an ORM column, dataclass field or
``self.x`` assignment). Writes flow into the field and the field flows into reads,
so data stored in an object and read elsewhere becomes reachable in the CPG.
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import NamedTuple

from models.base import NodeID
from models.edges.data_flow import DataFlowFlowsTo


class FieldDeclaration(NamedTuple):
    """A field declared on a class.

    Attributes:
        class_id: Declaring class.
        name: Field name.
        node_id: Node of the declaration.
    """

    class_id: NodeID
    name: str
    node_id: NodeID


class FieldAccess(NamedTuple):
    """An ``<expr>.<name>`` access attached to the nearest CPG node.

    Attributes:
        name: Accessed attribute name.
        site_id: Node the access belongs to (assignment target, call or function).
        is_write: Whether the access assigns the attribute.
        receiver_class_id: Class of ``<expr>`` when known (``self``/``cls``).
    """

    name: str
    site_id: NodeID
    is_write: bool
    receiver_class_id: NodeID | None = None


class _FieldIndex(NamedTuple):
    by_class: Mapping[NodeID, Mapping[str, NodeID]]
    declaring_classes: Mapping[str, frozenset[NodeID]]
    class_bases: Mapping[NodeID, tuple[NodeID, ...]]

    def resolve(self, access: FieldAccess) -> NodeID | None:
        if access.receiver_class_id is not None:
            return self._lookup(access.receiver_class_id, access.name)
        classes = self.declaring_classes.get(access.name, frozenset())
        if len(classes) != 1:
            return None
        return self.by_class[next(iter(classes))][access.name]

    def _lookup(self, class_id: NodeID, name: str) -> NodeID | None:
        pending: list[NodeID] = [class_id]
        visited: set[NodeID] = set()
        while pending:
            current = pending.pop(0)
            if current in visited:
                continue
            visited.add(current)
            field_id = self.by_class.get(current, {}).get(name)
            if field_id is not None:
                return field_id
            pending.extend(self.class_bases.get(current, ()))
        return None


def _build_index(
    declarations: Iterable[FieldDeclaration],
    class_bases: Mapping[NodeID, tuple[NodeID, ...]],
) -> _FieldIndex:
    by_class: dict[NodeID, dict[str, NodeID]] = defaultdict(dict)
    for declaration in declarations:
        if declaration.name.startswith("__") and declaration.name.endswith("__"):
            continue
        by_class[declaration.class_id].setdefault(declaration.name, declaration.node_id)

    declaring_classes: dict[str, set[NodeID]] = defaultdict(set)
    for class_id, fields in by_class.items():
        for name in fields:
            declaring_classes[name].add(class_id)

    return _FieldIndex(
        by_class=by_class,
        declaring_classes={name: frozenset(ids) for name, ids in declaring_classes.items()},
        class_bases=class_bases,
    )


def link_field_accesses(
    declarations: Iterable[FieldDeclaration],
    accesses: Iterable[FieldAccess],
    class_bases: Mapping[NodeID, tuple[NodeID, ...]],
) -> list[DataFlowFlowsTo]:
    """Return data-flow edges between field accesses and the fields they touch.

    An access with a known receiver class resolves through that class and its
    bases; otherwise only a field name declared by exactly one class resolves,
    so common names such as ``id`` or ``name`` never link unrelated models.

    Args:
        declarations: Fields declared in class bodies across the project.
        accesses: Attribute reads and writes across the project.
        class_bases: Repository base classes of each class.

    Returns:
        Unique ``FLOWS_TO`` edges: write site → field and field → read site.
    """

    index = _build_index(declarations, class_bases)
    edges: dict[tuple[NodeID, NodeID], DataFlowFlowsTo] = {}
    for access in accesses:
        field_id = index.resolve(access)
        if field_id is None or field_id == access.site_id:
            continue
        src, dst = (access.site_id, field_id) if access.is_write else (field_id, access.site_id)
        edges.setdefault((src, dst), DataFlowFlowsTo(src=src, dst=dst))
    return list(edges.values())
