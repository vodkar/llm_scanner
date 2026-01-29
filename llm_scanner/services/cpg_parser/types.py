from models.base import NodeID
from models.edges.base import RelationshipBase
from models.nodes import Node

type ParserResult = tuple[dict[NodeID, Node], list[RelationshipBase]]
