from pathlib import Path
from typing import Any
from pydantic import BaseModel, PrivateAttr
from tree_sitter import Tree, Node as TSNode


class SourceFile(BaseModel):
    """Represents a source file in the codebase."""

    path: Path
    tree: Tree
    __lines: list[str] = PrivateAttr()

    def model_post_init(self, context: Any) -> None:
        self.__lines = self.path.read_text().splitlines()
        return super().model_post_init(context)

    def node_snippet(self, node: TSNode):
        """Extract the source code snippet for a given Tree-sitter node."""
        start_byte = node.start_byte
        end_byte = node.end_byte
        return "\n".join(self.__lines)[start_byte:end_byte]
