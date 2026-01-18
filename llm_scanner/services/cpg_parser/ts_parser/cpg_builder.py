from pathlib import Path
from typing import Any
from pydantic import BaseModel, ConfigDict, PrivateAttr
from tree_sitter import Parser, Tree, Node as TSNode

from tree_sitter import Language, Parser
import tree_sitter_python as tspython
from models.edges.core import Edge
from models.nodes import Node
from models.nodes.code import CodeBlockType
from services.cpg_parser.ts_parser.node_processor import NodeProcessor
from services.cpg_parser.types import ParserResult

CODE_BLOCK_TYPES: dict[str, CodeBlockType] = {
    "if_statement": CodeBlockType.IF,
    "for_statement": CodeBlockType.FOR,
    "while_statement": CodeBlockType.WHILE,
    "try_statement": CodeBlockType.TRY,
    "with_statement": CodeBlockType.WITH,
}


class CPGFileBuilder(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    path: Path
    __parser: Parser = PrivateAttr(
        default_factory=lambda: Parser(Language(tspython.language()))
    )
    __tree: Tree = PrivateAttr()
    __source: bytes = PrivateAttr()
    __source_text: str = PrivateAttr()
    __lines: list[str] = PrivateAttr()

    def model_post_init(self, context: Any) -> None:
        self.__source = self.path.read_bytes()
        self.__source_text = self.__source.decode("utf-8")
        self.__tree = self.__parser.parse(self.__source)
        self.__lines = self.__source_text.splitlines()
        self.__processor = NodeProcessor(
            path=self.path,
            source=self.__source,
            source_text=self.__source_text,
            lines=self.__lines,
        )
        return super().model_post_init(context)

    def build(self) -> ParserResult:
        """Build a CPG representation from the file."""

        return self.__processor.process(self.__tree.root_node)
