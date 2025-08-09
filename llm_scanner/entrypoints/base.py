from models.edge import Edge
from models.node import Node
from services.cpg_parser import CPGBuilder
from utils.make_parseable_source import make_parseable_source


from pathlib import Path
from typing import Dict, List, Tuple


def parse_file_to_cpg(
    path: Path, ignore_magic: bool = True
) -> Tuple[Dict[str, Node], List[Edge]]:
    raw = Path(path).read_text(encoding="utf-8")
    src = make_parseable_source(raw)
    builder = CPGBuilder(src, str(path), ignore_magic=ignore_magic)
    return builder.build()
