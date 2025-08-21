from pathlib import Path
from typing import Dict, List, Tuple

from models.edge import Edge
from models.node import Node
from services.cpg_parser import CPGBuilderService, ProjectCPGBuilder
from utils.make_parseable_source import make_parseable_source


def parse_file_to_cpg(
    path: Path, ignore_magic: bool = True
) -> Tuple[Dict[str, Node], List[Edge]]:
    raw = Path(path).read_text(encoding="utf-8")
    src = make_parseable_source(raw)
    builder = CPGBuilderService(src, str(path), ignore_magic=ignore_magic)
    return builder.build()


def parse_project_to_cpg(
    root: Path, ignore_magic: bool = True
) -> Tuple[Dict[str, Node], List[Edge]]:
    """Parse a multi-file project folder into a single CPG.

    root: directory path containing a Python package or project.
    """
    builder = ProjectCPGBuilder(root, ignore_magic=ignore_magic)
    return builder.build()
