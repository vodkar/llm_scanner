import json
from pathlib import Path
from typing import Any, List, TypedDict, cast

from entrypoints.base import parse_file_to_cpg
from services.json_loader import JsonLoader


def test_json_loader_writes_file(tmp_path: Path):
    sample = Path(__file__).with_name("sample.py")
    nodes, edges = parse_file_to_cpg(sample)

    out = tmp_path / "graph.json"
    loader = JsonLoader(out)
    loader.load(nodes, edges)

    assert out.exists(), "Output JSON file should be created"

    raw_obj: Any = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(raw_obj, dict)
    assert "nodes" in raw_obj and "edges" in raw_obj
    assert isinstance(raw_obj["nodes"], list)
    assert isinstance(raw_obj["edges"], list)

    class NodeRow(TypedDict, total=False):
        id: str

    class EdgeRow(TypedDict):
        src: str
        dst: str
        type: str

    nodes_list = cast(List[NodeRow], raw_obj["nodes"])
    edges_list = cast(List[EdgeRow], raw_obj["edges"])

    # Basic integrity checks
    node_ids: set[str] = {n["id"] for n in nodes_list if "id" in n}
    for e in edges_list:
        assert e["src"] in node_ids
        assert e["dst"] in node_ids
        assert isinstance(e["type"], str)
