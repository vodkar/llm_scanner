# from pathlib import Path
# from typing import Any, List, TypedDict, cast

# import yaml
# from entrypoints.base import parse_file_to_cpg
# from loaders.yaml_loader import YamlLoader
# from tests.consts import SAMPLE_FILE


# def test_yaml_loader_writes_file(tmp_path: Path):
#     nodes, edges = parse_file_to_cpg(SAMPLE_FILE)

#     out = tmp_path / "graph.yaml"
#     loader = YamlLoader(out)
#     loader.load(nodes, edges)

#     assert out.exists(), "Output YAML file should be created"

#     raw_obj: Any = yaml.safe_load(out.read_text(encoding="utf-8"))
#     assert isinstance(raw_obj, dict)
#     assert "nodes" in raw_obj and "edges" in raw_obj
#     assert isinstance(raw_obj["nodes"], list)
#     assert isinstance(raw_obj["edges"], list)

#     class NodeRow(TypedDict, total=False):
#         id: str
#         kind: str
#         code: str

#     class EdgeRow(TypedDict):
#         src: str
#         dst: str
#         type: str

#     nodes_list = cast(List[NodeRow], raw_obj["nodes"])
#     edges_list = cast(List[EdgeRow], raw_obj["edges"])

#     # Integrity checks similar to JSON test
#     node_ids: set[str] = {n["id"] for n in nodes_list if "id" in n}
#     assert all("kind" in n for n in nodes_list)
#     for e in edges_list:
#         assert e["src"] in node_ids
#         assert e["dst"] in node_ids
#         assert isinstance(e["type"], str)

#     # Readability: ensure at least one node has multi-line code and appears with '|' in YAML
#     # We can't inspect dumper style post-load, so assert file text contains a literal block
#     text = out.read_text(encoding="utf-8")
#     assert "\n  code: |\n" in text or "\n  code: |-\n" in text
