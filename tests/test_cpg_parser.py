from pathlib import Path

from entrypoints.base import parse_file_to_cpg
from models.edge import EdgeType


def test_parse_sample(tmp_path: Path):
    sample = Path(__file__).with_name("sample.py")
    nodes, edges = parse_file_to_cpg(sample)

    # basic expectations
    assert any(n.type == "Module" for n in nodes.values())
    assert any(n.type == "Class" and n.name == "Order" for n in nodes.values())
    assert any(n.type == "Function" and n.name == "demo" for n in nodes.values())

    # calls should include demo -> export_orders_csv
    funcs = {n.qualname: n.id for n in nodes.values() if n.type == "Function"}
    demo_id = funcs.get("sample.demo") or funcs.get("demo")
    export_id = next((nid for q, nid in funcs.items() if q.endswith("export_orders_csv")), None)
    assert demo_id and export_id
    assert any(e.type == EdgeType.CALLS and e.src == demo_id and e.dst == export_id for e in edges)
    assert any(e.type == EdgeType.CALLS and e.src == demo_id and e.dst == export_id for e in edges)
