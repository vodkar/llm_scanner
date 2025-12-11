from pathlib import Path

from entrypoints.base import parse_file_to_cpg, parse_project_to_cpg
from models.edges import EdgeType
from tests.consts import SAMPLE_FILE, SAMPLE_PROJECT_ROOT


def test_parse_sample(tmp_path: Path):
    nodes, edges = parse_file_to_cpg(SAMPLE_FILE)

    # basic expectations
    assert any(n.type == "Module" for n in nodes.values())
    assert any(n.type == "Class" and n.name == "Order" for n in nodes.values())
    assert any(n.type == "Function" and n.name == "demo" for n in nodes.values())

    # calls should include demo -> export_orders_csv
    funcs = {n.qualname: n.id for n in nodes.values() if n.type == "Function"}
    demo_id = funcs.get("sample.demo") or funcs.get("demo")
    export_id = next(
        (nid for q, nid in funcs.items() if q.endswith("export_orders_csv")), None
    )
    assert demo_id and export_id
    assert any(
        e.type == EdgeType.CALLS and e.src == demo_id and e.dst == export_id
        for e in edges
    )
    assert any(
        e.type == EdgeType.CALLS and e.src == demo_id and e.dst == export_id
        for e in edges
    )


def test_parse_project_cross_file_calls(tmp_path: Path):
    # Use sample_project package under tests/
    nodes, edges = parse_project_to_cpg(SAMPLE_PROJECT_ROOT)

    # expect modules for main and utils
    assert any(
        n.type == "Module" and n.qualname.endswith("sample_project")
        for n in nodes.values()
    )
    funcs = {n.qualname: n.id for n in nodes.values() if n.type == "Function"}

    # We should have greet and run
    greet_id = next(
        (nid for q, nid in funcs.items() if q.endswith("utils.greet")), None
    )
    run_id = next((nid for q, nid in funcs.items() if q.endswith("main.run")), None)
    assert greet_id and run_id

    # Calls edge from main.run -> utils.greet
    assert any(
        e.type == EdgeType.CALLS and e.src == run_id and e.dst == greet_id
        for e in edges
    )
