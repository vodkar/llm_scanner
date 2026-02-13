from pathlib import Path

from models.base import NodeID
from models.edges.call_graph import CallGraphCalledBy
from models.edges.data_flow import (
    DataFlowDefinedBy,
    DataFlowFlowsTo,
    DefinitionOperation,
)
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder
from tests.consts import IMPORT_LINK_PROJECT_ROOT
from tests.utils import symbol_byte_index


def test_cpg_directory_builder__links_imported_function_constant_and_class() -> None:
    """Validate cross-file linking for from-imports (function, constant, class)."""

    provider_file = IMPORT_LINK_PROJECT_ROOT / "provider.py"
    consumer_file = IMPORT_LINK_PROJECT_ROOT / "consumer.py"
    provider_rel: Path = provider_file.relative_to(IMPORT_LINK_PROJECT_ROOT)
    consumer_rel: Path = consumer_file.relative_to(IMPORT_LINK_PROJECT_ROOT)

    nodes, edges = CPGDirectoryBuilder(root=IMPORT_LINK_PROJECT_ROOT, link_imports=True).build()

    provider_data = provider_file.read_bytes()
    consumer_data = consumer_file.read_bytes()

    def provider_idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(provider_data, needle, start)

    def consumer_idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(consumer_data, needle, start)

    exported_function_id = NodeID.create(
        "function",
        "exported_function",
        str(provider_rel),
        provider_idx(b"def exported_function"),
    )
    exported_const_id = NodeID.create(
        "variable",
        "EXPORTED_CONST",
        str(provider_rel),
        provider_idx(b"EXPORTED_CONST ="),
    )
    exported_class_id = NodeID.create(
        "class",
        "ExportedClass",
        str(provider_rel),
        provider_idx(b"class ExportedClass"),
    )

    const_copy_id = NodeID.create(
        "variable",
        "const_copy",
        str(consumer_rel),
        consumer_idx(b"const_copy ="),
    )

    function_call_sb = consumer_idx(b"exported_function(EXPORTED_CONST)")
    function_call_id = NodeID.create(
        "call",
        "exported_function(EXPORTED_CONST)",
        str(consumer_rel),
        function_call_sb,
    )

    class_call_sb = consumer_idx(b"ExportedClass()")
    class_call_id = NodeID.create(
        "call",
        "ExportedClass()",
        str(consumer_rel),
        class_call_sb,
    )

    assert exported_function_id in nodes
    assert exported_const_id in nodes
    assert exported_class_id in nodes

    assert (
        DataFlowDefinedBy(
            src=exported_const_id,
            dst=const_copy_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )

    assert DataFlowFlowsTo(src=exported_const_id, dst=function_call_id) in edges

    assert CallGraphCalledBy(src=function_call_id, dst=exported_function_id) in edges
    assert CallGraphCalledBy(src=class_call_id, dst=exported_class_id) in edges
