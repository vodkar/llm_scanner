from tree_sitter import Node as TSNode


def field_names_for(node: TSNode) -> list[str]:
    fields: set[str] = set()
    for i, _child in enumerate(node.children):
        field = node.field_name_for_child(i)
        if field:
            fields.add(field)
    return sorted(fields)
