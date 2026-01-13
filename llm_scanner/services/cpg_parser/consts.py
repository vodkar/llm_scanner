from models.nodes import CodeBlockType


CODE_BLOCK_TYPES: dict[str, CodeBlockType] = {
    "if_statement": CodeBlockType.IF,
    "for_statement": CodeBlockType.FOR,
    "while_statement": CodeBlockType.WHILE,
    "try_statement": CodeBlockType.TRY,
    "with_statement": CodeBlockType.WITH,
}
COMPLEXITY_NODES: set[str] = {
    "if_statement",
    "for_statement",
    "while_statement",
    "try_statement",
    "except_clause",
    "with_statement",
    "boolean_operator",
}
SENSITIVE_NAMES: set[str] = {
    "password",
    "secret",
    "token",
    "apikey",
    "api_key",
}
USER_INPUT_NAMES: set[str] = {
    "input",
    "request",
    "payload",
    "body",
    "event",
}
