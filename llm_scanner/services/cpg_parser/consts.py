# Code block types are no longer split by construct type.
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
