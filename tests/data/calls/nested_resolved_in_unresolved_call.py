def _sanitize(value: str) -> str:
    return value.strip()


def snake_case(value: str) -> str:
    return external_lib.snakecase(_sanitize(value))
