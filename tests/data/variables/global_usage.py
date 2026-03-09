global_var = [1, 2, 3]
config = {"debug": True}


def process_data(items: list) -> None:
    for item in items:
        print(item)


def main() -> None:
    local_a = global_var
    local_b = config["debug"]
    process_data(local_a)


def helper(x: int, y: int) -> int:
    result = x + y
    return result
