def outer() -> None:
    x = 10

    def inner() -> None:
        y = x + 1

    inner()
