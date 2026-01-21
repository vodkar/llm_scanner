EXPORTED_CONST = 42


def exported_function(x: int) -> int:
    return x + 1


class ExportedClass:
    def __init__(self) -> None:
        self.value = EXPORTED_CONST
