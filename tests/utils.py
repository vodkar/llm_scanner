def symbol_byte_index(data: bytes, needle: bytes, start: int = 0) -> int:
    return data.index(needle, start)
