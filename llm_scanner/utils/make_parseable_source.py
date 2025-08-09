import ast


def make_parseable_source(src: str) -> str:
    """Best-effort: if parsing fails, trim trailing lines until it succeeds.

    This helps tolerate accidentally duplicated footers or partial edits.
    """
    try:
        ast.parse(src)
        return src
    except SyntaxError:
        lines = src.splitlines()
        for i in range(len(lines), 0, -1):
            cand = "\n".join(lines[:i])
            try:
                ast.parse(cand)
                return cand
            except SyntaxError:
                continue
        # last resort: empty
        return ""
