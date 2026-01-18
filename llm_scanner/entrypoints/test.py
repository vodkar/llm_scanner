from pathlib import Path

from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder


if __name__ == "__main__":
    test_file = Path("tests/data/imports.py")

    builder = CPGFileBuilder(path=test_file)
    result = builder.build()
