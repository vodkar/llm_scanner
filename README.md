# llm-scanner CLI

Use the unified Typer-powered CLI via the single console script `llm-scanner`.

Commands

- `load-sample [PATH]` – parse one Python file and load its CPG into Neo4j. Defaults to `tests/sample.py`. Configure Neo4j with `NEO4J_URI`, `NEO4J_USER`, and `NEO4J_PASSWORD` or the corresponding options.
- `load-all-samples [TESTS_DIR]` – parse all Python files (excluding `__init__.py`) in a directory and write a combined YAML graph to `output.yaml` unless overridden with `--output`.
- `run-pipeline PATH` – run the full analysis pipeline against a project directory.

Examples

```bash
uv run llm-scanner load-sample tests/sample.py
uv run llm-scanner load-all-samples tests --output output.yaml
uv run llm-scanner run-pipeline tests/sample_project
```
