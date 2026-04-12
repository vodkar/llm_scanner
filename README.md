# llm-scanner CLI

Use the unified Typer-powered CLI via the single console script `llm-scanner`.

Commands

- `load-sample [PATH]` – parse one Python file and load its CPG into Neo4j. Defaults to `tests/sample.py`. Configure Neo4j with `NEO4J_URI`, `NEO4J_USER`, and `NEO4J_PASSWORD` or the corresponding options.
- `load-all-samples [TESTS_DIR]` – parse all Python files (excluding `__init__.py`) in a directory and write a combined YAML graph to `output.yaml` unless overridden with `--output`.
- `run-pipeline PATH` – run the full analysis pipeline against a project directory.
- `build-cvefixes-benchmark DB_PATH` – build the CVEFixes-with-context benchmark dataset from a local CVEFixes SQLite database.
- `build-cleanvul-benchmark DATASET_PATH` – build the CleanVul-with-context benchmark dataset from a local CleanVul CSV or Parquet file.

Examples

```bash
uv run llm-scanner load-sample tests/sample.py
uv run llm-scanner load-all-samples tests --output output.yaml
uv run llm-scanner run-pipeline tests/sample_project
```

## Building benchmark datasets

Both benchmark commands clone GitHub repositories, build CPGs with Neo4j, and assemble LLM context around vulnerability spans. **Neo4j must be running** before either command is invoked (see `docker-compose.yml`).

### CVEFixes

Download the CVEFixes SQLite database, then:

```bash
uv run llm-scanner build-cvefixes-benchmark /path/to/CVEFixes.db \
  --samples 200 \
  --output-dir data/ \
  --max-call-depth 3 \
  --token-budget 2048 \
  --seed 42
```

Output: `data/cvefixes_context_benchmark.json` and `data/cvefixes_unassociated.json`.

### CleanVul

Download the CleanVul dataset from [Hugging Face](https://huggingface.co/datasets/yikun-li/CleanVul) (CSV or Parquet), then:

```bash
uv run llm-scanner build-cleanvul-benchmark /path/to/cleanvul.csv \
  --samples 200 \
  --output-dir data/ \
  --max-call-depth 3 \
  --token-budget 2048 \
  --min-score 3 \
  --seed 42
```

Output: `data/cleanvul_context_benchmark.json` and `data/cleanvul_unassociated.json`.

Key options:

| Option | Default | Description |
|--------|---------|-------------|
| `-n / --samples` | 50 | Number of benchmark samples to generate |
| `--output-dir` | `data/` | Directory to write output JSON files |
| `--repo-cache-dir` | system temp | Directory to cache cloned repositories |
| `--max-call-depth` | 3 | Call graph traversal depth for context assembly |
| `--token-budget` | 2048 | Token budget per assembled context |
| `--seed` | none | Random seed for reproducible sampling |
| `--min-score` | 3 | *(CleanVul only)* Minimum `vulnerability_score` (0–4) |
| `--python-only / --all-languages` | python-only | *(CleanVul only)* Restrict to Python files |
| `--exclude-tests / --include-tests` | exclude-tests | *(CleanVul only)* Exclude test files |
