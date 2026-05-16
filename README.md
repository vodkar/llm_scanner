# llm-scanner CLI

Use the unified Typer-powered CLI via the single console script `llm-scanner`.

Commands

- `load-sample [PATH]` – parse one Python file and load its CPG into Neo4j. Defaults to `tests/sample.py`. Configure Neo4j with `NEO4J_URI`, `NEO4J_USER`, and `NEO4J_PASSWORD` or the corresponding options.
- `load-all-samples [TESTS_DIR]` – parse all Python files (excluding `__init__.py`) in a directory and write a combined YAML graph to `output.yaml` unless overridden with `--output`.
- `run-pipeline PATH` – run the full analysis pipeline against a project directory.
- `build-cvefixes-benchmark DB_PATH` – build the CVEFixes-with-context benchmark dataset from a local CVEFixes SQLite database.
- `build-cleanvul-benchmark DATASET_PATH` – build the CleanVul-with-context benchmark dataset (single ranking strategy: `current`) from a local CleanVul CSV or Parquet file.
- `build-cleanvul-benchmark-compare-rankings DATASET_PATH` – build aligned CleanVul datasets across **all** ranking strategies (one JSON file per strategy) for head-to-head benchmarking.

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

Output: `data/cvefixes_context_benchmark.json`.

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

Output: `data/cleanvul_context_benchmark.json`.

For aligned multi-strategy comparison (one dataset file per ranking strategy):

```bash
uv run llm-scanner build-cleanvul-benchmark-compare-rankings /path/to/cleanvul.csv \
  --samples 50 \
  --output-dir data/compare \
  --token-budget 2048
```

Output: one `cleanvul_context_benchmark_<strategy>.json` per ranking strategy (`current`,
`depth_repeats_context`, `random_picking`, `multiplicative_boost`, `cpg_structural`,
`evidence_budgeted`, `dummy`) and
`cleanvul_entries.json` files.

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

## Ranking strategies

Context-node ranking decides which lines reach the LLM under a hard token budget.
Available strategies (all selectable via `build-cleanvul-benchmark-compare-rankings`
and the tuner where applicable):

| Strategy | Combiner | Tunable from YAML | Notes |
|---|---|---|---|
| `current` | weighted sum (additive) | `config/ranking_coefficients_current.yaml` | Hand-tuned baseline; root pinned, security tier above context. |
| `multiplicative_boost` | $S_c \cdot (1 + \beta_{\text{sec}} \cdot S_{\text{sec}})$ | shared YAML | Context as base, security as boost. |
| `depth_repeats_context` | non-security baseline | none | Sorts by depth then repeats; ablation control. |
| `cpg_structural` | additive + per-edge depth | `config/ranking_coefficients_cpg_structural.yaml` | Edge-aware decay over `FLOWS_TO`/`SANITIZED_BY`/`CALLS`/…. |
| `evidence_budgeted` | **noisy-OR + greedy budgeted selection** | `config/budgeted_ranking_config_default.yaml` | New; 14-parameter operating point, role coverage + redundancy shaping. See `docs/evidence_aware_budgeted_ranking.md`. |
| `random_picking` | random | none | Lower-bound baseline. |
| `dummy` | identity | none | Returns nodes unchanged; control. |

Theory and formulas:

- `docs/ranking_system.md` — the additive system used by `current`, `multiplicative_boost`, `cpg_structural`.
- `docs/evidence_aware_budgeted_ranking.md` — the evidence-aware budgeted system used by `evidence_budgeted` (thesis-style).

## Tuning ranking coefficients with an LLM judge

The tunable strategies (`current`, `cpg_structural`, `evidence_budgeted`) read
their weights from a YAML file. The `llm-scanner tune-ranking-coefficients`
command samples those weights with Optuna, builds a benchmark per trial, and
scores it with an LLM judge served over an OpenAI-compatible endpoint.

### 1. Start the local judge (vLLM + Qwen)

```bash
docker compose -f docker-compose.vllm.yaml up -d
curl -fsS http://localhost:8000/v1/models   # sanity check
```

The default model is `Qwen/Qwen3.5-9B` with the `qwen3` reasoning parser
enabled. Override with the `MODEL` env var if you need a different one. Any
OpenAI-compatible endpoint works (vanilla OpenAI, Azure OpenAI, another vLLM
host) — pass its URL via `--judge-base-url`.

### 2. Make sure Neo4j is running

```bash
docker compose -f docker-compose.yml up -d neo4j
```

### 3. Run the tuner

Smoke run (3 trials × 5 samples) against the local judge:

```bash
uv run llm-scanner tune-ranking-coefficients \
    --strategy cpg_structural \
    --trials 3 \
    --sample-count 5 \
    --judge-base-url http://localhost:8000/v1 \
    --judge-model Qwen/Qwen3.5-9B \
    --dataset /path/to/cleanvul.csv \
    --output-dir data/tune_out \
    --repo-cache-dir data/repo_cache \
    --study-name smoke \
    --concurrency 1 \
    --judge-max-tokens 8192 \
    --judge-timeout 1200
```

To tune the new evidence-aware budgeted strategy, swap `--strategy`:

```bash
uv run llm-scanner tune-ranking-coefficients \
    --strategy evidence_budgeted \
    --trials 30 \
    --sample-count 40 \
    --judge-base-url http://localhost:8000/v1 \
    --judge-model Qwen/Qwen3-8B \
    --dataset /path/to/cleanvul.csv \
    --output-dir data/tune_out \
    --repo-cache-dir data/repo_cache \
    --study-name evidence_budgeted_v1 \
    --judge-max-tokens 4096
```

The 14-parameter search space (`depth_decay`, `context_strength`, `role_prior_temperature`,
the three evidence scales, `lexical_fallback_cap`, `token_cost_power`, `novelty_penalty`,
`role_coverage_bonus`, `small_node_token_threshold`, `local_window_radius`,
`budget_safety_ratio`) is documented in `docs/evidence_aware_budgeted_ranking.md` §9.
The tuner writes the best `BudgetedRankingConfig` to the SQLite study; the runtime
loads it via `BudgetedRankingConfig.from_yaml(...)` for evaluation.

Each trial clones the required repos (cached under `--repo-cache-dir`), builds
CPGs in Neo4j, assembles benchmark contexts with sampled coefficients, and
asks the judge to classify each sample. Optuna maximizes accuracy.

Studies are persisted as SQLite at `data/tuning_runs/<study-name>.db` — re-run
with the same `--study-name` to resume a study.

Key options:

| Option | Default | Description |
|--------|---------|-------------|
| `--strategy` | required | `cpg_structural`, `current`, or `evidence_budgeted` |
| `--trials` | 20 | Number of Optuna trials |
| `--sample-count` | 40 | Benchmark samples per trial |
| `--judge-base-url` | `http://localhost:8000/v1` | OpenAI-compatible endpoint |
| `--judge-model` | required | Model name to send to the endpoint |
| `--judge-api-key` | `not-needed` | API key (vLLM ignores it) |
| `--judge-max-tokens` | 2048 | Per-response token budget; raise for thinking models |
| `--judge-timeout` | 600 | Per-request timeout in seconds |
| `--concurrency` | 8 | Parallel judge requests |
| `--study-name` | UTC timestamp | Optuna study name (also the SQLite filename) |
| `--base-coefficients` | `config/ranking_coefficients_cpg_structural.yaml` | Starting point for `current`/`cpg_structural`; ignored for `evidence_budgeted` (uses module defaults). |
| `--max-call-depth` | 2 | Call graph traversal depth |
| `--seed` | 42 | Sampler / benchmark seed |
