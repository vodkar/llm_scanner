# Command list for quick access

## Tuning ranking coefficients

### Gemma 4 12B, self-consistency=3 (current)

Serve the judge (defaults in `docker-compose.vllm.yaml` target Gemma 4 12B QAT on a 16 GB GPU):

```bash
HF_HUB_OFFLINE=1 docker compose -f docker-compose.vllm.yaml up -d
```

Tune all four strategies (20 trials × 400 samples × 3 votes each, majority vote per sample),
resumable, in tmux; best params are exported in place to `config/best_<strategy>.yaml`:

```bash
tmux new-session -d -s gemma_sc3_tune 'data/tune_out/gemma_sc3/run_all.sh'
```

Sampling: temperature 1.2, top-p 0.95, top-k 64, repetition penalty 1.1, thinking on.
Studies: `data/tuning_runs/gemma_sc3_<strategy>.db`. The script lives under `data/` (gitignored).

### Qwen3-8B (previous)

### Multiplicative Amplification

```bash
 uv run llm-scanner tune-ranking-coefficients \
    --strategy multiplicative_amplification \
    --trials 50 \
    --sample-count 300 \
    --judge-base-url http://192.168.158.128:8000/v1 \
    --judge-model Qwen/Qwen3-8B \
    --dataset data/vulnerability_score_4.csv \
    --output-dir data/tune_out \
    --repo-cache-dir data/repo_cache \
    --study-name multiplicative_amplification \
    --concurrency 20 \
    --judge-max-tokens 8000 \
    --judge-timeout 1200 \
    --max-call-depth 12 \
    --judge-temperature 0.0 |& tee data/tune_out/multiplicative_amplification.log
```

### Evidence Budgeted

```bash
uv run llm-scanner tune-ranking-coefficients \
    --strategy evidence_budgeted \
    --trials 50 \
    --sample-count 300 \
    --judge-base-url http://192.168.158.128:8000/v1 \
    --judge-model Qwen/Qwen3-8B \
    --dataset data/vulnerability_score_4.csv \
    --output-dir data/tune_out \
    --repo-cache-dir data/repo_cache \
    --study-name evidence_budgeted \
    --concurrency 20 \
    --judge-max-tokens 8000 \
    --judge-timeout 1200 \
    --max-call-depth 12 \
    --judge-temperature 0.0 |& tee data/tune_out/evidence_budgeted.log
```

### CPG Structural

```bash
uv run llm-scanner tune-ranking-coefficients \
    --strategy cpg_structural \
    --trials 100 \
    --sample-count 300 \
    --judge-base-url http://192.168.158.128:8000/v1 \
    --judge-model Qwen/Qwen3-8B \
    --dataset data/vulnerability_score_4.csv \
    --output-dir data/tune_out \
    --repo-cache-dir data/repo_cache \
    --study-name cpg_structural \
    --concurrency 20 \
    --judge-max-tokens 8000 \
    --judge-timeout 1200 \
    --max-call-depth 12 \
    --judge-temperature 0.0 |& tee data/tune_out/cpg_structural.log
```

### Current

```bash
uv run llm-scanner tune-ranking-coefficients \
    --strategy current \
    --trials 50 \
    --sample-count 300 \
    --judge-base-url http://192.168.158.128:8000/v1 \
    --judge-model Qwen/Qwen3-8B \
    --dataset data/vulnerability_score_4.csv \
    --output-dir data/tune_out \
    --repo-cache-dir data/repo_cache \
    --study-name current \
    --concurrency 20 \
    --judge-max-tokens 8000 \
    --judge-timeout 1200 \
    --max-call-depth 12 \
    --judge-temperature 0.0 |& tee data/tune_out/current.log
```

## Exporting best coefficients

```bash
scripts/export_best_coefficients.sh
```

## Build CleanVul Benchmark Compare Rankings Datasets

### All strategies — best + last in one pass (recommended)

Builds datasets for every strategy using both best-tuned and last-trial coefficients in a
single sample pass, so all outputs are drawn from the same samples and are directly comparable.
Last-coefficient paths default to `config/best_*_last.yaml` from `export-best-coefficients`.

```bash
uv run llm-scanner build-cleanvul-benchmark-compare-rankings-all \
    ~/CleanVul/vulnerability_score_4.csv \
    --samples 500 \
    --output-dir data/final \
    --max-call-depth 12 \
    --token-budget 2048 \
    --cpg-structural-coefficients config/best_cpg_structural.yaml \
    --budgeted-ranking-config config/best_evidence_budgeted.yaml \
    --multiplicative-amplification-coefficients config/best_multiplicative_amplification.yaml \
    --current-coefficients config/best_current.yaml \
    --repo-cache-dir data/repo_cache |& tee data/tune_out/build_compare_rankings_all.log
```

### Best coefficients only

```bash
uv run llm-scanner build-cleanvul-benchmark-compare-rankings \
    ~/CleanVul/vulnerability_score_4.csv \
    --samples 500 \
    --output-dir data/final \
    --max-call-depth 12 \
    --token-budget 2048 \
    --cpg-structural-coefficients config/best_cpg_structural.yaml \
    --budgeted-ranking-config config/best_evidence_budgeted.yaml \
    --multiplicative-amplification-coefficients config/best_multiplicative_amplification.yaml \
    --current-coefficients config/best_current.yaml \
    --repo-cache-dir data/repo_cache |& tee data/tune_out/build_compare_rankings_best.log
```

### Manual, best and last coefficients per strategy (from the prepared-sample cache)

Builds `cleanvul_context_benchmark_<strategy>_{manual,best,last}.json` for every tunable
strategy: `manual` uses the built-in coefficients, `best`/`last` read
`config/best_<strategy>.yaml` and `config/best_<strategy>_last.yaml`. Samples come from the
prepared-sample cache under `<repo-cache-dir>/prepared_samples`, so samples already
prepared by the tuner are reused and Neo4j is only needed for new ones. Use the same
depth, Semgrep and exclusion settings as the tuning run to hit the cache. Each strategy's
three files are written when it finishes; rerunning skips strategies already written.
`--min-score` (default 4) sets the lowest `vulnerability_score` kept; pass `--min-score 3`
for `vulnerability_score_3.csv`.

```bash
uv run llm-scanner build-cleanvul-benchmark-coefficient-variants \
    ~/CleanVul/vulnerability_score_4.csv \
    --samples 100000 \
    --output-dir data/ca_variants/score4 \
    --repo-cache-dir data/repo_cache_gemma_sc3 \
    --max-call-depth 12 \
    --token-budget 4096 \
    --render-workers 4 \
    --include-static-findings \
    --enable-semgrep --semgrep-config data/cleanvul_score4_v2_rebuild/semgrep_p_python.yaml \
    --exclude-samples /var/opt/llm4codesec-framework/benchmarks/cleanvul_wrong_labels.json \
    --exclude-section samples --exclude-section disputed |& tee data/ca_variants/score4.log
```

