# Command list for quick access

## Tuning ranking coefficients

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