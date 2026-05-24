#!/usr/bin/env bash
# Materialize the best params of every tuned ranking strategy into config/
# by invoking `llm-scanner export-best-coefficients` once per (study, strategy).
#
# Outputs:
#   config/best_cpg_structural.yaml
#   config/best_current.yaml
#   config/best_evidence_budgeted.yaml
#   config/best_multiplicative_amplification.yaml

set -euo pipefail

cd "$(dirname "$0")/.."

declare -a JOBS=(
  "cpg_structural        coefficients_fnr_depth_12          config/best_cpg_structural.yaml"
  "current               current_fnr_depth_12               config/best_current.yaml"
  "evidence_budgeted     evidence_budgeted_fnr_depth_12  config/best_evidence_budgeted.yaml"
  "multiplicative_boost  multiplicative_boost_fnr_depth_12  config/best_multiplicative_boost.yaml"
)

for job in "${JOBS[@]}"; do
  read -r strategy study output <<< "$job"
  echo ">>> ${strategy} <- data/tuning_runs/${study}.db -> ${output}"
  uv run llm-scanner export-best-coefficients \
    --strategy "$strategy" \
    --study-name "$study" \
    --output "$output"
done
