#!/usr/bin/env bash
set -euo pipefail
REPO="${1:-.}"
OUT="output/codeql"
mkdir -p "$OUT"
codeql database create "$OUT/db" -l=python -s "$REPO"
# run standard security pack (includes taint)
codeql pack download codeql/python-queries
codeql database analyze "$OUT/db" codeql/python-queries \
  --format=sarifv2.1.0 --output "$OUT/results.sarif"
# also run specific queries to ensure traces
codeql query run --database "$OUT/db" \
  python/ql/src/Security/CWE-078/CommandInjection.ql \
  --output "$OUT/ci.bqrs"
codeql bqrs decode "$OUT/ci.bqrs" --format=json > "$OUT/ci.json"
