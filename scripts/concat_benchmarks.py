#!/usr/bin/env python3
"""Concatenate cvefixes_context_benchmark_1.json and cvefixes_context_benchmark_2.json."""

import json
from collections import Counter
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"

file1 = DATA_DIR / "cvefixes_context_benchmark_1.json"
file2 = DATA_DIR / "cvefixes_context_benchmark_2.json"
output = DATA_DIR / "cvefixes_context_benchmark_combined.json"

d1 = json.loads(file1.read_text())
d2 = json.loads(file2.read_text())

combined_samples = d1["samples"] + d2["samples"]

cwe_distribution: dict[str, int] = Counter()
for cwe, count in d1["metadata"]["cwe_distribution"].items():
    cwe_distribution[cwe] += count
for cwe, count in d2["metadata"]["cwe_distribution"].items():
    cwe_distribution[cwe] += count

combined = {
    "metadata": {
        "name": d1["metadata"]["name"],
        "task_type": d1["metadata"]["task_type"],
        "total_samples": len(combined_samples),
        "cwe_distribution": dict(sorted(cwe_distribution.items())),
    },
    "samples": combined_samples,
}

output.write_text(json.dumps(combined, indent=2))
print(f"Written {len(combined_samples)} samples to {output}")
