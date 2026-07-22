"""Generate per-entry verification task files for the vulnerability dataset.

Reads the CleanVul-style CSV and emits one ``task_<n>.md`` file per Python
(``extension == "py"``) row into an output directory. Each task file is a
self-contained prompt instructing an LLM (GPT 5.5) to clone the source
repository, inspect the real change at the recorded commit, and decide whether
the entry is a genuine, properly-fixed security vulnerability.
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

# Source code fields can be long; raise the CSV field-size cap.
csv.field_size_limit(10_000_000)

PY_EXTENSION: Final[str] = "py"
CODE_FENCE: Final[str] = "````"  # 4 backticks: survives stray ``` inside source


@dataclass(frozen=True, slots=True)
class CommitRef:
    """Parsed GitHub commit coordinates."""

    owner: str
    repo: str
    sha: str

    @classmethod
    def from_url(cls, url: str) -> CommitRef | None:
        """Parse ``https://github.com/<owner>/<repo>/commit/<sha>``.

        Returns None when the URL does not match the expected GitHub shape.
        """
        parts: list[str] = url.strip().rstrip("/").split("/")
        if len(parts) < 7 or parts[2] != "github.com" or parts[5] != "commit":
            return None
        return cls(owner=parts[3], repo=parts[4], sha=parts[6])

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}.git"

    @property
    def cache_dirname(self) -> str:
        return f"{self.owner}__{self.repo}"


def _fenced(code: str, lang: str = "python") -> str:
    return f"{CODE_FENCE}{lang}\n{code}\n{CODE_FENCE}"


def _field(row: dict[str, str], key: str) -> str:
    value: str = (row.get(key) or "").strip()
    return value if value else "_(empty)_"


def _render_task(index: int, row: dict[str, str], ref: CommitRef | None) -> str:
    commit_url: str = (row.get("commit_url") or "").strip()
    file_name: str = (row.get("file_name") or "").strip()
    func_before: str = row.get("func_before") or ""
    func_after: str = row.get("func_after") or ""

    if ref is not None:
        clone_block: str = "\n".join(
            (
                f"- Repository: `{ref.clone_url}`",
                f"- Commit SHA: `{ref.sha}`",
                f"- Local cache path: `data/repo_cache/{ref.cache_dirname}`",
            )
        )
        clone_cmds: str = "\n".join(
            (
                "REPO_DIR=data/repo_cache/" + ref.cache_dirname,
                'if [ -d "$REPO_DIR/.git" ]; then',
                '  git -C "$REPO_DIR" fetch --quiet origin || true',
                "else",
                f'  git clone --filter=blob:none {ref.clone_url} "$REPO_DIR"',
                "fi",
                f'git -C "$REPO_DIR" fetch --quiet origin {ref.sha} || true',
                f'git -C "$REPO_DIR" checkout --quiet {ref.sha}',
                "",
                "# Inspect the REAL change for this file at this commit:",
                f'git -C "$REPO_DIR" show {ref.sha} -- "{file_name}"',
                "# Parent state of the file (the vulnerable version):",
                f'git -C "$REPO_DIR" show {ref.sha}^:"{file_name}" | head -200',
            )
        )
    else:
        clone_block = (
            f"- Commit URL (could not be auto-parsed): `{commit_url}`\n"
            "- Derive the clone URL, commit SHA, and a cache path under "
            "`data/repo_cache/` from the URL yourself."
        )
        clone_cmds = (
            "# The commit_url did not match the standard GitHub pattern.\n"
            "# Parse owner/repo/sha from the URL above, then clone into\n"
            "# data/repo_cache/<owner>__<repo> and checkout the SHA."
        )

    return f"""# Verification Task {index}

You are a security code reviewer. Confirm whether the dataset entry below
represents a **real, exploitable security vulnerability** that was **actually
fixed** by the recorded commit — or whether it is a false positive (refactor,
style change, non-security bugfix, test/doc change, or otherwise mislabeled).

## Entry metadata

| Field | Value |
|-------|-------|
| Commit URL | {commit_url or "_(empty)_"} |
| Changed file | `{file_name or "(empty)"}` |
| CVE id | {_field(row, "cve_id")} |
| CWE id | {_field(row, "cwe_id")} |
| Vulnerability score | {_field(row, "vulnerability_score")} |
| Date | {_field(row, "date")} |

### Commit message
{_fenced((row.get("commit_msg") or "").strip() or "(empty)", "text")}

## Step 1 — Obtain the repository (reuse cache if present)

{clone_block}

Run (bash):
{_fenced(clone_cmds, "bash")}

If the commit or file cannot be fetched (force-pushed, deleted repo, renamed
file), record that in the verdict and rely on the recorded snippets below.

## Step 2 — Determine what actually changed

1. Read the real diff from `git show` above — do **not** trust the snippets
   blindly; the dataset may be noisy.
2. Locate the function for `{file_name or "the changed file"}` in both the
   parent (`{ref.sha + "^" if ref else "<sha>^"}`) and the commit
   (`{ref.sha if ref else "<sha>"}`).
3. Compare the real change against the recorded `func_before` / `func_after`
   below. Note any discrepancy.

## Step 3 — Assess the security claim

Answer concretely, citing the code:

- What is the alleged weakness (e.g. ReDoS, XSS, command/SQL injection, path
  traversal, deserialization, SSRF, auth bypass)? Map it to a CWE.
- Is there a plausible **attacker-controlled input** reaching a dangerous sink
  in the *before* version? Trace the data flow.
- Does the *after* version actually remove or neutralize that path (validation,
  escaping, safe API, sanitizer), or is it cosmetic / incomplete?
- Could this be a false positive? Consider: pure refactor, performance-only
  change, unrelated bugfix, test/fixture/docs, or defense-in-depth with no real
  exploit.

## Recorded `func_before` (claimed vulnerable)

{_fenced(func_before or "(empty)")}

## Recorded `func_after` (claimed fixed)

{_fenced(func_after or "(empty)")}

## Step 4 — Write the verdict

Append the following section to the END of this file (overwrite the placeholder
below) with your conclusions:

```
## VERDICT

- Real vulnerability: YES | NO | UNCERTAIN
- Properly fixed by this commit: YES | NO | PARTIAL | UNCERTAIN
- Vulnerability class (CWE): <id + short name, or N/A>
- Attacker-controlled input -> sink: <one-line data-flow summary, or N/A>
- Snippet matches real diff: YES | NO (explain if NO)
- Confidence: <0-100%>
- Reasoning: <2-5 sentences grounded in the actual code>
- Evidence: <key commands run / file:line references observed>
```

## VERDICT

_To be completed by the analyzing LLM._
"""


def generate(csv_path: Path, out_dir: Path) -> int:
    """Generate task files for every Python row. Returns the number written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: int = 0
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader: csv.DictReader[str] = csv.DictReader(handle)
        for row in reader:
            if (row.get("extension") or "").strip().lower() != PY_EXTENSION:
                continue
            written += 1
            ref: CommitRef | None = CommitRef.from_url(row.get("commit_url") or "")
            content: str = _render_task(written, row, ref)
            (out_dir / f"task_{written}.md").write_text(content, encoding="utf-8")
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--csv",
        type=Path,
        default=Path("data/vulnerability_score_4.csv"),
        help="Input dataset CSV.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("data/verification_tasks"),
        help="Directory to write task_<n>.md files into.",
    )
    args = parser.parse_args()
    count: int = generate(args.csv, args.out_dir)
    print(f"Wrote {count} task files to {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
