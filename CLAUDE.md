## STRONG TYPING RULES

- ALWAYS ADD **explicit type hints** to:
  - All function arguments and return values
  - All variable declarations where type isn't obvious
- USE BUILT-IN GENERICS:
  - `list`, `dict`, `set`, `tuple` instead of `List`, `Dict`, `Set`, `Tuple` etc.
  - `type1 | type2` instead of `Union[type1, type2]`
  - `type | None` instead of `Optional[type]`
- PREFER PRECISE TYPES over `Any`; AVOID `Any` UNLESS ABSOLUTELY REQUIRED
- USE:
  - `Final[...]` for constants. Do NOT USE `list` or `dict` as constants; use `tuple` or `MappingProxyType` instead
  - `ClassVar[...]` for class-level variables shared across instances
  - `Self` for methods that return an instance of the class
- For complex types, DEFINE CUSTOM TYPE ALIASES using `TypeAlias` for clarity

## CODE STYLE PRINCIPLES

- USE `f-strings` for all string formatting
- PREFER **list/dict/set comprehensions** over manual loops when constructing collections
- ALWAYS USE `with` context managers for file/resource handling
- USE `__` AND `_` prefixes for methods/variables to indicate private/protected scope.
- AVOID DEEP NESTING, prefer early returns and helper functions to flatten logic
- USE Enums (StrEnum, IntEnum) for sets of related constants instead of plain strings/ints
- ORGANIZE imports:
  - Standard library imports first
  - Third-party imports next
  - Local application imports last
  - WITHIN each group, SORT alphabetically
- Use `datetime.UTC` instead of `timezone.utc` for UTC timezone
- DO NOT put any logic in `__init__.py` files

## DOCSTRINGS & COMMENTS

- ADD triple-quoted docstrings to all **public functions and classes**
  - USE **Google-style** docstring formatting
  - DESCRIBE parameters, return types, and side effects if any
- OMIT OBVIOUS COMMENTS: clean code is self-explanatory

## ERROR HANDLING

- KEEP try/except blocks minimal; wrap a line of code that may throw in function with a clear exception handling strategy
- AVOID bare `except:` blocks — ALWAYS CATCH specific exception types
- AVOID using general exceptions like `Exception` or `BaseException`
- FAIL FAST: Validate inputs and raise `ValueError` / `TypeError` when appropriate
- USE `logging.exception()` to log errors with exception stack traces

## GENERAL INSTRUCTIONS

- DO NOT USE `@staticmethod`, prefer `@classmethod` or functions instead
- USE `@classmethod` for alternative constructors or class-level utilities (no `@staticmethod`)
- ALWAYS USE package managers for dependencies and virtual environments management; If package manager not specified, DEFAULT TO `pip` and `venv`
- FOLLOW the **Zen of Python (PEP 20)** to guide decisions on clarity and simplicity

ENFORCE ALL OF THE ABOVE IN EVERY GENERATED SNIPPET, CLASS, FUNCTION, AND MODULE.

## RUNNING CHECKS

Use `uv run` — no need to `source .venv/bin/activate` first.

### FULL PIPELINE (lint + type-check + tests)

```bash
uv run pre-commit run --all-files
```

This runs ruff fix → ruff format → isort → mypy → pytest → pytest coverage in one shot. Run this before committing.

### INDIVIDUAL CHECKS

```bash
# Linting (auto-fix where possible)
uv run ruff check --fix llm_scanner/ tests/

# Formatting
uv run ruff format llm_scanner/ tests/

# Type checking
uv run mypy llm_scanner/

# All tests
uv run pytest

# Specific test file or directory
uv run pytest tests/services/benchmark/ -v
uv run pytest tests/services/benchmark/test_cleanvul_loader.py -v
```

### KNOWN PRE-EXISTING MYPY ISSUE

`scripts/concat_compare_rankings.py:349` has a pre-existing type error unrelated to the main package — ignore it.

## LLM-JUDGE + COEFFICIENT TUNING

Start a local OpenAI-compatible endpoint with vLLM + Qwen:

```bash
docker compose -f docker-compose.vllm.yaml up -d
curl -fsS http://localhost:8000/v1/models  # sanity check
```

Run a smoke tune (3 trials × 5 samples) against the local judge:

```bash
uv run llm-scanner tune-ranking-coefficients \
    --strategy cpg_structural \
    --trials 3 \
    --sample-count 5 \
    --judge-base-url http://localhost:8000/v1 \
    --judge-model Qwen/Qwen2.5-7B-Instruct \
    --dataset path/to/cleanvul.csv \
    --output-dir data/tune_out \
    --repo-cache-dir data/repo_cache \
    --study-name smoke
```

Studies are persisted as SQLite under `data/tuning_runs/<study>.db`.
