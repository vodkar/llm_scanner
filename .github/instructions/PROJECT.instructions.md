---
applyTo: "**"
---

## Dependency management

`uv` is used as a dependency manager for Python projects.

## Code formatting

`black` is used for code formatting in this project. To format your code, run the following command:

```bash
uv run black .
```

## Type checking

`mypy` is used for static type checking in this project. To check your code for type errors, run the following command:

```bash
uv run mypy .
```

## The project structure

Main code stored in `llm_scanner/` folder. Use `PYTHONPATH=llm_scanner/` for running the project.

All code must be placed in correct folders:

- `llm_scanner/entrypoints` - Entry point scripts and command line interfaces
- `llm_scanner/services` - Business logic and service layer code
- `llm_scanner/models` - Data models and schemas
- `llm_scanner/clients` - External clients and libraries
- `llm_scanner/pipelines` - Data processing pipelines
- `llm_scanner/utils` - Utility functions and helpers

- `tests/` - Unit and integration tests

## Testing

Use `pytest` for running tests. To run the tests, use the following command:

```bash
uv run pytest tests/
```

## Class Definitions

Use `pydantic` for defining data models and schemas.
