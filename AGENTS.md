# Repository Guidelines

## Project Structure & Module Organization
- Source lives in `src/bannedfuncdetector/` with layers: `application/` (orchestration), `domain/` (entities, protocols), `infrastructure/` (adapters, decompilers, file detection), and `presentation/` (CLI output helpers).
- Tests are under `tests/`, mirroring modules; fixtures sit in `tests/conftest.py`.
- CI config is in `.github/workflows/ci.yml`; scripts and shims used by tests are generated on the fly inside `tests/conftest.py`.

## Build, Test, and Development Commands
- Install (editable): `python -m pip install -e .`
- Dev deps: `python -m pip install -r requirements-dev.txt`
- Lint: `ruff check src tests`
- Security lint: `bandit -q -r src`
- Type check: `mypy src`
- Audit deps: `pip-audit -r requirements.txt && pip-audit -r requirements-dev.txt`
- Tests: `python -m pytest -q`
Run commands with Python ≥3.13; CI runs on 3.13 and 3.14 across Ubuntu, macOS, Windows.

## Coding Style & Naming Conventions
- Follow Ruff defaults plus project ruff config; keep imports sorted and unused code removed.
- Type hints are required; mypy runs in strict mode (disallow untyped defs, no implicit optional).
- Use lower_snake_case for functions/variables, UpperCamelCase for classes, and SCREAMING_SNAKE_CASE for constants.
- Keep modules small and layer-aware: domain is pure, infrastructure holds I/O, application wires behaviors, presentation only formats output.

## Testing Guidelines
- Prefer unit-style tests colocated in `tests/` with `test_*.py` naming; classes start with `Test` and functions with `test_`.
- Use fixtures from `tests/conftest.py` instead of duplicating setup; extend them when adding new adapters.
- Maintain or raise coverage; when adding branches, extend existing coverage-focused suites (`test_coverage_*`, `test_file_infra_coverage.py`) rather than creating duplicates.

## Commit & Pull Request Guidelines
- Commit messages: short imperative summary; group related fixes together.
- PRs should describe problem, approach, and test evidence (`python -m pytest -q`; add lint/type outputs when relevant). Include platform notes if a change is OS-specific.
- Keep diffs minimal and layer-safe; avoid altering public APIs without updating dependent tests/docs.

## Security & Configuration Tips
- Validate new external calls through adapters; keep allowlists tight (see `infrastructure/adapters`).
- Avoid disabling linters (`# noqa`, `# pragma: no cover`) unless absolutely necessary and justify in the code.
- When adding dependencies, prefer the minimal version that satisfies the need and document why in the PR description.
