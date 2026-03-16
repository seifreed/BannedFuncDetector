# Repository Guidelines

## Project Structure & Module Organization
BannedFuncDetector is a src-layout project with domain-driven grouping:

- `src/bannedfuncdetector/`: application code.
- `src/bannedfuncdetector/domain`: core entities and result types.
- `src/bannedfuncdetector/application`: analysis workflows and service orchestration.
- `src/bannedfuncdetector/infrastructure`: external integrations, decompilers, adapters, validators, and config handling.
- `src/bannedfuncdetector/presentation`: output/report formatting and CLI entrypoints.
- `tests/`: unit/integration coverage by layer.
- `BannedFuncDetector.py`, `README.md`, and `config.json`: entrypoint/package metadata and defaults.

## Build, Test, and Development Commands
Use these commands from the repo root:
- Install local package: `pip install -e .`
- Install development deps: `pip install -r requirements-dev.txt`
- Run CLI (dev mode): `PYTHONPATH=. bannedfunc -f <file>`
- Full test suite: `PYTHONPATH=. pytest -q`
- Targeted tests: `PYTHONPATH=. pytest -q tests/test_decompiler_selector.py`
- Lint: `ruff check src tests`
- Type check: `mypy src`
- Security lint: `bandit -q -r src`
- Dependency audit: `pip-audit -r requirements.txt` and `pip-audit -r requirements-dev.txt`

## Coding Style & Naming Conventions
Code is Python 3.12+ with explicit typing enforced by `mypy` configuration.
- Use 4-space indentation, `snake_case` for functions/variables, and `PascalCase` for classes.
- Keep modules focused (domain/app/infrastructure boundaries).
- Prefer small, typed helper functions and `Result`-style flow for failures where currently used.
- Use descriptive names for decompilers and file handlers (`r2ghidra`, `r2dec`, `decai`, etc.).
- Run formatting/linting before commit; keep import order clean and avoid unused code.

## Testing Guidelines
Tests use `pytest` with discovery defaults configured for `test_*.py`.
- Add tests near related behavior under `tests/test_<area>.py`.
- Reuse fixtures and shared setup from `tests/conftest.py`.
- New functionality should include at least one positive and one error-path test.
- For regressions, add a focused test first and include failing-to-green sequence in PR notes.

## Commit & Pull Request Guidelines
Recent history shows concise imperative messages (`Add ...`, `Fix ...`, etc.); follow that convention.
- Keep commits atomic and scoped to one change.
- PRs should include:
  - short summary of behavior changes,
  - rationale and tradeoffs,
  - exact validation commands run (with outputs if failures were fixed).
- For CLI or output changes, include usage or example updates when user-facing behavior changes.

## Security & Configuration Notes
Detection depends on external tooling (radare2 and optional plugins). Validate local system requirements before deep runtime tests, and prefer existing configuration paths over hardcoded binaries or absolute paths.
