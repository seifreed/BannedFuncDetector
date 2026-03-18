# BannedFuncDetector — Copilot Instructions

## What This Project Does

A security tool that detects banned/insecure function calls (e.g., `strcpy`, `system`, `scanf`) in compiled binaries (PE/ELF/Mach-O) by running decompilers via radare2 and scanning the resulting pseudocode.

## Commands

```bash
# Setup
python -m pip install -e .
python -m pip install -r requirements-dev.txt

# Run all tests
python -m pytest -q

# Run a single test
python -m pytest tests/test_analyzers.py::TestClassName::test_method_name -v

# Lint
ruff check src tests

# Type check (strict mode)
mypy src

# Security lint
bandit -q -r src -c pyproject.toml

# Dependency audit
pip-audit -r requirements.txt && pip-audit -r requirements-dev.txt
```

Requires Python ≥3.13. CI matrix: Ubuntu/macOS/Windows × Python 3.13 and 3.14.

## Architecture

Clean Architecture with strict layer boundaries — outer layers depend on inner, never the reverse:

```
domain/         ← pure, no I/O: protocols, entities, Result type, banned function registry
infrastructure/ ← I/O & external: r2pipe adapter, decompiler impls, config, file detection
application/    ← orchestration: analyze_binary(), analyze_directory(), DI wiring
presentation/   ← output: terminal/JSON formatting, error messages
```

**Entry points**: `bannedfunc` CLI → `cli.py` / `cli_dispatch.py`; library API → `bannedfunc.py`.

**Dependency injection**: `AnalysisRuntime` (in `application/analysis_runtime.py`) is the DI container. Interfaces are `Protocol` classes in `domain/protocols.py` prefixed with `I` (e.g., `IDecompiler`, `IR2Client`, `IConfigRepository`). All protocols are `@runtime_checkable`.

**Error handling**: `Result[T, E]` (`Ok(value)` / `Err(error)`) from `domain/result.py` — no exception-based control flow in business logic. Inspired by Rust's `Result<T, E>`.

**Decompiler fallback chain**: r2ghidra → r2dec → default (pdc). Resolved at runtime by `infrastructure/decompilers/selector.py` and coordinated by `DecompilerOrchestrator`.

**Parallel scanning**: `analyze_directory()` uses `ThreadPoolExecutor` (default 4 workers) via `application/internal/directory_runners.py`.

## Key Conventions

**Naming**: `lower_snake_case` functions/vars, `UpperCamelCase` classes, `SCREAMING_SNAKE_CASE` constants, `IName` protocol interfaces.

**Type hints**: Required everywhere — mypy runs strict (`disallow_untyped_defs`, `no_implicit_optional`, `disallow_untyped_decorators`). No `Optional[T]` shorthand; use `T | None`.

**Domain entities**: All dataclasses use `frozen=True` — entities are immutable.

**Subprocess security**: All subprocess calls validate against `ALLOWED_EXECUTABLES` / `ALLOWED_REQUIREMENT_EXECUTABLES` allowlists via `_validate_executable()` before execution. Never use `shell=True`. Bandit skips B404/B603 for this reason (justified in `pyproject.toml`).

**`# noqa` / `# pragma: no cover`**: Avoid unless absolutely necessary; justify inline when used.

## Tests

- Mirror `src/` structure in `tests/`; test files: `test_*.py`, classes: `Test*`, functions: `test_*`
- Shared fixtures in `tests/conftest.py`: `FakeR2`, `FakeDecompilerOrchestrator`, `HTTPTestServer` — extend these for new adapters rather than creating new fixtures
- Coverage-focused integration tests live in `test_coverage_*.py` and `test_file_infra_coverage.py` — add new branch coverage there, not in new files
- CI scripts/shims are generated on the fly inside `conftest.py`

## Adding a New Decompiler

1. Create `src/bannedfuncdetector/infrastructure/decompilers/{name}_decompiler.py`
2. Inherit from `BaseR2Decompiler`; implement `IDecompiler`: `decompile()`, `is_available()`, `get_name()`
3. Register in `orchestrator_service.py`
4. Add `tests/test_{name}_decompiler.py` using `FakeR2` fixture
5. Update CLI help text if user-selectable
