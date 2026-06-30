# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.1.0] - 2026-06-30

### Added
- Cross-reference-based detection (`axffj`): banned calls are detected from each
  function's resolved call targets instead of regexing recovered C, so detection
  works on stripped/Go binaries where decompilation is unreliable. Fortified
  wrappers are unwrapped (`__strcpy_chk` -> `strcpy`) so they still match.
- AI-assisted decompilation backend (`decai`), driven entirely by `config.json`;
  defaults to OpenCode Zen free models (OpenAI-compatible), with selectable
  providers (ollama, gemini, anthropic, mistral, xai, deepseek, ...).
- Text and HTML report formats via `output.format` (alongside JSON). The HTML
  report escapes attacker-controlled symbol names.
- Public library API: `analyze_file()` and `analyze_directory()` returning a
  `Result` (`Ok`/`Err`), as documented in the README.
- `output.open_results`: open the saved report in the platform's default viewer
  (`open`/`xdg-open`/`start`) after a successful single-file scan.
- `--check-requirements` now surfaces libmagic availability, and the CLI warns
  when both detection methods (`--skip-banned` + `--skip-analysis`) are disabled.
- DEBUG logging (`-v`) of previously-silent libmagic and decompilation failures.

### Changed
- Batch per-function `axffj` cross-reference queries into a single r2pipe
  round-trip (sentinel-delimited), collapsing tens of thousands of round-trips
  into a handful — detection-loop time on large binaries drops sharply (measured
  ~15x on a 199k-function binary) with byte-identical results.
- Substring-gate banned-pattern matching and cache lowercased names in the
  detection pre-filter; cache r2-plugin availability instead of probing per
  function.
- Honor `config["analysis"]["timeout"]` for radare2's `anal.timeout` (was
  hardcoded to 30s), so large binaries can use the configured analysis budget.
- Consolidate the directory worker count under `analysis.max_workers` and drop
  the dead top-level `max_workers` duplicate (behavior unchanged).
- Large internal cleanup: removed dead legacy flat modules (~1000 lines),
  collapsed the 6-file decompiler `orchestrator` cluster into one module,
  centralized banned-function matching in the domain layer, and unified the
  duplicated decompiler backends and call/name matchers behind shared helpers.

### Fixed
- `--parallel` directory analysis is runnable again, with logging configured in
  the worker processes so `--parallel -v` emits DEBUG.
- Strip ANSI color from r2 output so decompilation-based detection isn't silently
  defeated by color codes splitting a call site.
- Wire the decompiler orchestrator into `create_binary_analyzer`, and honor
  custom `banned_functions` from config during a scan.
- Reject non-regular files (FIFO/device) so analysis can't hang; close the r2
  session on a `ValueError` during setup; warn when the r2 session dies mid-scan
  so a silently-partial result is visible.
- Surface unreadable subdirectories during a directory scan; correct file counts;
  stop discarding error categories/notices.
- `-v` now actually enables DEBUG; `--check-requirements` runs without `-f/-d`;
  an unusable output directory is reported instead of crashing with a traceback.
- Config robustness: validate `max_workers`/`timeout`/`small_function_threshold`
  types (reject bool/non-int), honor `worker_limit`, round-trip nested fields,
  accept a string port, and reject `r2ai-server` as a decompiler type instead of
  silently falling back.
- Defensive size coercion in DTOs (handles Decimal, never raises); resolve a
  function offset from the `sj` list and preserve address 0.
- decai: stop discarding valid decompilation that references error handling, and
  offer to install the r2ai-server when its binary is absent.

### Security
- Prevent r2 command injection via crafted function names.
- Harden the `decai -q` query against r2 command injection.

### Removed
- Dead config options with no runtime effect: `decompiler.options.error_threshold`,
  `decompiler.options.max_retries`, and the orphaned `r2pipe_threads` key.

### Internal
- Test suite hardened to 100% source coverage (no `pragma` exclusions) and made
  cross-platform; CI runs on Ubuntu/macOS/Windows with the strict coverage gate
  on Linux. Consolidated dependencies into a single `requirements.txt`.

## [3.0.1] - 2026-03-20

### Fixed
- Windows CI test failures - PE file detection fallback when python-magic fails
- GitHub Actions CI hangs - skip r2pipe tests in CI environment (Ubuntu, Windows)
- File detection returns None instead of False when magic detection fails, allowing magic bytes fallback

### Added
- GitHub Releases workflow with sdist and wheel assets
- Codecov coverage upload in CI workflow
- CHANGELOG.md for version tracking

## [3.0.0] - 2026-03-20

### Added
- Initial release with modular architecture (application, domain, infrastructure, presentation layers)
- Binary analysis using radare2 decompilers (default, r2dec, r2ghidra, decai)
- Detection of banned/insecure functions in binary files
- Directory scanning for batch analysis
- Parallel processing support
- Extensible decompiler registry
- OIDC trusted publishing to PyPI

### Security
- Input validation for all external command execution
- Allowlist-based subprocess execution
- No hardcoded secrets or credentials

### Changed
- Complete refactor from legacy script to modular architecture
- Improved error handling with Result types
- Comprehensive test coverage (89%+)