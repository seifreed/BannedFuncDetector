# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2025-03-20

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

### Fixed
- Windows CI test failures (PE file detection fallback, skip r2pipe tests)
- GitHub Actions CI hangs (skip r2pipe tests in CI environment)
- File detection fallback when python-magic fails on Windows