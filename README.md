<p align="center">
  <img src="https://img.shields.io/badge/BannedFuncDetector-RE%20Security-blue?style=for-the-badge" alt="BannedFuncDetector">
</p>

<h1 align="center">BannedFuncDetector</h1>

<p align="center">
  <strong>Detect banned/insecure functions in binary files using radare2 decompilers</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/bannedfuncdetector/"><img src="https://img.shields.io/pypi/v/bannedfuncdetector?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/bannedfuncdetector/"><img src="https://img.shields.io/pypi/pyversions/bannedfuncdetector?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/BannedFuncDetector/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/BannedFuncDetector/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/BannedFuncDetector/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <img src="https://img.shields.io/badge/coverage-91%25-brightgreen?style=flat-square" alt="Coverage">
</p>

<p align="center">
  <a href="https://github.com/seifreed/BannedFuncDetector/stargazers"><img src="https://img.shields.io/github/stars/seifreed/BannedFuncDetector?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/BannedFuncDetector/issues"><img src="https://img.shields.io/github/issues/seifreed/BannedFuncDetector?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**BannedFuncDetector** is a Python tool that scans binary files to detect banned or insecure functions. It supports traditional radare2 decompilers and AI-assisted decompilation to provide readable output and highlight risky calls.

### Key Features

| Feature | Description |
|---------|-------------|
| **Binary Analysis** | Analyze PE/ELF/Mach-O binaries for banned functions |
| **Multiple Decompilers** | r2ghidra, r2dec, default, and decai (AI assistant) |
| **Directory Scans** | Analyze one file or whole directories |
| **Parallel Processing** | Speed up directory scans |
| **JSON Reports** | Results saved per target with structured output |
| **Library Mode** | Use via CLI or import as a Python package |

### Supported Decompilers

```
Default (pdc)  r2ghidra (pdg)  r2dec (pdd)  decai (AI assistant)
```

---

## Installation

### From PyPI (Recommended)

```bash
pip install bannedfuncdetector
```

### From Source

```bash
git clone https://github.com/seifreed/BannedFuncDetector.git
cd BannedFuncDetector
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

---

## Quick Start

```bash
# Analyze a single binary
bannedfunc -f /path/to/binary

# Analyze a directory
bannedfunc -d /path/to/binaries --parallel

# Use r2dec
bannedfunc -f /path/to/binary --decompiler r2dec
```

---

## Usage

### Command Line Interface

```bash
# Basic analysis
bannedfunc -f /path/to/binary

# Analyze a directory with parallel workers
bannedfunc -d /path/to/binaries --parallel

# Save output to a custom directory
bannedfunc -f /path/to/binary -o output

# Force a decompiler
bannedfunc -f /path/to/binary --decompiler r2ghidra --force-decompiler

# Skip decompilation analysis (names only)
bannedfunc -f /path/to/binary --skip-analysis
```

### Available Options

| Option | Description |
|--------|-------------|
| `-f, --file` | Executable file to analyze |
| `-d, --directory` | Directory with executables to analyze |
| `-o, --output` | Output directory for results |
| `--decompiler` | Decompiler to use (default, r2ghidra, r2dec, decai) |
| `--force-decompiler` | Force the specified decompiler |
| `--parallel` | Process files in parallel (directory only) |
| `--skip-banned` | Skip banned function name checks |
| `--skip-analysis` | Skip decompilation analysis |
| `--check-requirements` | Check system requirements before running |
| `-v, --verbose` | Show detailed information |

---

## Python Library

### Basic Usage

```python
from bannedfuncdetector.bannedfunc import analyze_file

result = analyze_file(
    "/path/to/binary",
    decompiler_type="r2ghidra",
    output_dir="output",
)

print(result)
```

### Directory Analysis

```python
from bannedfuncdetector.bannedfunc import analyze_directory

results = analyze_directory(
    "/path/to/binaries",
    output_dir="output",
    decompiler_type="r2dec",
)

print(results)
```

---

## Requirements

- Python 3.14+
- radare2 (required)
- r2ghidra/r2dec (optional decompilers)
- Ollama + decai plugin (optional for AI-assisted decompilation)
- See `pyproject.toml` for Python dependencies

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support the Project

If you find BannedFuncDetector useful, consider supporting its development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Attribution Required:**
- Author: **Marc Rivero** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/BannedFuncDetector](https://github.com/seifreed/BannedFuncDetector)

---

<p align="center">
  <sub>Made with dedication for the reverse engineering community</sub>
</p>
