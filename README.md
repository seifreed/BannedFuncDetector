<p align="center">
  <img src="https://img.shields.io/badge/BannedFuncDetector-RE%20Security-blue?style=for-the-badge" alt="BannedFuncDetector">
</p>

<h1 align="center">BannedFuncDetector</h1>

<p align="center">
  <strong>Find insecure function calls a symbol-table grep can't see — including statically-linked and inlined ones — via radare2 decompilation</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/bannedfuncdetector/"><img src="https://img.shields.io/pypi/v/bannedfuncdetector?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/bannedfuncdetector/"><img src="https://img.shields.io/pypi/pyversions/bannedfuncdetector?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/BannedFuncDetector/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/BannedFuncDetector/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/BannedFuncDetector/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <img src="https://img.shields.io/badge/coverage-100%25-brightgreen?style=flat-square" alt="Coverage">
</p>

<p align="center">
  <a href="https://github.com/seifreed/BannedFuncDetector/stargazers"><img src="https://img.shields.io/github/stars/seifreed/BannedFuncDetector?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/BannedFuncDetector/issues"><img src="https://img.shields.io/github/issues/seifreed/BannedFuncDetector?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**BannedFuncDetector** scans binaries for banned/insecure function usage (the Microsoft banned API set: `strcpy`, `sprintf`, `gets`, …).

### Why not just `rabin2 -i | grep strcpy`?

For a dynamically-linked binary, that one-liner *is* equivalent to the name check here — and you should use it. BannedFuncDetector exists for the case the import-table grep misses:

- **Statically-linked and inlined calls.** A `strcpy` compiled into the binary (static linking, LTO, inlined libc) never appears in the import table, so `rabin2 -i | grep` finds nothing. BannedFuncDetector walks the decompiled code (`pdc`/`pdg`/`pdd`) and catches it at the call site.
- **A curated banned-API list** so you don't grep one name at a time.
- **Batch + structured output:** directory scans, parallel workers, per-target JSON reports for pipelines.

If your target is dynamically linked and you just want a yes/no on imports, the grep is faster and has zero dependencies. Reach for this tool when "is it in the imports?" isn't the same question as "is it in the code?".

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

## AI decompilation (decai)

The `decai` decompiler uses an AI backend through the radare2 `decai` plugin.
The backend is driven entirely by the `decompiler.options.decai` section of
`config.json`, so you can switch providers without touching code.

**Default backend: OpenCode Zen — free `big-pickle` model.** Zen exposes free
models (`big-pickle`, `deepseek-v4-flash-free`, …) over an OpenAI-compatible
endpoint, so `decai` reaches them with `api=openai`. The models are free of
charge but Zen still requires a **free** key (there is no anonymous access):

```bash
# 1. Sign up and copy your key at https://opencode.ai/auth
# 2. Store it in decai's "openai" slot (Zen is OpenAI-compatible):
r2 -qc 'decai -K' /bin/ls        # add a line:  openai=<your-zen-key>
#    or export it:  export OPENAI_API_KEY=<your-zen-key>
```

> ⚠️ **Privacy note for malware analysis.** Any cloud backend uploads the
> disassembly of the analyzed sample to a third party. For sensitive or
> classified samples, use the local Ollama backend (below) so nothing leaves
> the host — it is the only key-free, fully private option.

**Switch backend** by editing `config.json` → `decompiler.options.decai`:

```jsonc
// Local / offline (private, no key) — requires Ollama + a local model:
"decai": { "api": "ollama", "model": "qwen2.5-coder:7b",
           "host": "http://localhost", "port": 11434 }

// OpenCode Zen (default) — free models, free key:
"decai": { "api": "openai", "model": "big-pickle", "host": "https://opencode.ai/zen" }
```

`api`, `model` and the `host`(+`port`)-derived base URL are applied to the
plugin automatically when `--decompiler decai` runs (decai builds the request
URL as `host` + `/v1/chat/completions`). Providers supported by decai:
`openai` (incl. OpenCode Zen), `ollama`, `ollamacloud`, `gemini`, `anthropic`,
`claude`, `mistral`, `xai`, `deepseek`, `lmstudio`.

> If you see `ABI mismatch` warnings for `r2ai.dylib`, rebuild the backend
> plugin for your radare2 version: `r2pm -ci r2ai`.

---

## Python Library

Both helpers return a `Result`: `Ok(outcome)` on success or `Err(failure)` on
error — check with `.is_ok()` and read the value with `.unwrap()`.

### Basic Usage

```python
from bannedfuncdetector.bannedfunc import analyze_file

result = analyze_file(
    "/path/to/binary",
    decompiler_type="r2ghidra",
    output_dir="output",
)

if result.is_ok():
    outcome = result.unwrap()
    for finding in outcome.report.detected_functions:
        print(finding.name, finding.banned_calls)
else:
    print("Analysis failed:", result.error)
```

### Directory Analysis

```python
from bannedfuncdetector.bannedfunc import analyze_directory

result = analyze_directory(
    "/path/to/binaries",
    output_dir="output",
    decompiler_type="r2dec",
    parallel=True,
)

if result.is_ok():
    summary = result.unwrap().summary
    print(f"{summary.analyzed_files}/{summary.total_files} files analyzed")
```

---

## Requirements

- Python 3.13+ (tested on 3.13 y 3.14)
- radare2 (required)
- r2ghidra/r2dec (optional decompilers)
- decai plugin (optional, for AI-assisted decompilation — see "AI decompilation" above)
- See `pyproject.toml` for Python dependencies

---

## Support the Project

If you find BannedFuncDetector useful, consider supporting its development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

<p align="center">
  <sub>Made with dedication for the reverse engineering community</sub>
</p>


