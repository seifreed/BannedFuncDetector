# R2 Banned Functions Analyzer

This program analyzes Windows binaries (PE files) for banned or insecure functions, using radare2 as a backend and various decompilers, including AI-based decompilers.

## Features

- Detection of more than 200 insecure functions commonly banned in secure software development
- Support for multiple decompilers:
  - **default**: Default radare2 decompiler (pdc)
  - **r2ghidra**: Ghidra-based decompiler, offers good quality C code
  - **decai**: AI-based decompiler using the decai plugin with support for local LLM models via Ollama
- Analysis of individual binaries or entire directories
- Parallel processing for faster execution
- Generation of detailed reports in JSON format
- Customizable configuration

## Requirements

- Python 3.6+
- radare2 (latest version recommended)
- r2pipe (Python module)
- python-magic (to detect PE files)
- Optional decompilers:
  - r2ghidra (installable via r2pm)
  - decai (installable via r2pm)
  - Ollama (for decai)

## Usage


### Basic analysis of a binary:

```
./BannedFuncDetector.py -f binary.exe
```

### Detailed analysis with r2ghidra:

```
./BannedFuncDetector.py -f binary.exe --decompiler r2ghidra -v
```

### Analyzing a directory with the default decompiler:

```
./BannedFuncDetector.py -d malware_samples/ --decompiler default -o results
```

### Analysis with decai using Ollama:

```
./BannedFuncDetector.py -f binary.exe --decompiler decai -v
```


### Available options:

```
  -h, --help            Show this help message
  -f FILE, --file FILE  Path to the binary file to analyze
  -d DIRECTORY, --directory DIRECTORY
                        Path to the directory containing binaries to analyze
  -o OUTPUT, --output OUTPUT
                        Output directory for results
  --decompiler {default,r2ghidra,r2dec,decai}
                        Decompiler to use
  --force-decompiler    Force the use of the specified decompiler without interactive questions
  --parallel            Process files in parallel (only with --directory)
  --skip-banned         Skip searching for banned function names
  --skip-analysis       Skip decompilation analysis
  --check-requirements  Check system requirements before running
  -v, --verbose         Show detailed information during analysis
```

## Configuration

You can customize the configuration by creating a `config.json` file in the program directory. The configuration structure is as follows:

```json
{
    "decompiler": {
        "type": "decai",
        "options": {
            "decai": {
                "model": "qwen2:5b-coder",
                "advanced_options": {
                    "temperature": 0.1,
                    "context": "full",
                    "max_tokens": 4096
                }
            }
        }
    },
    "output_dir": "output",
    "max_workers": 10,
    "skip_small_functions": true,
    "small_function_threshold": 10,
    "r2pipe_threads": 10
}
```

## Project Structure

- `main.py`: Main entry point of the program
- `BannedFuncDetector.py`: Executable launcher
- `config.py`: Program configuration management
- `utils.py`: General utility functions
- `decompilers.py`: Functions related to decompilers
- `detector.py`: Functions to analyze binaries for banned functions


## License

This project is under the MIT License. See the `LICENSE` file for more details. 