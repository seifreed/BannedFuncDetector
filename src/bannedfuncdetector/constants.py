"""
Constants for BannedFuncDetector.
Author: Marc Rivero | @seifreed
"""

# Python version requirements
MIN_PYTHON_VERSION = (3, 14)

# Analysis thresholds
# Minimum 10 characters to filter out empty/error decompilation results
MIN_DECOMPILED_CODE_LENGTH = 10
# Minimum 30 characters required for meaningful code analysis (filters trivial stubs)
MIN_VALID_CODE_LENGTH = 30
# Functions under 20 bytes are typically compiler-generated stubs (e.g., PLT entries, thunks)
# Skipping them reduces false positives and improves performance
SMALL_FUNCTION_THRESHOLD = 20

# File detection
# Read 8 bytes: sufficient for PE (2), ELF (4), and Mach-O (4) signature detection
PE_MAGIC_BYTES_SIZE = 8
PE_SIGNATURE = b"MZ"  # DOS signature for PE files
ELF_SIGNATURE = b"\x7fELF"  # ELF signature

# Decompiler settings
DEFAULT_DECOMPILER = "default"
# 30 second timeout prevents hanging on complex/obfuscated functions
# Balance between thorough analysis and reasonable execution time
DECOMPILER_TIMEOUT = 30

# Analysis settings
# Default 4 workers provides good parallelism without overwhelming system resources
# Optimal for most modern multi-core CPUs (can be overridden via config)
DEFAULT_MAX_WORKERS = 4
DEFAULT_OUTPUT_DIR = "output"

# Logging
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
