"""
Decompiler implementations and orchestration.

This package provides decompiler classes and orchestration functions for
decompiling binary functions using various radare2 plugins.

Modules:
    - base_decompiler: Base class, enums, exceptions, configuration, and utilities
    - r2ghidra_decompiler: R2Ghidra decompiler implementation
    - r2dec_decompiler: R2Dec decompiler implementation
    - decai_decompiler: DecAI (AI-based) decompiler implementation
    - default_decompiler: Default radare2 decompiler implementation
    - registry: Decompiler instance registry and factory function
    - cascade: Decompiler cascade/fallback logic
    - availability: Decompiler availability checking
    - selector: Decompiler selection logic
    - orchestrator: Decompilation dispatcher and main orchestration
"""

# Base module exports (enums, exceptions, configuration, utilities)
from .base_decompiler import (
    # Enum
    DecompilerType,
    # Exceptions
    DecompilationError,
    DecompilerNotAvailableError,
    FunctionNotFoundError,
    # Configuration
    DECOMPILER_CONFIG,
    DECAI_PREFERRED_MODELS,
    # Constants
    ERROR_SKIP_PATTERNS,
    # Base class
    BaseR2Decompiler,
    # Utility functions
    clean_decompiled_output,
    is_small_function,
    is_valid_result,
    try_decompile_with_command,
    get_function_info,
    # Availability check functions
    check_decompiler_plugin_available,
)

# Decompiler class exports
from .r2ghidra_decompiler import R2GhidraDecompiler
from .r2dec_decompiler import R2DecDecompiler
from .decai_decompiler import DecAIDecompiler, decompile_with_decai
from .default_decompiler import DefaultDecompiler

# Registry exports
from .registry import (
    DecompilerInstance,
    DECOMPILER_INSTANCES,
    create_decompiler,
)

# Cascade exports
from .cascade import (
    DECOMPILER_CASCADE_ORDER,
)

# Availability exports
from .availability import (
    check_decompiler_available,
    get_available_decompiler,
)

# Selector exports
from .selector import (
    select_decompiler,
    resolve_to_decompiler_type,
)

# Orchestrator exports
from .orchestrator import (
    decompile_function,
    decompile_with_selected_decompiler,
    DecompilerOrchestrator,
    create_decompiler_orchestrator,
    get_default_decompiler_orchestrator,
)

__all__ = [
    # Enum
    "DecompilerType",
    # Exceptions
    "DecompilationError",
    "DecompilerNotAvailableError",
    "FunctionNotFoundError",
    # Configuration
    "DECOMPILER_CONFIG",
    "DECAI_PREFERRED_MODELS",
    # Constants
    "ERROR_SKIP_PATTERNS",
    # Base class
    "BaseR2Decompiler",
    # Decompiler classes
    "R2GhidraDecompiler",
    "R2DecDecompiler",
    "DecAIDecompiler",
    "DefaultDecompiler",
    # Registry exports
    "DecompilerInstance",
    "DECOMPILER_INSTANCES",
    "create_decompiler",
    # Cascade exports
    "DECOMPILER_CASCADE_ORDER",
    # Utility functions
    "clean_decompiled_output",
    "is_small_function",
    "is_valid_result",
    "try_decompile_with_command",
    "get_function_info",
    # Decompilation function (decai has complex logic, kept as function)
    "decompile_with_decai",
    # Availability check functions
    "check_decompiler_plugin_available",
    "check_decompiler_available",
    "get_available_decompiler",
    # Selector functions
    "select_decompiler",
    "resolve_to_decompiler_type",
    # Orchestrator functions
    "decompile_function",
    "decompile_with_selected_decompiler",
    # Protocol implementation
    "DecompilerOrchestrator",
    "create_decompiler_orchestrator",
    # Deprecated (use create_decompiler_orchestrator instead)
    "get_default_decompiler_orchestrator",
]
