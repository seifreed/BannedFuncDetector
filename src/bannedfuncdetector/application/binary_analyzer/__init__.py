#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Binary Analyzer Package

This package provides the core binary analysis logic for detecting
banned/insecure functions in binary files.

Public API:
    - analyze_binary: Analyze a binary file for banned functions
    - analyze_function: Analyze a single function for banned calls
    - R2BinaryAnalyzer: Protocol-compliant binary analyzer class

Author: Marc Rivero | @seifreed
"""

# Public API exports
from .core import (
    analyze_binary,
    analyze_function,
    R2BinaryAnalyzer,
)

# Operations exports (for backward compatibility)
from .operations import (
    _validate_binary_input,
    _open_binary_with_r2,
    _extract_functions,
    _parse_result_address,
    _validate_and_resolve_params,
    _setup_binary_analysis,
    _execute_detection,
)

# Detection exports (for backward compatibility)
from .detection import (
    _find_banned_in_text,
    _create_detection_result,
    _validate_analysis_inputs,
    _check_function_name_banned,
    _decompile_and_search,
)

# Reporting exports (for backward compatibility)
from .reporting import (
    _create_analysis_report,
    _save_analysis_results,
)

__all__ = [
    # Public API
    "analyze_binary",
    "analyze_function",
    "R2BinaryAnalyzer",
    # Internal functions (exported for backward compatibility)
    "_validate_binary_input",
    "_open_binary_with_r2",
    "_extract_functions",
    "_parse_result_address",
    "_validate_and_resolve_params",
    "_setup_binary_analysis",
    "_execute_detection",
    "_find_banned_in_text",
    "_create_detection_result",
    "_validate_analysis_inputs",
    "_check_function_name_banned",
    "_decompile_and_search",
    "_create_analysis_report",
    "_save_analysis_results",
]
