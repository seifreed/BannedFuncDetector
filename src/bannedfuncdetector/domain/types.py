#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Type aliases for common complex types used throughout the codebase.

This module defines type aliases for complex types to improve readability
and maintainability of function signatures across the codebase.

Author: Marc Rivero | @seifreed
"""
from typing import Any, Callable, TypeAlias, TypedDict

from .result import Result


# =============================================================================
# TypedDict definitions for structured data
# =============================================================================


class DetectionResult(TypedDict, total=False):
    """
    Detection result for a banned function.

    Required fields:
        name: Name of the function containing banned calls.
        address: Memory address of the function (int or hex string).
        banned_functions: List of banned function names found.

    Optional fields:
        detection_method: Method used for detection (e.g., "name", "name_match", "decompilation").
        match_type: Type of match (e.g., "import", "string_reference", "decompilation").
        decompiler: Which decompiler was used (e.g., "r2ghidra", "r2dec").
        size: Size of the function in bytes.
        type: Category of the banned function (e.g., "memory", "string").
        string: The string reference that was found (for string_reference match_type).
    """

    name: str
    address: int | str
    banned_functions: list[str]
    detection_method: str
    match_type: str
    decompiler: str
    size: int
    type: str
    string: str


class FunctionInfo(TypedDict, total=False):
    """
    Function information from binary analysis.

    Required fields:
        name: Name of the function.
        offset: Memory offset/address of the function.

    Optional fields:
        size: Size of the function in bytes.
    """

    name: str
    offset: int
    size: int


class AnalysisReport(TypedDict, total=False):
    """
    Complete analysis report for a binary.

    Required fields:
        total_functions: Total number of functions found in the binary.
        unsafe_functions: Number of functions containing banned calls.
        results: List of detection results for banned functions.

    Optional fields:
        binary: Path to the analyzed binary file.
    """

    binary: str
    total_functions: int
    unsafe_functions: int
    results: list[DetectionResult]

# R2 types
R2JsonOutput: TypeAlias = dict[str, Any] | list[Any] | None
R2Command: TypeAlias = str

# Decompiler types
DecompiledCode: TypeAlias = str
DecompilerConfig: TypeAlias = dict[str, Any]

# Result type aliases
DetectionResultType: TypeAlias = Result[DetectionResult, str]
AnalysisResultType: TypeAlias = Result[AnalysisReport, str]
DecompilationResultType: TypeAlias = Result[DecompiledCode, str]

# Callable types
FunctionAnalyzer: TypeAlias = Callable[..., DetectionResultType]
ParallelExecutor: TypeAlias = Callable[..., list[DetectionResult]]

__all__ = [
    "DetectionResult",
    "FunctionInfo",
    "AnalysisReport",
    "R2JsonOutput",
    "R2Command",
    "DecompiledCode",
    "DecompilerConfig",
    "DetectionResultType",
    "AnalysisResultType",
    "DecompilationResultType",
    "FunctionAnalyzer",
    "ParallelExecutor",
]
