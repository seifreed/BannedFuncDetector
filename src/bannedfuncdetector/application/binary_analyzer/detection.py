#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Detection Helpers

This module provides detection-related functions for finding banned
function calls in decompiled code.

Author: Marc Rivero | @seifreed
"""
import logging
from typing import Any

from bannedfuncdetector.domain.protocols import IR2Client, IDecompilerOrchestrator
from bannedfuncdetector.domain.result import Result, Ok, Err, ok, err
from bannedfuncdetector.domain.types import DetectionResult, FunctionInfo
from bannedfuncdetector.domain.banned_functions import BANNED_FUNCTIONS

# Configure module logger
logger = logging.getLogger(__name__)


# =============================================================================
# Detection Helpers
# =============================================================================

def _find_banned_in_text(text: str, banned_functions: set[str]) -> list[str]:
    """
    Find banned function names contained in the provided text.

    Args:
        text: Text to scan.
        banned_functions: Set of banned function names.

    Returns:
        List of banned function names found in the text.
    """
    text_lower = text.lower()
    return [banned for banned in banned_functions if banned.lower() in text_lower]


def _create_detection_result(
    func_name: str,
    func_addr: Any,
    banned_functions: list[str],
    detection_method: str,
    decompiler: str | None = None
) -> DetectionResult:
    """
    Creates a standardized detection result dictionary.

    Args:
        func_name: Name of the function.
        func_addr: Address of the function.
        banned_functions: List of banned function names found.
        detection_method: Method used for detection.
        decompiler: Decompiler used (if applicable).

    Returns:
        Dict with function name, address, banned functions, and method.
    """
    result: DetectionResult = {
        "name": func_name,
        "address": hex(func_addr) if isinstance(func_addr, int) else str(func_addr),
        "banned_functions": banned_functions,
        "detection_method": detection_method
    }
    if decompiler is not None:
        result["decompiler"] = decompiler
    return result


def _validate_analysis_inputs(
    func: FunctionInfo | dict[str, Any] | None,
    banned_functions: set[str] | None
) -> Result[set[str], str]:
    """
    Validates and normalizes inputs for function analysis.

    Args:
        func: Function dictionary to validate.
        banned_functions: Set of banned function names.

    Returns:
        Result[set[str], str]: Ok with normalized banned_functions set,
            or Err with error message if func is invalid.
    """
    if func is None:
        return err("Function dictionary cannot be None")

    normalized = banned_functions or BANNED_FUNCTIONS
    return ok(set(normalized))


def _check_function_name_banned(
    func_name: str,
    func_addr: Any,
    banned_functions: set[str],
    verbose: bool = False
) -> Result[DetectionResult, str]:
    """
    Checks if function name matches any banned function.

    Args:
        func_name: Name of the function.
        func_addr: Address of the function.
        banned_functions: Set of banned function names.
        verbose: If True, enables verbose logging.

    Returns:
        Result[DetectionResult, str]: Ok with detection result if match found,
            Err with message if no match found.
    """
    detected_banned = _find_banned_in_text(func_name, banned_functions)

    if detected_banned:
        if verbose:
            logger.info(f"Insecure function detected by name: {func_name}")
        return ok(_create_detection_result(
            func_name, func_addr, detected_banned, "name"
        ))
    return err(f"No banned functions found in name: {func_name}")


# =============================================================================
# Decompile and Search Helper
# =============================================================================

def _decompile_and_search(
    r2: IR2Client,
    func_name: str,
    func_addr: Any,
    banned_functions: set[str],
    decompiler_type: str,
    verbose: bool = False,
    decompiler_orchestrator: IDecompilerOrchestrator | None = None
) -> Result[DetectionResult, str]:
    """
    Decompiles function and searches for banned calls in code.

    Args:
        r2: An r2pipe instance connected to the binary.
        func_name: Name of the function to decompile.
        func_addr: Address of the function.
        banned_functions: Set of banned function names.
        decompiler_type: Type of decompiler to use.
        verbose: If True, enables verbose logging.
        decompiler_orchestrator: IDecompilerOrchestrator instance for decompilation.
            If None, creates a default orchestrator from the infrastructure layer.
            For testing, provide a mock orchestrator.

    Returns:
        Result[DetectionResult, str]: Ok with detection result if banned calls found,
            Err with message if decompilation failed or no banned calls found.
    """
    # Use orchestrator if provided, otherwise get default from infrastructure
    if decompiler_orchestrator is None:
        from bannedfuncdetector.infrastructure.decompilers.orchestrator import (
            get_default_decompiler_orchestrator,
        )
        decompiler_orchestrator = get_default_decompiler_orchestrator()

    decompile_result = decompiler_orchestrator.decompile_function(
        r2, func_name, decompiler_type
    )

    if isinstance(decompile_result, Err):
        return err(f"Decompilation failed: {decompile_result.error}")

    decompiled_code = decompile_result.unwrap()
    if not decompiled_code:
        return err(f"Empty decompilation result for {func_name}")

    detected_banned = _find_banned_in_text(decompiled_code, banned_functions)

    if detected_banned:
        if verbose:
            logger.info(f"Insecure function detected in decompiled code: {func_name}")
        return ok(_create_detection_result(
            func_name, func_addr, detected_banned, "decompilation", decompiler_type
        ))
    return err(f"No banned functions found in decompiled code: {func_name}")


__all__ = [
    "_find_banned_in_text",
    "_create_detection_result",
    "_validate_analysis_inputs",
    "_check_function_name_banned",
    "_decompile_and_search",
]
