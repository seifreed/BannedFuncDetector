#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Decompiler Orchestrator Module

Main decompilation dispatcher and orchestration functions.

This module is responsible for WHICH decompiler to use (orchestration):
    - decompile_function(): Main dispatcher using class instances
    - decompile_with_selected_decompiler(): Orchestration for multiple functions
    - search_banned_functions_in_code(): Search for banned functions in decompiled code

For availability checking, see availability.py.
For decompiler selection, see selector.py.
For HOW to try multiple decompilers (cascade logic), see cascade.py.
For decompiler registry and factory, see registry.py.

Author: Marc Rivero | @seifreed
"""

import logging
import re
from typing import Any

from bannedfuncdetector.infrastructure.config_repository import get_default_config
from bannedfuncdetector.domain.types import (
    DecompiledCode,
    DecompilationResultType,
    DetectionResult,
    FunctionInfo,
)
from bannedfuncdetector.constants import SMALL_FUNCTION_THRESHOLD
from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    DecompilationError,
    DecompilerType,
)
from bannedfuncdetector.infrastructure.decompilers.registry import DECOMPILER_INSTANCES
from bannedfuncdetector.infrastructure.decompilers.cascade import (
    _decompile_with_instance,
)
from bannedfuncdetector.infrastructure.decompilers.availability import (
    check_decompiler_available,
    get_available_decompiler,
)
from bannedfuncdetector.infrastructure.decompilers.selector import (
    select_decompiler,
    resolve_to_decompiler_type,
)
from bannedfuncdetector.domain.protocols import IR2Client, IConfigRepository
from bannedfuncdetector.domain.result import Result, Ok, Err, ok, err
from bannedfuncdetector.domain.banned_functions import BANNED_FUNCTIONS

# Configure logging
logger = logging.getLogger(__name__)


# =============================================================================
# DECOMPILATION DISPATCHER
# =============================================================================


def decompile_function(
    r2: IR2Client,
    function_name: str,
    decompiler_type: str | DecompilerType | None = None,
    config: IConfigRepository | None = None,
) -> DecompilationResultType:
    """
    Decompile a function using the specified decompiler.

    Uses a strategy dispatch pattern for clean decompiler selection.
    Delegates actual decompilation to the cascade module.

    Args:
        r2: r2pipe instance.
        function_name: Name of the function to decompile.
        decompiler_type: Type of decompiler to use.
        config: Configuration repository. Required in v2.0.
            Use create_config_from_file() or create_config_from_dict().

    Returns:
        DecompilationResultType: Ok(decompiled_code) on success,
                                 Err(error_message) on failure.

    .. deprecated::
        Passing None for config is deprecated and will raise an error in v2.0.
    """
    try:
        if config is None:
            import warnings
            warnings.warn(
                "Passing None for config is deprecated. Use create_config_from_file() or create_config_from_dict().",
                DeprecationWarning,
                stacklevel=2
            )
            config = get_default_config()
        decompiler_type_enum = resolve_to_decompiler_type(decompiler_type, config)

        # Get decompiler options from configuration
        decompiler_options = config["decompiler"].get("options", {})

        # Decompile using class instance (delegates to cascade module)
        return _decompile_with_instance(
            r2, function_name, decompiler_type_enum, decompiler_options
        )

    except (KeyError, AttributeError, TypeError) as e:
        return err(f"Configuration error decompiling {function_name}: {str(e)}")
    except (RuntimeError, ValueError) as e:
        # RuntimeError: r2pipe execution failure
        # ValueError: Invalid data or parsing errors
        logger.error(f"Runtime error decompiling {function_name}: {e}")
        return err(f"Runtime error decompiling {function_name}: {str(e)}")
    except DecompilationError as e:
        logger.error(f"Decompilation error for {function_name}: {e}")
        return err(f"Decompilation error: {str(e)}")


# =============================================================================
# BANNED FUNCTION SEARCH
# =============================================================================


def _build_detection_result(
    func_name: str, func_addr: Any, insecure_func: str
) -> DetectionResult:
    """Build a detection result dictionary."""
    return {
        "name": func_name,
        "address": func_addr if func_addr is not None else 0,
        "banned_functions": [insecure_func],
        "match_type": "decompilation",
    }


def _search_single_banned_function(
    decompiled_code: DecompiledCode,
    insecure_func: str,
    func_name: str,
) -> bool:
    """
    Search for a single banned function in decompiled code.

    Returns True if found, False otherwise.
    """
    try:
        pattern = r"\b" + re.escape(insecure_func) + r"\s*\("
        return bool(re.search(pattern, decompiled_code, re.IGNORECASE))
    except (re.error, TypeError, ValueError, AttributeError) as e:
        logger.debug(
            f"Error searching for pattern {insecure_func} in {func_name}: {e}"
        )
        return False


def _search_banned_in_decompiled(
    decompiled_code: DecompiledCode, func: FunctionInfo, verbose: bool
) -> Result[DetectionResult, str]:
    """
    Searches for banned functions in decompiled code.

    Args:
        decompiled_code: The decompiled source code.
        func: Function information dictionary.
        verbose: If True, shows detailed information.

    Returns:
        Result[DetectionResult, str]: Ok with detection info if a banned function
            is found, Err with message if no banned functions found.
    """
    func_name = func.get("name") or "unknown"
    func_addr = func.get("offset")

    for insecure_func in BANNED_FUNCTIONS:
        if _search_single_banned_function(decompiled_code, insecure_func, func_name):
            if verbose:
                logger.warning(
                    f"Unsafe function detected in {func_name}: {insecure_func}"
                )
            return ok(_build_detection_result(func_name, func_addr, insecure_func))

    return err(f"No banned functions found in decompiled code for {func_name}")


# =============================================================================
# LOGGING HELPERS
# =============================================================================


def _log_progress(
    current: int,
    total: int,
    func_name: str,
    success_count: int,
    error_count: int,
    log_interval: int,
    decompiler_type: str,
    verbose: bool,
) -> None:
    """
    Logs progress information during decompilation.

    Args:
        current: Current function index (0-based).
        total: Total number of functions.
        func_name: Name of the current function.
        success_count: Number of successful decompilations.
        error_count: Number of errors.
        log_interval: Interval for logging progress.
        decompiler_type: Type of decompiler being used.
        verbose: If True, shows detailed information.
    """
    if not verbose:
        return

    is_interval = current % log_interval == 0 or current == total - 1
    is_detailed_interval = current % 50 == 0

    if is_interval:
        percent = (current + 1) / total * 100
        logger.info(
            f"Progress: {current + 1}/{total} functions ({percent:.1f}%) - "
            f"Successes: {success_count}, Errors: {error_count}"
        )

    if is_detailed_interval:
        logger.info(f"Decompiling {func_name} with {decompiler_type}...")


def _log_final_summary(
    total_functions: int,
    success_count: int,
    error_count: int,
    detected_count: int,
    verbose: bool,
) -> None:
    """
    Logs the final summary of the decompilation analysis.

    Args:
        total_functions: Total number of functions analyzed.
        success_count: Number of successful decompilations.
        error_count: Number of errors.
        detected_count: Number of unsafe functions detected.
        verbose: If True, shows detailed information.
    """
    if not verbose:
        return

    logger.info("Decompilation analysis completed:")
    logger.info(f"   - Total functions analyzed: {total_functions}")
    logger.info(f"   - Successful decompilations: {success_count}")
    logger.info(f"   - Errors: {error_count}")
    logger.info(f"   - Unsafe functions detected: {detected_count}")


# =============================================================================
# FUNCTION PROCESSING
# =============================================================================


def _handle_decompilation_error(
    func_name: str,
    error: str,
    verbose: bool,
    log_interval: int,
    current_index: int,
) -> tuple[Result[DetectionResult, str], bool]:
    """Handle decompilation failure and return appropriate result."""
    if verbose and current_index % log_interval == 0:
        logger.error(f"Error: Decompilation of {func_name} failed: {error}")
    return err(f"Decompilation failed: {error}"), False


def _classify_exception(exception: Exception) -> str:
    """Classify an exception into a category for error messages."""
    if isinstance(exception, (KeyError, AttributeError, TypeError)):
        return "Data error"
    if isinstance(exception, (OSError, IOError)):
        return "I/O error"
    return "Runtime error"


def _handle_processing_exception(
    func_name: str,
    exception: Exception,
    verbose: bool,
    log_interval: int,
    current_index: int,
) -> tuple[Result[DetectionResult, str], bool]:
    """Handle exceptions during function processing."""
    error_type = _classify_exception(exception)

    if verbose and current_index % log_interval == 0:
        logger.error(f"{error_type} processing {func_name}: {exception}")
    return err(f"{error_type}: {str(exception)}"), False


def _process_single_function(
    r2: IR2Client,
    func: FunctionInfo,
    decompiler_type: str,
    verbose: bool,
    log_interval: int,
    current_index: int,
) -> tuple[Result[DetectionResult, str], bool]:
    """
    Processes a single function: decompiles it and searches for banned functions.

    Returns:
        Tuple of (Result[DetectionResult, str], success boolean).
    """
    func_name = func.get("name") or "unknown"

    try:
        decompile_result = decompile_function(r2, func_name, decompiler_type)

        if isinstance(decompile_result, Err):
            return _handle_decompilation_error(
                func_name, decompile_result.error, verbose, log_interval, current_index
            )

        decompiled = decompile_result.unwrap()
        if not decompiled:
            return err(f"Empty decompilation result for {func_name}"), False

        detection_result = _search_banned_in_decompiled(decompiled, func, verbose)
        return detection_result, True

    except (KeyError, AttributeError, RuntimeError, ValueError, TypeError) as e:
        return _handle_processing_exception(
            func_name, e, verbose, log_interval, current_index
        )


# =============================================================================
# MAIN DECOMPILATION FUNCTION
# =============================================================================


def _iterate_and_decompile_functions(
    r2: IR2Client,
    functions: list[FunctionInfo],
    decompiler_type_str: str,
    verbose: bool,
    small_function_threshold: int,
    skip_small_functions: bool,
) -> tuple[list[DetectionResult], int, int]:
    """
    Iterates through functions and decompiles them to search for banned functions.

    Returns:
        Tuple of (detected_functions list, success_count, error_count).
    """
    detected_functions_list: list[DetectionResult] = []
    total = len(functions)
    log_interval = max(1, total // 10)
    success_count, error_count = 0, 0

    for i, func in enumerate(functions):
        # Skip small functions if configured
        if skip_small_functions and func.get("size", 0) < small_function_threshold:
            continue

        _log_progress(
            i,
            total,
            func.get("name", "unknown"),
            success_count,
            error_count,
            log_interval,
            decompiler_type_str,
            verbose,
        )

        detection_result, success = _process_single_function(
            r2, func, decompiler_type_str, verbose, log_interval, i
        )

        # Update counters and append detection if found
        if success:
            if isinstance(detection_result, Ok):
                detected_functions_list.append(detection_result.unwrap())
            success_count += 1
        else:
            error_count += 1

    return detected_functions_list, success_count, error_count


def _log_decompilation_progress(
    functions: list[FunctionInfo],
    decompiler_type_str: str,
    verbose: bool,
) -> None:
    """
    Logs the start of decompilation progress.

    Args:
        functions: List of functions to decompile.
        decompiler_type_str: Type of decompiler being used.
        verbose: If True, shows detailed information.
    """
    if verbose:
        logger.info(
            f"Decompiling {len(functions)} functions with {decompiler_type_str}..."
        )


def _get_function_filtering_config(config: IConfigRepository) -> tuple[int, bool]:
    """Get function filtering configuration settings."""
    threshold = config.get("small_function_threshold", SMALL_FUNCTION_THRESHOLD)
    skip = config.get("skip_small_functions", True)
    return threshold, skip


def decompile_with_selected_decompiler(
    r2: IR2Client,
    functions: list[FunctionInfo],
    verbose: bool = True,
    decompiler_type: str | DecompilerType | None = None,
    config: IConfigRepository | None = None,
) -> list[DetectionResult]:
    """
    Uses the selected decompiler to decompile the binary and look for banned functions.

    Args:
        r2: r2pipe instance connected to the binary.
        functions: List of function dictionaries from radare2.
        verbose: If True, enables verbose logging output.
        decompiler_type: Type of decompiler to use.
        config: Configuration repository providing decompiler settings.
            Required in v2.0. Use create_config_from_file() or create_config_from_dict().

    Returns:
        List of detected banned functions.

    .. deprecated::
        Passing None for config is deprecated and will raise an error in v2.0.
    """
    if config is None:
        import warnings
        warnings.warn(
            "Passing None for config is deprecated. Use create_config_from_file() or create_config_from_dict().",
            DeprecationWarning,
            stacklevel=2
        )
        config = get_default_config()
    decompiler_type_str = select_decompiler(
        requested=decompiler_type, force=False, verbose=verbose, config=config
    )

    if not functions:
        if verbose:
            logger.warning("No functions found to decompile")
        return []

    _log_decompilation_progress(functions, decompiler_type_str, verbose)
    threshold, skip = _get_function_filtering_config(config)

    detected, success_count, error_count = _iterate_and_decompile_functions(
        r2, functions, decompiler_type_str, verbose, threshold, skip
    )

    _log_final_summary(
        len(functions), success_count, error_count, len(detected), verbose
    )
    return detected


# =============================================================================
# DECOMPILER ORCHESTRATOR CLASS (Protocol Implementation)
# =============================================================================


class DecompilerOrchestrator:
    """
    Implementation of the IDecompilerOrchestrator protocol.

    This class wraps the module-level orchestration functions to provide
    a protocol-compliant interface for decompilation coordination.

    The orchestrator handles:
    - Decompiler selection based on availability and preferences
    - Function decompilation with appropriate decompiler
    - Availability checking for different decompiler backends

    Example:
        >>> orchestrator = DecompilerOrchestrator()
        >>> decompiler = orchestrator.select_decompiler('r2ghidra')
        >>> if orchestrator.check_decompiler_available(decompiler):
        ...     result = orchestrator.decompile_function(r2, 'main', decompiler)
    """

    def __init__(self, config: IConfigRepository | None = None) -> None:
        """
        Initialize the DecompilerOrchestrator.

        Args:
            config: Configuration repository for decompiler settings.
                If None, uses the default configuration.
        """
        self._config = config

    def decompile_function(
        self,
        r2: IR2Client,
        function_name: str,
        decompiler_type: str | None = None,
        **options: Any
    ) -> "Result[str, str]":
        """
        Decompile a function using the configured decompiler.

        Args:
            r2: An active r2pipe client instance connected to the binary.
            function_name: Name or hex address of the function to decompile.
            decompiler_type: Optional decompiler to use. If None, uses default.
            **options: Additional decompiler-specific options.

        Returns:
            Result[str, str]: Ok containing the decompiled pseudocode on success,
                or Err containing an error message on failure.
        """
        return decompile_function(r2, function_name, decompiler_type, self._config)

    def select_decompiler(
        self,
        requested: str | None = None,
        force: bool = False
    ) -> str:
        """
        Select appropriate decompiler based on availability.

        Args:
            requested: The preferred decompiler type to use.
            force: If True, returns the requested decompiler without checking
                availability.

        Returns:
            str: The selected decompiler type name.
        """
        return select_decompiler(
            requested=requested, force=force, verbose=False, config=self._config
        )

    def check_decompiler_available(self, decompiler_type: str) -> bool:
        """
        Check if a decompiler is available.

        Args:
            decompiler_type: The decompiler type to check.

        Returns:
            bool: True if the decompiler is available, False otherwise.
        """
        return check_decompiler_available(decompiler_type)


def create_decompiler_orchestrator(
    config: IConfigRepository | None = None
) -> DecompilerOrchestrator:
    """Factory function for creating orchestrator instances.

    Creates a new orchestrator instance each time, enabling proper
    dependency injection and testing isolation.

    Args:
        config: Optional configuration repository. If None, uses global config.

    Returns:
        DecompilerOrchestrator: A new orchestrator instance.

    Example:
        >>> orchestrator = create_decompiler_orchestrator(config)
        >>> result = orchestrator.decompile_function(r2, 'main')
    """
    return DecompilerOrchestrator(config)


def get_default_decompiler_orchestrator(
    config: IConfigRepository | None = None
) -> DecompilerOrchestrator:
    """
    Get or create a DecompilerOrchestrator instance.

    .. deprecated:: 2.0
        Use :func:`create_decompiler_orchestrator` instead.
        This function now simply delegates to the factory function.

    Args:
        config: Optional configuration repository. If None, uses global config.

    Returns:
        DecompilerOrchestrator: A new orchestrator instance.
    """
    import warnings
    warnings.warn(
        "get_default_decompiler_orchestrator is deprecated. "
        "Use create_decompiler_orchestrator instead.",
        DeprecationWarning,
        stacklevel=2
    )
    return create_decompiler_orchestrator(config)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Dispatcher
    "decompile_function",
    "decompile_with_selected_decompiler",
    # Re-exported for backward compatibility (from availability.py)
    "check_decompiler_available",
    "get_available_decompiler",
    # Re-exported for backward compatibility (from selector.py)
    "select_decompiler",
    "resolve_to_decompiler_type",
    # Protocol implementation
    "DecompilerOrchestrator",
    "create_decompiler_orchestrator",
    # Deprecated (use create_decompiler_orchestrator instead)
    "get_default_decompiler_orchestrator",
]
