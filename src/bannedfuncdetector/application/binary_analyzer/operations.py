#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Binary Operations

This module provides binary file operations including opening binaries
with r2pipe, extracting functions, and setting up binary analysis.

Author: Marc Rivero | @seifreed
"""
import os
import logging
from typing import Any, Callable

from bannedfuncdetector.domain.protocols import IR2Client, IConfigRepository, IDecompilerOrchestrator
from bannedfuncdetector.domain.result import Result, Ok, Err, ok, err
from bannedfuncdetector.domain.types import FunctionInfo, DetectionResult
from bannedfuncdetector.domain.config_types import (
    AnalysisOptions,
    BinaryAnalysisOptions,
    ResolvedAnalysisParams,
)
from bannedfuncdetector.infrastructure import handle_errors
from bannedfuncdetector.infrastructure.config_repository import get_default_config
from bannedfuncdetector.analyzer_exceptions import (
    BinaryNotFoundError,
    DecompilerNotAvailableError,
)

# Configure module logger
logger = logging.getLogger(__name__)


# =============================================================================
# Input Validation Functions
# =============================================================================

def _validate_binary_input(binary_path: str) -> None:
    """
    Validates that the binary file exists.

    Args:
        binary_path: Path to the binary file to validate.

    Raises:
        BinaryNotFoundError: If the specified binary file does not exist.
    """
    if not os.path.exists(binary_path):
        error_msg = f"The file {binary_path} does not exist."
        logger.error(error_msg)
        raise BinaryNotFoundError(error_msg)


# =============================================================================
# Binary Operations
# =============================================================================

def _open_binary_with_r2(
    binary_path: str,
    verbose: bool = False,
    config: IConfigRepository | None = None,
    r2_factory: Callable[[str], IR2Client] | None = None
) -> IR2Client:
    """
    Opens a binary file with r2pipe and performs initial analysis.

    Args:
        binary_path: Path to the binary file to open.
        verbose: If True, enables verbose logging output.
        config: Configuration repository instance providing r2pipe settings.
            Required parameter - will raise ValueError if None.
        r2_factory: Factory callable for creating IR2Client instances.
            If None, uses the default factory from bannedfuncdetector.factories.

    Returns:
        An r2pipe instance connected to the binary.

    Raises:
        ValueError: If config is None.

    .. deprecated::
        The config parameter will be required in v2.0. Currently raises
        ValueError if None.
    """
    if config is None:
        raise ValueError(
            "config parameter is required. Use create_config_from_file() or "
            "create_config_from_dict() to create a configuration."
        )
    # Default 10 threads for r2pipe command processing (balance between performance and resource usage)
    r2pipe_threads = config.get("r2pipe_threads", 10)

    if r2pipe_threads > 0:
        os.environ["R2PIPE_THREADS"] = str(r2pipe_threads)

    if verbose:
        logger.info(f"Opening {binary_path} with r2pipe...")

    # Use provided factory or get default from factories module
    if r2_factory is None:
        from bannedfuncdetector.factories import create_r2_client
        r2_factory = create_r2_client

    r2 = r2_factory(binary_path)

    if verbose:
        logger.info("Analyzing the binary...")
    # aaa performs automatic analysis: analyze all, analyze function calls, analyze all again
    r2.cmd("aaa")

    return r2


@handle_errors("extracting functions from binary")
def _extract_functions(r2: IR2Client, verbose: bool = False) -> Result[list[FunctionInfo], str]:
    """
    Extracts the list of functions from an analyzed binary.

    Args:
        r2: An r2pipe instance connected to the binary.
        verbose: If True, enables verbose logging output.

    Returns:
        Result[list[FunctionInfo], str]: Ok with list of function dictionaries,
            or Err with error message if no functions found.

    Note:
        This function uses @handle_errors decorator to catch common exceptions
        (KeyError, AttributeError, TypeError, RuntimeError, ValueError, OSError, IOError)
        and convert them to Result.Err for graceful error handling.
    """
    if verbose:
        logger.info("Getting function list...")

    functions = r2.cmdj("aflj")

    if not functions:
        error_msg = "No functions found in the binary."
        if verbose:
            logger.warning(error_msg)
        return err(error_msg)

    if verbose:
        logger.info(f"Found {len(functions)} functions.")

    # The functions from r2 aflj command match the FunctionInfo structure
    # Cast is safe as aflj returns list of function dicts matching FunctionInfo
    function_list: list[FunctionInfo] = functions
    return ok(function_list)


def _parse_result_address(address: Any) -> int:
    """
    Parse an address field from a result entry into an int.

    Args:
        address: Address value (may be string or int).

    Returns:
        Integer representation of the address.
    """
    if isinstance(address, str):
        return int(address, 16)
    if isinstance(address, int):
        return address
    return 0


# =============================================================================
# Analysis Setup Functions
# =============================================================================

def _validate_and_resolve_params(
    binary_path: str,
    options: BinaryAnalysisOptions | None,
    output_dir: str | None,
    decompiler_type: str | None,
    verbose: bool,
    worker_limit: int | None,
    config: IConfigRepository | None,
    decompiler_orchestrator: IDecompilerOrchestrator | None,
) -> Result[ResolvedAnalysisParams, str]:
    """
    Validate inputs and resolve parameters from options or kwargs.

    Handles both the options object and individual keyword arguments for
    backward compatibility. Validates the binary path and resolves the
    decompiler to use.

    Args:
        binary_path: Path to the binary file to analyze.
        options: BinaryAnalysisOptions containing analysis configuration.
        output_dir: Directory for JSON output (None to skip saving).
        decompiler_type: Decompiler type to use.
        verbose: Enable detailed logging.
        worker_limit: Max concurrent workers.
        config: Configuration repository instance.
        decompiler_orchestrator: Optional decompiler orchestrator for DI.

    Returns:
        Result[ResolvedAnalysisParams, str]: Ok with resolved parameters,
            or Err with error message if validation failed.
    """
    import warnings

    # Declare resolved_config with explicit type annotation
    resolved_config: IConfigRepository

    # Resolve parameters from options or individual kwargs
    if options is not None:
        resolved_output_dir = options.output_dir
        resolved_decompiler_type = options.decompiler_type
        resolved_verbose = options.verbose
        resolved_worker_limit = options.worker_limit
        if options.config is None:
            warnings.warn(
                "Passing None for config is deprecated. "
                "Use create_config_from_file() or create_config_from_dict().",
                DeprecationWarning,
                stacklevel=3
            )
            resolved_config = get_default_config()
        else:
            resolved_config = options.config
    else:
        resolved_output_dir = output_dir
        resolved_decompiler_type = decompiler_type
        resolved_verbose = verbose
        resolved_worker_limit = worker_limit
        if config is None:
            warnings.warn(
                "Passing None for config is deprecated. "
                "Use create_config_from_file() or create_config_from_dict().",
                DeprecationWarning,
                stacklevel=3
            )
            resolved_config = get_default_config()
        else:
            resolved_config = config

    # Validate binary path and resolve decompiler
    try:
        _validate_binary_input(binary_path)
        # Use orchestrator if provided, otherwise get default from infrastructure
        if decompiler_orchestrator is None:
            from bannedfuncdetector.infrastructure.decompilers.orchestrator import (
                get_default_decompiler_orchestrator,
            )
            decompiler_orchestrator = get_default_decompiler_orchestrator()
        final_decompiler = decompiler_orchestrator.select_decompiler(
            requested=resolved_decompiler_type, force=False
        )
    except BinaryNotFoundError as e:
        return err(f"Binary not found: {str(e)}")
    except DecompilerNotAvailableError as e:
        return err(f"Decompiler not available: {str(e)}")

    return ok(ResolvedAnalysisParams(
        output_dir=resolved_output_dir,
        decompiler_type=final_decompiler,
        verbose=resolved_verbose,
        worker_limit=resolved_worker_limit,
        config=resolved_config,
    ))


def _setup_binary_analysis(
    binary_path: str,
    params: ResolvedAnalysisParams,
) -> Result[tuple[IR2Client, list[FunctionInfo]], str]:
    """
    Open binary with r2 and extract functions.

    Opens the binary file using radare2, performs analysis, and extracts
    the list of functions.

    Args:
        binary_path: Path to the binary file to analyze.
        params: Resolved analysis parameters.

    Returns:
        Result[tuple[IR2Client, list[FunctionInfo]], str]: Ok with tuple of
            r2 client and functions list, or Err with error message.
    """
    try:
        r2 = _open_binary_with_r2(binary_path, params.verbose, params.config)
        functions_result = _extract_functions(r2, params.verbose)

        if isinstance(functions_result, Err):
            r2.quit()
            return err(f"No functions found in binary: {binary_path}")

        return ok((r2, functions_result.unwrap()))

    except (OSError, IOError) as e:
        logger.error(f"I/O error opening binary {binary_path}: {str(e)}")
        return err(f"I/O error: {str(e)}")
    except ValueError as e:
        logger.error(f"Configuration error for binary {binary_path}: {str(e)}")
        return err(f"Configuration error: {str(e)}")
    except RuntimeError as e:
        logger.error(f"Runtime error opening binary {binary_path}: {str(e)}")
        return err(f"Runtime error: {str(e)}")


def _execute_detection(
    r2: IR2Client,
    functions: list[FunctionInfo],
    params: ResolvedAnalysisParams,
    parallel_executor: Callable[..., list[DetectionResult]] | None,
    function_analyzer: Callable[..., Result[DetectionResult, str]],
) -> list[DetectionResult]:
    """
    Run detection on all functions using parallel or sequential execution.

    Executes banned function detection on the extracted functions using
    either a custom parallel executor or the default parallel detection.

    Args:
        r2: An r2pipe instance connected to the binary.
        functions: List of functions to analyze.
        params: Resolved analysis parameters.
        parallel_executor: Optional custom parallel executor for DI.
        function_analyzer: Function analyzer callable (analyze_function).

    Returns:
        List of detection results for functions with banned calls.
    """
    from bannedfuncdetector.application.parallel_analyzer import _run_parallel_detection

    if parallel_executor is not None:
        return parallel_executor(
            r2, functions, params.decompiler_type, params.verbose,
            params.worker_limit, params.config
        )

    analysis_opts = AnalysisOptions(
        verbose=params.verbose,
        worker_limit=params.worker_limit,
        decompiler_type=params.decompiler_type,
        config=params.config,
    )

    return _run_parallel_detection(
        r2, functions, analysis_opts,
        function_analyzer=function_analyzer
    )


__all__ = [
    "_validate_binary_input",
    "_open_binary_with_r2",
    "_extract_functions",
    "_parse_result_address",
    "_validate_and_resolve_params",
    "_setup_binary_analysis",
    "_execute_detection",
]
