#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Parallel Analyzer

This module provides parallel processing logic for analyzing functions
within a binary using ThreadPoolExecutor.

Author: Marc Rivero | @seifreed
"""
import concurrent.futures
import logging
from typing import Any, Callable

from bannedfuncdetector.domain.protocols import IR2Client, IConfigRepository, IDecompilerOrchestrator
from bannedfuncdetector.infrastructure.config_repository import get_default_config
from bannedfuncdetector.domain.banned_functions import get_banned_functions_set
from bannedfuncdetector.domain.types import FunctionInfo, DetectionResult
from bannedfuncdetector.domain.config_types import AnalysisOptions

# Configure module logger
logger = logging.getLogger(__name__)


def _resolve_thread_count(
    worker_limit: int | None,
    max_items: int | None = None,
    config: IConfigRepository | None = None
) -> int:
    """
    Resolves the number of workers to use for parallel analysis.

    Args:
        worker_limit: Requested worker limit, or None to use config default
            or CPU count.
        max_items: Optional maximum number of items to process. If provided
            and worker_limit is None, the result will be capped at this value
            (useful for directory-level parallelism where thread count should
            not exceed file count).
        config: Configuration repository instance providing worker settings.
            If None, falls back to global config (deprecated pattern).

    Returns:
        The resolved number of workers.
    """
    import os

    if config is None:
        config = get_default_config()

    if worker_limit is not None:
        return worker_limit

    # Use config default if available, otherwise use CPU count
    default_workers = config.get("worker_limit", None)
    if default_workers is not None:
        resolved = default_workers
    else:
        # Fallback to 1 if CPU count detection fails (unlikely but defensive)
        resolved = os.cpu_count() or 1

    # Cap at max_items to avoid creating more threads than tasks
    # (prevents wasted resources when analyzing fewer files than available cores)
    if max_items is not None:
        resolved = min(resolved, max_items)

    return int(resolved)


def _analyze_functions_parallel(
    r2: IR2Client,
    functions: list[FunctionInfo],
    banned_functions_set: set[str],
    options: AnalysisOptions,
    function_analyzer: Callable[..., Any] | None = None
) -> list[DetectionResult]:
    """
    Analyzes functions in parallel using ThreadPoolExecutor.

    Args:
        r2: An r2pipe instance connected to the binary.
        functions: List of function dictionaries from radare2.
        banned_functions_set: Set of banned function names to detect.
        options: Analysis options containing decompiler_type, verbose, worker_limit, and config.
            The config field is required.
        function_analyzer: Optional custom function analyzer (for dependency injection).

    Returns:
        A list of detection results for functions containing banned calls.

    Raises:
        ValueError: If options.config is None.

    .. deprecated::
        The options.config field will be required in v2.0. Currently raises
        ValueError if None.
    """
    if options.config is None:
        raise ValueError(
            "options.config is required. Use create_config_from_file() or "
            "create_config_from_dict() to create a configuration."
        )
    config = options.config

    # Require function_analyzer to be provided - breaks circular dependency
    if function_analyzer is None:
        raise ValueError(
            "function_analyzer must be provided. "
            "Pass analyze_function from binary_analyzer when calling this function."
        )

    max_workers = _resolve_thread_count(options.worker_limit, config=config)
    results: list[DetectionResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(
                function_analyzer, r2, func, banned_functions_set,
                options.decompiler_type, options.verbose, config
            )
            for func in functions
        ]

        results = _process_parallel_results(futures, options.verbose)

    return results


def _process_parallel_results(
    futures: list[concurrent.futures.Future[Any]],
    verbose: bool = False
) -> list[DetectionResult]:
    """
    Processes results from parallel function analysis.

    Args:
        futures: List of Future objects from ThreadPoolExecutor.
        verbose: If True, enables verbose logging output.

    Returns:
        List of detection results (Ok results from futures).
    """
    results: list[DetectionResult] = []

    # Process futures as they complete (not in submission order) for better responsiveness
    for future in concurrent.futures.as_completed(futures):
        try:
            result = future.result()
            # Result type pattern: only successful detections (Ok) are collected
            # Functions without banned calls return Err and are filtered out here
            if result.is_ok():
                detection = result.unwrap()
                results.append(detection)
                if verbose:
                    logger.info(
                        f"Insecure function found: {detection['name']} at {detection['address']}"
                    )
        except (RuntimeError, ValueError) as e:
            # RuntimeError: r2pipe execution failure or thread issues
            # ValueError: Invalid data or parsing errors
            if verbose:
                logger.error(f"Runtime error analyzing a function: {str(e)}")
        except (KeyError, AttributeError, TypeError) as e:
            # Data structure or type errors during analysis
            if verbose:
                logger.error(f"Data error analyzing a function: {str(e)}")
        except (OSError, IOError) as e:
            # I/O errors during analysis
            if verbose:
                logger.error(f"I/O error analyzing a function: {str(e)}")
        except concurrent.futures.CancelledError:
            # Task was cancelled - can happen during shutdown
            if verbose:
                logger.warning("Function analysis task was cancelled")

    return results


def _run_parallel_detection(
    r2: IR2Client,
    functions: list[FunctionInfo],
    options: AnalysisOptions,
    function_analyzer: Callable[..., Any] | None = None,
    banned_functions_provider: Callable[..., set[str]] | None = None,
    decompiler_orchestrator: IDecompilerOrchestrator | None = None
) -> list[DetectionResult]:
    """
    Runs ThreadPoolExecutor-based banned function detection.

    This is the main entry point for parallel detection, used by analyze_binary().

    Args:
        r2: An r2pipe instance connected to the binary.
        functions: List of function dictionaries from radare2.
        options: Analysis options containing decompiler_type, verbose, worker_limit, and config.
            The config field is required.
        function_analyzer: The function analyzer callable (required - breaks circular dependency).
            This should be analyze_function from binary_analyzer.
        banned_functions_provider: Optional custom banned functions provider
            (for dependency injection).
        decompiler_orchestrator: IDecompilerOrchestrator instance for checking
            decompiler availability. If None, creates a default orchestrator from
            the infrastructure layer. For testing, provide a mock orchestrator.

    Returns:
        List of detection results.

    Raises:
        ValueError: If function_analyzer is not provided, or if options.config is None.

    .. deprecated::
        The options.config field will be required in v2.0. Currently raises
        ValueError if None.
    """
    if options.config is None:
        raise ValueError(
            "options.config is required. Use create_config_from_file() or "
            "create_config_from_dict() to create a configuration."
        )
    config = options.config

    # Use provided provider or the canonical implementation from banned_functions
    provider = banned_functions_provider or get_banned_functions_set
    banned_functions_set = provider(config)

    # Log decompiler if verbose and available
    if options.verbose:
        # Use orchestrator if provided, otherwise create from infrastructure
        if decompiler_orchestrator is None:
            from bannedfuncdetector.infrastructure.decompilers.orchestrator import (
                create_decompiler_orchestrator,
            )
            decompiler_orchestrator = create_decompiler_orchestrator()
        if decompiler_orchestrator.check_decompiler_available(options.decompiler_type):
            logger.info(f"Using decompiler: {options.decompiler_type}")

    return _analyze_functions_parallel(
        r2, functions, banned_functions_set, options,
        function_analyzer=function_analyzer
    )


__all__: list[str] = []
