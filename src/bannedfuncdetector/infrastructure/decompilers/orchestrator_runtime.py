"""Runtime helpers for multi-function decompiler orchestration."""

from __future__ import annotations

import logging

from bannedfuncdetector.constants import SMALL_FUNCTION_THRESHOLD
from bannedfuncdetector.domain import BannedFunction, FunctionDescriptor
from bannedfuncdetector.domain.protocols import IConfigRepository, IR2Client
from bannedfuncdetector.domain.result import Err, Ok, Result, err
from collections.abc import Callable
from bannedfuncdetector.domain.types import DecompilationResultType

from .orchestrator_progress import (
    _handle_decompilation_error,
    _handle_processing_exception,
    _log_progress,
)
from .orchestrator_search import _search_banned_in_decompiled

logger = logging.getLogger(__name__)


def _process_single_function(
    r2: IR2Client,
    func: FunctionDescriptor,
    decompiler_type: str,
    verbose: bool,
    log_interval: int,
    current_index: int,
    config: IConfigRepository,
    decompile_function_impl: Callable[..., DecompilationResultType],
) -> tuple[Result[BannedFunction, str], bool]:
    """Decompile one function and search for banned calls."""
    func_name = func.name
    try:
        decompile_result = decompile_function_impl(
            r2,
            func_name,
            decompiler_type,
            config=config,
        )

        if isinstance(decompile_result, Err):
            return _handle_decompilation_error(
                func_name, decompile_result.error, verbose, log_interval, current_index
            )

        decompiled = decompile_result.unwrap()
        if not decompiled:
            return err(f"Empty decompilation result for {func_name}"), False

        detection_result = _search_banned_in_decompiled(decompiled, func, verbose)
        return detection_result, True
    except (KeyError, AttributeError, RuntimeError, ValueError, TypeError) as exc:
        return _handle_processing_exception(
            func_name, exc, verbose, log_interval, current_index
        )


def _iterate_and_decompile_functions(
    r2: IR2Client,
    functions: list[FunctionDescriptor],
    decompiler_type_str: str,
    verbose: bool,
    small_function_threshold: int,
    skip_small_functions: bool,
    config: IConfigRepository,
    decompile_function_impl: Callable[..., DecompilationResultType],
) -> tuple[list[BannedFunction], int, int]:
    """Iterate functions, decompile them, and collect banned-call detections."""
    detected_functions_list: list[BannedFunction] = []
    total = len(functions)
    log_interval = max(1, total // 10)
    decompiled_count, error_count = 0, 0

    for index, func in enumerate(functions):
        if skip_small_functions and func.size < small_function_threshold:
            continue

        _log_progress(
            index,
            total,
            func.name,
            decompiled_count,
            error_count,
            log_interval,
            decompiler_type_str,
            verbose,
        )

        detection_result, decompiled_ok = _process_single_function(
            r2,
            func,
            decompiler_type_str,
            verbose,
            log_interval,
            index,
            config,
            decompile_function_impl,
        )
        if decompiled_ok:
            if isinstance(detection_result, Ok):
                detected_functions_list.append(detection_result.unwrap())
            decompiled_count += 1
        else:
            error_count += 1

    return detected_functions_list, decompiled_count, error_count


def _log_decompilation_progress(
    functions: list[FunctionDescriptor],
    decompiler_type_str: str,
    verbose: bool,
) -> None:
    """Log the start of decompilation progress."""
    if verbose:
        logger.info(f"Decompiling {len(functions)} functions with {decompiler_type_str}...")


def _get_function_filtering_config(config: IConfigRepository) -> tuple[int, bool]:
    """Get function filtering configuration settings."""
    threshold = config.get("small_function_threshold", SMALL_FUNCTION_THRESHOLD)
    skip = config.get("skip_small_functions", True)
    return threshold, skip


__all__: list[str] = []  # internal module; use explicit imports
