"""Decompiler orchestration: dispatch, search, iteration and the service facade.

This module is the single coordination point for running decompilers over
functions and scanning the resulting pseudocode for banned calls. It exposes:

- ``decompile_function``: decompile one function with the resolved backend.
- ``decompile_with_selected_decompiler``: scan a list of functions.
- ``DecompilerOrchestrator`` / ``create_decompiler_orchestrator``: the
  protocol-compliant service facade used by the application layer.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from bannedfuncdetector.constants import SMALL_FUNCTION_THRESHOLD
from bannedfuncdetector.domain import BannedFunction, FunctionDescriptor
from bannedfuncdetector.domain.banned_functions import BANNED_FUNCTIONS
from bannedfuncdetector.domain.protocols import IConfigRepository, IR2Client
from bannedfuncdetector.domain.result import Err, Ok, Result, err, ok
from bannedfuncdetector.domain.types import (
    DecompilationResultType,
    DecompiledCode,
    classify_error,
    create_detection_result as _create_detection_result,
    search_banned_call_in_text,
)

from .availability import check_decompiler_available, get_available_decompiler
from .base_decompiler import DecompilationError, DecompilerType
from .cascade import _decompile_with_instance
from .selector import resolve_to_decompiler_type, select_decompiler

logger = logging.getLogger(__name__)

# Pre-sorted once at module load; sorting 300+ items on every analyzed function is O(N log N) waste.
_BANNED_FUNCTIONS_SORTED: tuple[str, ...] = tuple(sorted(BANNED_FUNCTIONS))


# --------------------------------------------------------------------------- #
# Single-function decompilation
# --------------------------------------------------------------------------- #
def decompile_function(
    r2: IR2Client,
    function_name: str,
    decompiler_type: str | DecompilerType | None = None,
    *,
    config: IConfigRepository,
) -> DecompilationResultType:
    """Decompile one function using the resolved decompiler backend."""
    try:
        decompiler_type_enum = resolve_to_decompiler_type(decompiler_type, config)
        decompiler_options = config["decompiler"].get("options", {})
        return _decompile_with_instance(
            r2, function_name, decompiler_type_enum, decompiler_options
        )
    except (KeyError, AttributeError, TypeError) as exc:
        return err(f"Configuration error decompiling {function_name}: {str(exc)}")
    except (RuntimeError, ValueError) as exc:
        logger.error(f"Runtime error decompiling {function_name}: {exc}")
        return err(f"Runtime error decompiling {function_name}: {str(exc)}")
    except DecompilationError as exc:
        logger.error(f"Decompilation error for {function_name}: {exc}")
        return err(f"Decompilation error: {str(exc)}")


# --------------------------------------------------------------------------- #
# Banned-call search inside decompiled code
# --------------------------------------------------------------------------- #
def _search_single_banned_function(
    decompiled_code: DecompiledCode,
    insecure_func: str,
    func_name: str,
) -> bool:
    """Search for a single banned function in decompiled code."""
    try:
        return search_banned_call_in_text(decompiled_code, insecure_func)
    except (TypeError, ValueError, AttributeError) as exc:
        logger.debug(
            f"Error searching for pattern {insecure_func} in {func_name}: {exc}"
        )
        return False


def _search_banned_in_decompiled(
    decompiled_code: DecompiledCode,
    func: FunctionDescriptor,
    verbose: bool,
) -> Result[BannedFunction, str]:
    """Search for all banned functions in decompiled code."""
    func_name = func.name
    func_addr = func.address

    found: list[str] = [
        insecure_func
        for insecure_func in _BANNED_FUNCTIONS_SORTED
        if _search_single_banned_function(decompiled_code, insecure_func, func_name)
    ]

    if found:
        if verbose:
            logger.warning(
                f"Unsafe functions detected in {func_name}: {', '.join(found)}"
            )
        return ok(
            _create_detection_result(func_name, func_addr, list(found), "decompilation")
        )

    return err(f"No banned functions found in decompiled code for {func_name}")


# --------------------------------------------------------------------------- #
# Progress and exception logging
# --------------------------------------------------------------------------- #
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
    """Log progress information during decompilation."""
    if not verbose:
        return

    is_interval = current % log_interval == 0 or current == total - 1
    is_detailed_interval = current % 50 == 0
    if is_interval:
        percent = (current + 1) / total * 100
        logger.info(
            f"Progress: {current + 1}/{total} functions ({percent:.1f}%) - "
            f"Decompiled: {success_count}, Errors: {error_count}"
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
    """Log the final summary of the decompilation analysis."""
    if not verbose:
        return
    logger.info("Decompilation analysis completed:")
    logger.info(f"   - Total functions analyzed: {total_functions}")
    logger.info(f"   - Successful decompilations: {success_count}")
    logger.info(f"   - Errors: {error_count}")
    logger.info(f"   - Unsafe functions detected: {detected_count}")


def _handle_decompilation_error(
    func_name: str,
    error: str,
    verbose: bool,
    log_interval: int,
    current_index: int,
) -> tuple[Result[BannedFunction, str], bool]:
    """Handle decompilation failure and return the failure tuple."""
    if verbose and current_index % log_interval == 0:
        logger.error(f"Error: Decompilation of {func_name} failed: {error}")
    return err(f"Decompilation failed: {error}"), False


def _handle_processing_exception(
    func_name: str,
    exception: Exception,
    verbose: bool,
    log_interval: int,
    current_index: int,
) -> tuple[Result[BannedFunction, str], bool]:
    """Handle exceptions during function processing."""
    error_type = classify_error(exception)
    if verbose and current_index % log_interval == 0:
        logger.error(f"{error_type} processing {func_name}: {exception}")
    return err(f"{error_type}: {str(exception)}"), False


# --------------------------------------------------------------------------- #
# Multi-function iteration
# --------------------------------------------------------------------------- #
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
        logger.info(
            f"Decompiling {len(functions)} functions with {decompiler_type_str}..."
        )


def _get_function_filtering_config(config: IConfigRepository) -> tuple[int, bool]:
    """Get function filtering configuration settings."""
    threshold = config.get("small_function_threshold", SMALL_FUNCTION_THRESHOLD)
    skip = config.get("skip_small_functions", True)
    return threshold, skip


# --------------------------------------------------------------------------- #
# Multi-function decompilation entrypoint
# --------------------------------------------------------------------------- #
def decompile_with_selected_decompiler(
    r2: IR2Client,
    functions: list[FunctionDescriptor],
    verbose: bool = True,
    decompiler_type: str | DecompilerType | None = None,
    *,
    config: IConfigRepository,
    decompile_function_impl: Callable[
        ..., DecompilationResultType
    ] = decompile_function,
) -> list[BannedFunction]:
    """Use the selected decompiler to scan all candidate functions."""
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
        r2,
        functions,
        decompiler_type_str,
        verbose,
        threshold,
        skip,
        config,
        decompile_function_impl,
    )
    _log_final_summary(
        len(functions), success_count, error_count, len(detected), verbose
    )
    return detected


# --------------------------------------------------------------------------- #
# Service facade
# --------------------------------------------------------------------------- #
class DecompilerOrchestrator:
    """Protocol-compliant orchestration facade."""

    def __init__(
        self,
        config: IConfigRepository,
        *,
        config_factory: "Callable[[dict], IConfigRepository] | None" = None,
    ) -> None:
        self._config = config
        self._config_factory = config_factory

    def decompile_function(
        self,
        r2: IR2Client,
        function_name: str,
        decompiler_type: str | None = None,
        **options: Any,
    ) -> "Result[str, str]":
        if options and self._config_factory is not None:
            # Merge caller options into a config overlay so they reach the cascade
            config_dict = self._config.to_dict()
            decompiler_opts = config_dict.get("decompiler", {}).get("options", {})
            decompiler_opts.update(options)
            config_dict.setdefault("decompiler", {})["options"] = decompiler_opts
            merged_config = self._config_factory(config_dict)
            return decompile_function(
                r2, function_name, decompiler_type, config=merged_config
            )
        return decompile_function(
            r2, function_name, decompiler_type, config=self._config
        )

    def select_decompiler(
        self,
        requested: str | None = None,
        force: bool = False,
    ) -> str:
        return select_decompiler(
            requested=requested, force=force, verbose=False, config=self._config
        )

    def check_decompiler_available(self, decompiler_type: str) -> bool:
        return check_decompiler_available(decompiler_type)


def create_decompiler_orchestrator(
    config: IConfigRepository,
    *,
    config_factory: "Callable[[dict], IConfigRepository] | None" = None,
) -> DecompilerOrchestrator:
    """Create a new orchestrator instance."""
    return DecompilerOrchestrator(config, config_factory=config_factory)


__all__ = [
    "decompile_function",
    "decompile_with_selected_decompiler",
    "check_decompiler_available",
    "get_available_decompiler",
    "select_decompiler",
    "resolve_to_decompiler_type",
    "DecompilerOrchestrator",
    "create_decompiler_orchestrator",
]
