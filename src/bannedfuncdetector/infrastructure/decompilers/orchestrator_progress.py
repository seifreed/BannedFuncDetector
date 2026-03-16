"""Progress and exception helpers for decompiler orchestration."""

from __future__ import annotations

import logging

from bannedfuncdetector.domain import BannedFunction
from bannedfuncdetector.domain.result import Result, err
from bannedfuncdetector.domain.types import classify_error

logger = logging.getLogger(__name__)


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


__all__: list[str] = []  # internal module; use explicit imports
