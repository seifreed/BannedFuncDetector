"""Detection helpers for banned-function analysis."""

import logging
from typing import Any

from bannedfuncdetector.domain import BannedFunction, FunctionDescriptor
from bannedfuncdetector.domain.protocols import IR2Client, IDecompilerOrchestrator
from bannedfuncdetector.domain.result import Result, Err, ok, err
from bannedfuncdetector.domain.banned_functions import BANNED_FUNCTIONS
from bannedfuncdetector.domain.types import (
    create_detection_result as _create_detection_result,
    find_banned_calls_in_text,
    find_banned_names_in_text,
)

logger = logging.getLogger(__name__)


def _find_banned_in_name(text: str, banned_functions: set[str]) -> list[str]:
    """Return banned functions matching ``text`` by bare name (word-boundary)."""
    return find_banned_names_in_text(text, banned_functions)


def _find_banned_in_code(text: str, banned_functions: set[str]) -> list[str]:
    """Return banned functions found in decompiled code by call site."""
    return find_banned_calls_in_text(text, banned_functions)


def _validate_analysis_inputs(
    func: FunctionDescriptor | None, banned_functions: set[str] | None
) -> Result[set[str], str]:
    """Validate and normalize inputs for function analysis."""
    if func is None:
        return err("Function descriptor cannot be None")

    normalized = banned_functions or BANNED_FUNCTIONS
    # Return the set directly; callers treat it as read-only.
    return ok(normalized if isinstance(normalized, set) else set(normalized))


def _check_function_name_banned(
    func_name: str, func_addr: Any, banned_functions: set[str], verbose: bool = False
) -> Result[BannedFunction, str]:
    """Check whether the function name itself matches a banned symbol."""
    detected_banned = _find_banned_in_name(func_name, banned_functions)

    if detected_banned:
        if verbose:
            logger.info(f"Insecure function detected by name: {func_name}")
        return ok(
            _create_detection_result(func_name, func_addr, detected_banned, "name")
        )
    return err(f"No banned functions found in name: {func_name}")


def _decompile_and_search(
    r2: IR2Client,
    func_name: str,
    func_addr: Any,
    banned_functions: set[str],
    decompiler_type: str,
    verbose: bool = False,
    decompiler_orchestrator: IDecompilerOrchestrator | None = None,
) -> Result[BannedFunction, str]:
    """Decompile a function and search the recovered code for banned calls."""
    if decompiler_orchestrator is None:
        return err("Decompilation orchestrator is required for decompilation analysis")

    decompile_result = decompiler_orchestrator.decompile_function(
        r2, func_name, decompiler_type
    )

    if isinstance(decompile_result, Err):
        return err(f"Decompilation failed: {decompile_result.error}")

    decompiled_code = decompile_result.unwrap()
    if not decompiled_code:
        return err(f"Empty decompilation result for {func_name}")

    detected_banned = _find_banned_in_code(decompiled_code, banned_functions)

    if detected_banned:
        if verbose:
            logger.info(f"Insecure function detected in decompiled code: {func_name}")
        return ok(
            _create_detection_result(
                func_name, func_addr, detected_banned, "decompilation"
            )
        )
    return err(f"No banned functions found in decompiled code: {func_name}")


__all__: list[str] = []  # internal module; use explicit imports
