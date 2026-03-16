"""Search helpers for finding banned calls inside decompiled code."""

from __future__ import annotations

import logging

from bannedfuncdetector.domain import BannedFunction, FunctionDescriptor
from bannedfuncdetector.domain.types import create_detection_result as _create_detection_result
from bannedfuncdetector.domain.banned_functions import BANNED_FUNCTIONS
from bannedfuncdetector.domain.result import Result, err, ok
from bannedfuncdetector.domain.types import DecompiledCode, search_banned_call_in_text

logger = logging.getLogger(__name__)

# Pre-sorted once at module load; sorting 300+ items on every analyzed function is O(N log N) waste.
_BANNED_FUNCTIONS_SORTED: tuple[str, ...] = tuple(sorted(BANNED_FUNCTIONS))


def _search_single_banned_function(
    decompiled_code: DecompiledCode,
    insecure_func: str,
    func_name: str,
) -> bool:
    """Search for a single banned function in decompiled code."""
    try:
        return search_banned_call_in_text(decompiled_code, insecure_func)
    except (TypeError, ValueError, AttributeError) as exc:
        logger.debug(f"Error searching for pattern {insecure_func} in {func_name}: {exc}")
        return False


def _search_banned_in_decompiled(
    decompiled_code: DecompiledCode,
    func: FunctionDescriptor,
    verbose: bool,
) -> Result[BannedFunction, str]:
    """Search for all banned functions in decompiled code."""
    func_name = func.name
    func_addr = func.address

    # Use pre-sorted tuple for deterministic iteration order (sorting once at module load).
    found: list[str] = []
    for insecure_func in _BANNED_FUNCTIONS_SORTED:
        if _search_single_banned_function(decompiled_code, insecure_func, func_name):
            found.append(insecure_func)

    if found:
        if verbose:
            logger.warning(f"Unsafe functions detected in {func_name}: {', '.join(found)}")
        return ok(_create_detection_result(func_name, func_addr, list(found), "decompilation"))

    return err(f"No banned functions found in decompiled code for {func_name}")


__all__: list[str] = []  # internal module; use explicit imports
