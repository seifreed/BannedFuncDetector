#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detection helpers for banned-function analysis."""

import logging
import re
from typing import Any

from bannedfuncdetector.domain import BannedFunction, FunctionDescriptor
from bannedfuncdetector.domain.protocols import IR2Client, IDecompilerOrchestrator
from bannedfuncdetector.domain.result import Result, Err, ok, err
from bannedfuncdetector.domain.banned_functions import BANNED_FUNCTIONS
from bannedfuncdetector.domain.types import (
    create_detection_result as _create_detection_result,
)

logger = logging.getLogger(__name__)


# Pre-compiled regex caches keyed on the canonical BANNED_FUNCTIONS set.
# Patterns are built once at module load so neither _find_banned_in_name nor
# _find_banned_in_code pays re.compile() overhead on every analyzed function.
def _build_name_patterns(funcs: set[str]) -> dict[str, re.Pattern[str]]:
    return {f: re.compile(r"\b" + re.escape(f) + r"\b", re.IGNORECASE) for f in funcs}


def _build_call_patterns(funcs: set[str]) -> dict[str, re.Pattern[str]]:
    return {
        f: re.compile(r"\b" + re.escape(f) + r"\s*\(", re.IGNORECASE) for f in funcs
    }


_NAME_PATTERNS: dict[str, re.Pattern[str]] = _build_name_patterns(BANNED_FUNCTIONS)
_CALL_PATTERNS: dict[str, re.Pattern[str]] = _build_call_patterns(BANNED_FUNCTIONS)


def _find_banned_in_name(text: str, banned_functions: set[str]) -> list[str]:
    """Return banned function names matching the function name using word boundary.

    Uses pre-compiled patterns from the module-level cache when the caller passes
    the canonical BANNED_FUNCTIONS set; falls back to on-demand compilation for
    any custom set supplied at runtime.
    """
    found: list[str] = []
    use_cache = banned_functions is BANNED_FUNCTIONS
    for banned in banned_functions:
        pattern = _NAME_PATTERNS.get(banned) if use_cache else None
        if pattern is None:
            pattern = re.compile(r"\b" + re.escape(banned) + r"\b", re.IGNORECASE)
        if pattern.search(text):
            found.append(banned)
    return found


def _find_banned_in_code(text: str, banned_functions: set[str]) -> list[str]:
    """Return banned function names found in decompiled code using call-site matching.

    Uses pre-compiled patterns from the module-level cache when the caller passes
    the canonical BANNED_FUNCTIONS set; falls back to on-demand compilation for
    any custom set supplied at runtime.
    """
    found: list[str] = []
    use_cache = banned_functions is BANNED_FUNCTIONS
    for banned in banned_functions:
        pattern = _CALL_PATTERNS.get(banned) if use_cache else None
        if pattern is None:
            pattern = re.compile(r"\b" + re.escape(banned) + r"\s*\(", re.IGNORECASE)
        if pattern.search(text):
            found.append(banned)
    return found


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
