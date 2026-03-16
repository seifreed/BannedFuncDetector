#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Type aliases and shared domain utilities.

Author: Marc Rivero | @seifreed
"""
import re
from typing import Any, TypeAlias

from .entities import (
    BannedFunction,
    FunctionDescriptor,
)
from .error_types import ErrorCategory
from .result import Result

# Decompiler types
DecompiledCode: TypeAlias = str
DecompilationResultType: TypeAlias = Result[DecompiledCode, str]


def classify_error(exc: Exception) -> str:
    """Classify an exception into a standard error category label."""
    if isinstance(exc, (OSError, IOError)):
        return ErrorCategory.IO
    if isinstance(exc, (RuntimeError, ValueError)):
        return ErrorCategory.RUNTIME
    if isinstance(exc, (KeyError, AttributeError, TypeError)):
        return ErrorCategory.DATA
    return ErrorCategory.ERROR


def _compile_call_pattern(func_name: str) -> re.Pattern[str]:
    """Compile a call-site regex pattern for a function name."""
    return re.compile(r"\b" + re.escape(func_name) + r"\s*\(", re.IGNORECASE)


# Pre-compiled call-site patterns for all canonical banned functions.
# Built once at module load; used by both application and infrastructure layers.
_CALL_PATTERN_CACHE: dict[str, re.Pattern[str]] = {}


def _ensure_call_pattern_cache() -> dict[str, re.Pattern[str]]:
    """Lazily build the call-pattern cache on first use (avoids circular import at module load)."""
    if not _CALL_PATTERN_CACHE:
        from .banned_functions import BANNED_FUNCTIONS
        for f in BANNED_FUNCTIONS:
            _CALL_PATTERN_CACHE[f] = _compile_call_pattern(f)
    return _CALL_PATTERN_CACHE


def search_banned_call_in_text(text: str, func_name: str) -> bool:
    """Check if a banned function call pattern exists in text.

    Uses pre-compiled patterns from the module-level cache for canonical
    banned function names; falls back to on-demand compilation for custom names.
    """
    cache = _ensure_call_pattern_cache()
    pattern = cache.get(func_name)
    if pattern is None:
        pattern = _compile_call_pattern(func_name)
    return bool(pattern.search(text))


def safe_parse_address(addr: Any) -> int:
    """Parse an address value safely, returning 0 for unparseable inputs.

    Handles: int, hex string ("0x401000", "4010a0"), None, empty string,
    and non-hex strings ("main", "sym.main") without raising.
    """
    if addr is None:
        return 0
    if isinstance(addr, int):
        return addr
    if isinstance(addr, str):
        stripped = addr.strip()
        if not stripped:
            return 0
        try:
            return int(stripped, 16)
        except ValueError:
            return 0
    return 0


def create_detection_result(
    func_name: str,
    func_addr: Any,
    banned_functions: list[str],
    detection_method: str,
) -> BannedFunction:
    """Create a standardized banned-function entity with category assignment."""
    from .banned_functions import get_highest_risk_category

    parsed_address = safe_parse_address(func_addr)
    category = get_highest_risk_category(banned_functions) if banned_functions else None
    return BannedFunction(
        name=func_name,
        address=parsed_address,
        size=0,
        banned_calls=tuple(banned_functions),
        detection_method=detection_method,
        category=category,
    )


__all__ = [
    "DecompiledCode",
    "DecompilationResultType",
    "FunctionDescriptor",
    "BannedFunction",
    "classify_error",
    "search_banned_call_in_text",
    "safe_parse_address",
    "create_detection_result",
]
