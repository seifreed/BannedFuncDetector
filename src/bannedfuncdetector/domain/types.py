"""
Type aliases and shared domain utilities.

Author: Marc Rivero | @seifreed
"""

import re
from collections.abc import Callable
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


def _compile_name_pattern(func_name: str) -> re.Pattern[str]:
    """Compile a word-boundary regex pattern matching a bare function name."""
    return re.compile(r"\b" + re.escape(func_name) + r"\b", re.IGNORECASE)


class _BannedPatternMatcher:
    """Lazily-built, cached regex matcher over the canonical banned-function set.

    Call-site (``name(``) and bare-name matching are identical except for the
    regex shape, so both share this matcher; only the ``compile`` callable
    differs. Patterns for the canonical set are built once on first use (lazy to
    avoid a circular import at module load); unknown names compile on demand.
    """

    def __init__(self, compile_pattern: "Callable[[str], re.Pattern[str]]") -> None:
        self._compile = compile_pattern
        self._cache: dict[str, re.Pattern[str]] = {}

    def _ensure_cache(self) -> None:
        if not self._cache:
            from .banned_functions import BANNED_FUNCTIONS

            for f in BANNED_FUNCTIONS:
                self._cache[f] = self._compile(f)

    def _pattern_for(self, name: str) -> re.Pattern[str]:
        return self._cache.get(name) or self._compile(name)

    def matches(self, text: str, name: str) -> bool:
        """Whether ``name``'s pattern occurs in ``text``."""
        self._ensure_cache()
        return bool(self._pattern_for(name).search(text))

    def find_all(self, text: str, names: set[str]) -> list[str]:
        """Every name in ``names`` whose pattern occurs in ``text``."""
        self._ensure_cache()
        return [name for name in names if self._pattern_for(name).search(text)]


_CALL_MATCHER = _BannedPatternMatcher(_compile_call_pattern)
_NAME_MATCHER = _BannedPatternMatcher(_compile_name_pattern)


def search_banned_call_in_text(text: str, func_name: str) -> bool:
    """Check if a banned function call pattern exists in text."""
    return _CALL_MATCHER.matches(text, func_name)


def find_banned_calls_in_text(text: str, banned_functions: set[str]) -> list[str]:
    """Return every banned function whose call site (``name(``) appears in text."""
    return _CALL_MATCHER.find_all(text, banned_functions)


def find_banned_names_in_text(text: str, banned_functions: set[str]) -> list[str]:
    """Return every banned function whose bare name appears in text (word-boundary)."""
    return _NAME_MATCHER.find_all(text, banned_functions)


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
    "find_banned_calls_in_text",
    "find_banned_names_in_text",
    "safe_parse_address",
    "create_detection_result",
]
