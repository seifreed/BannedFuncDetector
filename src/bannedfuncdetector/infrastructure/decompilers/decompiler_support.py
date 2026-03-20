"""Shared utility helpers for decompiler implementations."""

from __future__ import annotations

import logging
from typing import Any

from bannedfuncdetector.constants import (
    MIN_DECOMPILED_CODE_LENGTH,
    MIN_VALID_CODE_LENGTH,
)
from bannedfuncdetector.domain.protocols import IR2Client

logger = logging.getLogger(__name__)

ERROR_SKIP_PATTERNS: frozenset[str] = frozenset(
    [
        "error:",
        "warn:",
        "warning:",
        "unknown branch",
    ]
)


def clean_decompiled_output(decompiled_text: str | None) -> str | None:
    """Clean decompiled output by removing error messages and warnings."""
    if not decompiled_text:
        return decompiled_text

    cleaned_lines = [
        line
        for line in decompiled_text.splitlines()
        if line.strip() and not _should_skip_line(line)
    ]
    return "\n".join(cleaned_lines)


def _should_skip_line(line: str) -> bool:
    """Determine if a line should be skipped during output cleaning."""
    line_lower = line.lower()
    return any(pattern in line_lower for pattern in ERROR_SKIP_PATTERNS)


def is_small_function(func: dict[str, Any], threshold: int) -> bool:
    """Check if a function is considered small based on its size."""
    size = func.get("size", 0)
    return bool(size < threshold) if isinstance(size, int) else False


def is_valid_result(code: str | None) -> bool:
    """Check if decompiled code is a valid result."""
    if not code or len(code) <= MIN_VALID_CODE_LENGTH:
        return False
    return "Error" not in code and "error" not in code.lower()


def try_decompile_with_command(
    r2: IR2Client,
    command: str,
    function_name: str,
    clean_error_messages: bool = True,
) -> str | None:
    """Try to decompile with a specific command and handle errors."""
    try:
        r2.cmd(f"s {function_name}")
        decompiled: str | None = r2.cmd(command)
        if clean_error_messages:
            decompiled = clean_decompiled_output(decompiled)
        if decompiled and len(decompiled.strip()) > MIN_DECOMPILED_CODE_LENGTH:
            return decompiled
        return None
    except (RuntimeError, ValueError, OSError, IOError, AttributeError):
        return None


def get_function_info(r2: IR2Client, function_name: str) -> dict[str, Any] | None:
    """Get function information from radare2."""
    try:
        function_info = r2.cmdj(f"afij @ {function_name}")
        return _normalize_function_info(function_info)
    except (RuntimeError, ValueError) as exc:
        logger.error(f"Error getting function information {function_name}: {exc}")
        return None
    except (AttributeError, TypeError) as exc:
        logger.error(f"Data error getting function information {function_name}: {exc}")
        return None


def _normalize_function_info(function_info: Any) -> dict[str, Any] | None:
    """Normalize radare2 function info into a single dictionary when possible."""
    if function_info is None:
        return None
    if isinstance(function_info, list):
        return function_info[0] if function_info else None
    if isinstance(function_info, dict):
        return function_info
    return None


def _get_function_offset(
    r2: IR2Client,
    function_name: str,
    function_info: Any,
) -> int | None:
    """Get the function offset from function info or by seeking."""
    function_info = _normalize_function_info(function_info)
    if function_info:
        offset = function_info.get("offset") or function_info.get("addr")
        if offset is not None:
            return int(offset) if isinstance(offset, (int, float)) else None

    r2.cmd(f"s {function_name}")
    addr_info = r2.cmdj("sj")
    if addr_info and isinstance(addr_info, dict):
        offset = addr_info.get("offset") or addr_info.get("addr")
        if offset is not None:
            return int(offset) if isinstance(offset, (int, float)) else None
    return None


def _try_decompile_pair(
    r2: IR2Client,
    function_name: str,
    primary_cmd: str,
    fallback_cmd: str,
    clean_error_messages: bool,
    use_alternative: bool,
) -> str:
    """Try decompiling with a primary command, optionally falling back."""
    decompiled = try_decompile_with_command(
        r2, primary_cmd, function_name, clean_error_messages
    )
    if decompiled:
        return decompiled
    if use_alternative:
        return (
            try_decompile_with_command(
                r2, fallback_cmd, function_name, clean_error_messages
            )
            or ""
        )
    return ""


__all__ = [
    "ERROR_SKIP_PATTERNS",
    "clean_decompiled_output",
    "get_function_info",
    "is_small_function",
    "is_valid_result",
    "try_decompile_with_command",
]
