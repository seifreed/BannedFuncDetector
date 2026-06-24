"""Shared utility helpers for decompiler implementations."""

from __future__ import annotations

import logging
import re
from typing import Any

from bannedfuncdetector.constants import (
    MIN_DECOMPILED_CODE_LENGTH,
    MIN_VALID_CODE_LENGTH,
)
from bannedfuncdetector.domain.protocols import IR2Client

logger = logging.getLogger(__name__)

# radare2 treats ';' and newlines as command separators and '!', backticks,
# '|', '>' etc. as shell/redirect operators. Function names originate from the
# analyzed (untrusted) binary via `aflj`, so a crafted binary could smuggle r2
# commands — including `!`-prefixed shell commands — through a function name.
# Legitimate r2 symbol names (e.g. ``sym.imp.strcpy``, ``fcn.00401000``,
# ``main``, ``sym.std::vector``) consist only of word characters and ``.:+-``;
# anything else is rejected before it reaches an r2 command string.
_SAFE_R2_NAME = re.compile(r"[\w.:+-]+")


def is_safe_r2_name(name: str) -> bool:
    """Return True if ``name`` is safe to interpolate into an r2 command."""
    return bool(name) and _SAFE_R2_NAME.fullmatch(name) is not None


# Characters radare2 interprets specially on a command line: ';' and newlines
# are command separators (the r2pipe protocol itself treats '\n' as a command
# boundary, before any quoting applies), '!' escapes to the shell, backticks
# substitute command output, '|' pipes to the shell, '@' is a temp-seek, '~'
# greps, '$' is a variable, '>'/'<' redirect, '(' defines a macro, and quotes
# delimit arguments. Free text embedded in `decai -q` originates from the
# analyzed (untrusted) binary's disassembly, so every one of these is removed
# before the text reaches an r2 command string.
_R2_QUERY_FORBIDDEN = "\n\r;@~|`'\"!$><(){}#&"
_R2_QUERY_TRANSLATION = {ord(ch): " " for ch in _R2_QUERY_FORBIDDEN}


def sanitize_r2_query_text(text: str) -> str:
    """Flatten free text into a single line safe to embed in an r2 command.

    Newlines and every r2/shell command metacharacter are replaced with
    spaces and whitespace runs are collapsed, so untrusted disassembly text
    cannot break out of an `decai -q '...'` query into a separate r2 command.
    """
    return " ".join(text.translate(_R2_QUERY_TRANSLATION).split())

ERROR_SKIP_PATTERNS: frozenset[str] = frozenset(
    [
        "error:",
        "warn:",
        "warning:",
        "unknown branch",
    ]
)


# ANSI escape sequences (color/SGR and other CSI codes). radare2 emits these in
# decompiled output by default; left in, they split a banned-function name from
# its call paren ("printf\x1b[0m(") and defeat call-site detection. Strip them so
# detection is correct even when the r2 session was opened with color enabled.
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def clean_decompiled_output(decompiled_text: str | None) -> str | None:
    """Clean decompiled output by removing ANSI codes, error messages and warnings."""
    if not decompiled_text:
        return decompiled_text

    decompiled_text = _ANSI_ESCAPE.sub("", decompiled_text)
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


# Markers that identify an AI/decompiler *failure message* rather than code.
# decai surfaces failures as a leading "ERROR: ..." string and r2 backends emit
# phrases like "Cannot decompile"/"Unknown command". These are matched
# case-sensitively so ordinary code that merely references error handling
# (``strerror``, ``error_code``, ``GetLastError``, a ``goto error;`` label) is
# not mistaken for a failed decompilation.
_DECOMPILE_FAILURE_MARKERS = (
    "ERROR:",
    "Cannot decompile",
    "Unknown command",
    "RCmd.Use",
)


def is_valid_result(code: str | None) -> bool:
    """Check if decompiled code is a valid result (not a failure message)."""
    if not code or len(code) <= MIN_VALID_CODE_LENGTH:
        return False
    return not any(marker in code for marker in _DECOMPILE_FAILURE_MARKERS)


def try_decompile_with_command(
    r2: IR2Client,
    command: str,
    function_name: str,
    clean_error_messages: bool = True,
) -> str | None:
    """Try to decompile with a specific command and handle errors."""
    if not is_safe_r2_name(function_name):
        logger.warning("Refusing to seek unsafe function name: %r", function_name)
        return None
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
    if not is_safe_r2_name(function_name):
        logger.warning(
            "Refusing to query unsafe function name: %r", function_name
        )
        return None
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


def _coerce_offset(value: Any) -> int | None:
    """Coerce a radare2 offset value to int, or None if it is not numeric.

    Uses an explicit None check (not truthiness) so a valid address of 0 is
    preserved rather than discarded.
    """
    if isinstance(value, bool):
        return None
    return int(value) if isinstance(value, (int, float)) else None


def _offset_from_entry(entry: dict[str, Any]) -> int | None:
    """Read the offset (or addr) from a function/seek info dict."""
    offset = _coerce_offset(entry.get("offset"))
    if offset is not None:
        return offset
    return _coerce_offset(entry.get("addr"))


def _current_seek_entry(addr_info: Any) -> dict[str, Any] | None:
    """Return the active entry from radare2's `sj` output.

    `sj` returns the seek history as a list of entries; the active position is
    the one flagged ``current`` (falling back to the last entry). Older builds
    may return a single dict, which is passed through unchanged.
    """
    if isinstance(addr_info, dict):
        return addr_info
    if isinstance(addr_info, list) and addr_info:
        for entry in addr_info:
            if isinstance(entry, dict) and entry.get("current"):
                return entry
        last = addr_info[-1]
        return last if isinstance(last, dict) else None
    return None


def _get_function_offset(
    r2: IR2Client,
    function_name: str,
    function_info: Any,
) -> int | None:
    """Get the function offset from function info or by seeking."""
    function_info = _normalize_function_info(function_info)
    if function_info:
        offset = _offset_from_entry(function_info)
        if offset is not None:
            return offset

    if not is_safe_r2_name(function_name):
        logger.warning("Refusing to seek unsafe function name: %r", function_name)
        return None
    r2.cmd(f"s {function_name}")
    entry = _current_seek_entry(r2.cmdj("sj"))
    if entry is not None:
        return _offset_from_entry(entry)
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
    "is_safe_r2_name",
    "is_small_function",
    "is_valid_result",
    "sanitize_r2_query_text",
    "try_decompile_with_command",
]
