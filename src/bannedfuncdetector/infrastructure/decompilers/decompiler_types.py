"""Shared decompiler enum and exceptions."""

from __future__ import annotations

import logging
from enum import Enum

logger = logging.getLogger(__name__)


class DecompilerType(str, Enum):
    """Enumeration of supported decompiler types."""

    DEFAULT = "default"
    R2GHIDRA = "r2ghidra"
    R2DEC = "r2dec"
    DECAI = "decai"

    @classmethod
    def from_string(cls, value: str | None) -> "DecompilerType":
        """Convert a string to DecompilerType, with fallback to DEFAULT."""
        if value is None:
            return cls.DEFAULT

        value_lower = value.lower().strip()
        if value_lower == "r2ai":
            logger.warning(
                "AI assistant requested as a decompiler; using the default",
                extra={
                    "operation": "decompiler_selection",
                    "event_name": "decompiler_request_fallback",
                    "outcome": "defaulted",
                },
            )
            return cls.DEFAULT

        for member in cls:
            if member.value == value_lower:
                return member

        logger.warning(
            "Unknown decompiler type; using the default",
            extra={
                "operation": "decompiler_selection",
                "event_name": "decompiler_type_unknown",
                "outcome": "defaulted",
            },
        )
        return cls.DEFAULT


class DecompilationError(Exception):
    """Base exception for decompilation errors."""


class DecompilerNotAvailableError(DecompilationError):
    """Raised when a decompiler is not available."""


class FunctionNotFoundError(DecompilationError):
    """Raised when a function cannot be found."""


__all__ = [
    "DecompilerType",
    "DecompilationError",
    "DecompilerNotAvailableError",
    "FunctionNotFoundError",
]
