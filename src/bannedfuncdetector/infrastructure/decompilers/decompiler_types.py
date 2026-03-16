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
            logger.warning("r2ai is not a decompiler, it's an AI assistant. Using default decompiler.")
            return cls.DEFAULT

        for member in cls:
            if member.value == value_lower:
                return member

        logger.warning(f"Unknown decompiler type: {value}. Using default decompiler.")
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
