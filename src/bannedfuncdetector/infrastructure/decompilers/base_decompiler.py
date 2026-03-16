"""Stable facade for base decompiler abstractions and shared helpers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.infrastructure.adapters.r2_client import R2Client

from .decompiler_availability import (
    DECAI_PREFERRED_MODELS,
    DECOMPILER_CONFIG,
    check_decompiler_plugin_available,
    _check_decai_service_available,
)
from .decompiler_support import (
    ERROR_SKIP_PATTERNS,
    clean_decompiled_output,
    get_function_info,
    is_small_function,
    is_valid_result,
    try_decompile_with_command,
)
from .decompiler_types import (
    DecompilationError,
    DecompilerNotAvailableError,
    DecompilerType,
    FunctionNotFoundError,
)


class BaseR2Decompiler(ABC):
    """Abstract base class for radare2-based decompilers."""

    def __init__(self, name: str, command: str) -> None:
        self.name = name
        self.command = command

    def decompile(self, r2: IR2Client, function_name: str) -> str:
        """Decompile a function using the configured command."""
        decompiled = try_decompile_with_command(
            r2=r2,
            command=self.command,
            function_name=function_name,
            clean_error_messages=True,
        )
        return decompiled if decompiled else ""

    @abstractmethod
    def is_available(self, r2: IR2Client | None = None) -> bool:
        """Check if this decompiler is available."""

    def get_name(self) -> str:
        """Get the human-readable name of this decompiler."""
        return self.name


__all__ = [
    "DecompilerType",
    "DecompilationError",
    "DecompilerNotAvailableError",
    "FunctionNotFoundError",
    "DECOMPILER_CONFIG",
    "DECAI_PREFERRED_MODELS",
    "ERROR_SKIP_PATTERNS",
    "BaseR2Decompiler",
    "R2Client",
    "clean_decompiled_output",
    "is_small_function",
    "is_valid_result",
    "try_decompile_with_command",
    "get_function_info",
    "check_decompiler_plugin_available",
    "_check_decai_service_available",
]
