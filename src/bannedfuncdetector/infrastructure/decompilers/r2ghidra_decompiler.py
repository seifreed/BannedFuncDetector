#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - R2Ghidra Decompiler Module

This module provides the R2GhidraDecompiler class for decompilation
using the r2ghidra radare2 plugin (pdg command).

Author: Marc Rivero | @seifreed
"""

from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    BaseR2Decompiler,
    DecompilerType,
    _try_decompile_pair,
    check_decompiler_plugin_available,
)


class R2GhidraDecompiler(BaseR2Decompiler):
    """
    R2Ghidra decompiler implementation using the pdg command.

    This class provides r2ghidra-specific decompilation functionality,
    extending BaseR2Decompiler and implementing the IDecompiler protocol.
    Falls back to r2dec (pdd) if r2ghidra fails.

    Thread Safety:
        This class is stateless and thread-safe. Each decompilation uses the
        provided r2pipe instance which should be managed by the caller.

    Example:
        >>> decompiler = R2GhidraDecompiler()
        >>> if decompiler.is_available(r2):
        ...     code = decompiler.decompile(r2, 'main')
        ...     print(code)
    """

    def __init__(self) -> None:
        """Initialize the R2Ghidra decompiler."""
        super().__init__(name=DecompilerType.R2GHIDRA.value, command="pdg")

    def decompile(
        self,
        r2: IR2Client,
        function_name: str,
        clean_error_messages: bool = True,
        use_alternative: bool = True,
    ) -> str:
        """
        Decompile a function using the r2ghidra plugin.

        Uses the 'pdg' command for decompilation with optional fallback to r2dec.

        Args:
            r2: r2pipe instance.
            function_name: Name of the function to decompile.
            clean_error_messages: Whether to clean error messages from output.
            use_alternative: Whether to fall back to r2dec if r2ghidra fails.

        Returns:
            Decompiled code string, or empty string if decompilation fails.
        """
        return _try_decompile_pair(
            r2,
            function_name,
            primary_cmd="pdg",
            fallback_cmd="pdd",
            clean_error_messages=clean_error_messages,
            use_alternative=use_alternative,
        )

    def is_available(self, r2: IR2Client | None = None) -> bool:
        """
        Check if r2ghidra is available.

        Args:
            r2: An optional r2pipe instance (not used, included for interface compatibility).

        Returns:
            True if r2ghidra is available, False otherwise.
        """
        return check_decompiler_plugin_available(DecompilerType.R2GHIDRA)


__all__ = ["R2GhidraDecompiler"]
