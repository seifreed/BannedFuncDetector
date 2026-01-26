#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - R2Dec Decompiler Module

This module provides the R2DecDecompiler class for decompilation
using the r2dec radare2 plugin (pdd command).

Author: Marc Rivero | @seifreed
"""

from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    BaseR2Decompiler,
    DecompilerType,
    _try_decompile_pair,
    check_decompiler_plugin_available,
)


class R2DecDecompiler(BaseR2Decompiler):
    """
    R2Dec decompiler implementation using the pdd command.

    This class provides r2dec-specific decompilation functionality,
    extending BaseR2Decompiler and implementing the IDecompiler protocol.
    Falls back to r2ghidra (pdg) if r2dec fails.

    Thread Safety:
        This class is stateless and thread-safe. Each decompilation uses the
        provided r2pipe instance which should be managed by the caller.

    Example:
        >>> decompiler = R2DecDecompiler()
        >>> if decompiler.is_available(r2):
        ...     code = decompiler.decompile(r2, 'main')
        ...     print(code)
    """

    def __init__(self) -> None:
        """Initialize the R2Dec decompiler."""
        super().__init__(name=DecompilerType.R2DEC.value, command="pdd")

    def decompile(
        self,
        r2: IR2Client,
        function_name: str,
        clean_error_messages: bool = True,
        use_alternative: bool = True,
    ) -> str:
        """
        Decompile a function using the r2dec plugin.

        Uses the 'pdd' command for decompilation with optional fallback to r2ghidra.

        Args:
            r2: r2pipe instance.
            function_name: Name of the function to decompile.
            clean_error_messages: Whether to clean error messages from output.
            use_alternative: Whether to fall back to r2ghidra if r2dec fails.

        Returns:
            Decompiled code string, or empty string if decompilation fails.
        """
        return _try_decompile_pair(
            r2,
            function_name,
            primary_cmd="pdd",
            fallback_cmd="pdg",
            clean_error_messages=clean_error_messages,
            use_alternative=use_alternative,
        )

    def is_available(self, r2: IR2Client | None = None) -> bool:
        """
        Check if r2dec is available.

        Args:
            r2: An optional r2pipe instance (not used, included for interface compatibility).

        Returns:
            True if r2dec is available, False otherwise.
        """
        return check_decompiler_plugin_available(DecompilerType.R2DEC)


__all__ = ["R2DecDecompiler"]
