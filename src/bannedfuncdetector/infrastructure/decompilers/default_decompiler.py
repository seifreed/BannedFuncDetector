#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Default Decompiler Module

This module provides the DefaultDecompiler class for decompilation
using radare2's built-in pdc command (always available).

Author: Marc Rivero | @seifreed
"""

from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    BaseR2Decompiler,
    DecompilerType,
    try_decompile_with_command,
)


class DefaultDecompiler(BaseR2Decompiler):
    """
    Default decompiler implementation using radare2's built-in pdc command.

    This class provides the fallback decompilation functionality using
    radare2's native decompiler. It's always available as it doesn't
    require any additional plugins.

    Thread Safety:
        This class is stateless and thread-safe. Each decompilation uses the
        provided r2pipe instance which should be managed by the caller.

    Example:
        >>> decompiler = DefaultDecompiler()
        >>> if decompiler.is_available(r2):
        ...     code = decompiler.decompile(r2, 'main')
        ...     print(code)
    """

    def __init__(self) -> None:
        """Initialize the Default decompiler."""
        super().__init__(name=DecompilerType.DEFAULT.value, command="pdc")

    def decompile(self, r2: IR2Client, function_name: str) -> str:
        """
        Decompile a function using radare2's built-in pdc command.

        Args:
            r2: An active r2pipe instance connected to the binary being analyzed.
            function_name: The name or address of the function to decompile.

        Returns:
            str: The decompiled pseudocode. Returns empty string if decompilation fails.
        """
        decompiled = try_decompile_with_command(
            r2=r2,
            command=self.command,
            function_name=function_name,
            clean_error_messages=True,
        )
        return decompiled if decompiled else ""

    def is_available(self, r2: IR2Client | None = None) -> bool:
        """
        Check if the default decompiler is available.

        The default decompiler (pdc) is always available as it's built into radare2.

        Args:
            r2: An optional r2pipe instance (not used, included for interface compatibility).

        Returns:
            True - the default decompiler is always available.
        """
        return True


__all__ = ["DefaultDecompiler"]
