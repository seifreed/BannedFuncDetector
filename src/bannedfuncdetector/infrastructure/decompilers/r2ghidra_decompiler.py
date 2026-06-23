"""
BannedFuncDetector - R2Ghidra Decompiler Module

This module provides the R2GhidraDecompiler class for decompilation
using the r2ghidra radare2 plugin (pdg command).

Author: Marc Rivero | @seifreed
"""

from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    DecompilerType,
    PairedR2Decompiler,
)


class R2GhidraDecompiler(PairedR2Decompiler):
    """R2Ghidra decompiler (pdg command), falling back to r2dec (pdd).

    Stateless and thread-safe; each decompilation uses the caller-provided
    r2pipe instance.

    Example:
        >>> decompiler = R2GhidraDecompiler()
        >>> if decompiler.is_available(r2):
        ...     code = decompiler.decompile(r2, 'main')
    """

    def __init__(self) -> None:
        """Initialize the R2Ghidra decompiler (pdg primary, pdd fallback)."""
        super().__init__(DecompilerType.R2GHIDRA, command="pdg", fallback_command="pdd")


__all__ = ["R2GhidraDecompiler"]
