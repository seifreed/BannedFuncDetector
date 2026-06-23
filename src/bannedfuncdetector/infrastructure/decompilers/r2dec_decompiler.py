"""
BannedFuncDetector - R2Dec Decompiler Module

This module provides the R2DecDecompiler class for decompilation
using the r2dec radare2 plugin (pdd command).

Author: Marc Rivero | @seifreed
"""

from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    DecompilerType,
    PairedR2Decompiler,
)


class R2DecDecompiler(PairedR2Decompiler):
    """R2Dec decompiler (pdd command), falling back to r2ghidra (pdg).

    Stateless and thread-safe; each decompilation uses the caller-provided
    r2pipe instance.

    Example:
        >>> decompiler = R2DecDecompiler()
        >>> if decompiler.is_available(r2):
        ...     code = decompiler.decompile(r2, 'main')
    """

    def __init__(self) -> None:
        """Initialize the R2Dec decompiler (pdd primary, pdg fallback)."""
        super().__init__(DecompilerType.R2DEC, command="pdd", fallback_command="pdg")


__all__ = ["R2DecDecompiler"]
