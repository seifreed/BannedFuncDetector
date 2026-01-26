#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Decompiler Registry Module

This module provides the decompiler registry and factory function.

Contains:
    - DecompilerInstance type alias
    - DECOMPILER_INSTANCES registry
    - create_decompiler factory function

Author: Marc Rivero | @seifreed
"""

import logging

from bannedfuncdetector.infrastructure.decompilers.base_decompiler import DecompilerType
from bannedfuncdetector.infrastructure.decompilers.r2ghidra_decompiler import R2GhidraDecompiler
from bannedfuncdetector.infrastructure.decompilers.r2dec_decompiler import R2DecDecompiler
from bannedfuncdetector.infrastructure.decompilers.decai_decompiler import DecAIDecompiler
from bannedfuncdetector.infrastructure.decompilers.default_decompiler import DefaultDecompiler

# Configure logging
logger = logging.getLogger(__name__)


# =============================================================================
# TYPE ALIASES
# =============================================================================

# Type alias for decompiler instances
DecompilerInstance = (
    DefaultDecompiler | R2GhidraDecompiler | R2DecDecompiler | DecAIDecompiler
)


# =============================================================================
# DECOMPILER REGISTRY
# =============================================================================

# Pre-configured decompiler instances
DECOMPILER_INSTANCES: dict[str, DecompilerInstance] = {
    DecompilerType.R2GHIDRA.value: R2GhidraDecompiler(),
    DecompilerType.R2DEC.value: R2DecDecompiler(),
    DecompilerType.DECAI.value: DecAIDecompiler(),
    DecompilerType.DEFAULT.value: DefaultDecompiler(),
}


# =============================================================================
# FACTORY FUNCTION
# =============================================================================


def create_decompiler(decompiler_type: str | DecompilerType) -> DecompilerInstance:
    """
    Factory function to create decompiler instances by type.

    Args:
        decompiler_type: The type of decompiler to create. Valid values:
            - DecompilerType.R2GHIDRA or 'r2ghidra': Uses pdg command (Ghidra decompiler)
            - DecompilerType.R2DEC or 'r2dec': Uses pdd command (r2dec decompiler)
            - DecompilerType.DECAI or 'decai': Uses AI via Ollama
            - DecompilerType.DEFAULT or 'default': Tries all available, uses pdc fallback
            - 'r2ai': Invalid, returns default with warning
            - Any other: Unknown, returns default with warning

    Returns:
        An instance of a decompiler that implements the IDecompiler protocol.

    Examples:
        >>> decompiler = create_decompiler(DecompilerType.R2GHIDRA)
        >>> print(decompiler.get_name())
        r2ghidra

        >>> decompiler = create_decompiler('r2dec')
        >>> print(decompiler.get_name())
        r2dec
    """
    # Convert string to DecompilerType
    if isinstance(decompiler_type, str):
        decompiler_type_enum = DecompilerType.from_string(decompiler_type)
    else:
        decompiler_type_enum = decompiler_type

    decompiler_key = decompiler_type_enum.value

    if decompiler_key not in DECOMPILER_INSTANCES:
        logger.warning(
            f"Unknown decompiler type: {decompiler_key}. Using default decompiler."
        )
        decompiler_key = DecompilerType.DEFAULT.value

    return DECOMPILER_INSTANCES[decompiler_key]


__all__ = [
    "DecompilerInstance",
    "DECOMPILER_INSTANCES",
    "create_decompiler",
]
