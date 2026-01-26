#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Decompiler Cascade Module

This module handles HOW to try multiple decompilers in sequence (fallback strategy).

Contains:
    - _decompile_with_default_cascade(): Default decompilation with cascade fallback
    - DECOMPILER_CASCADE_ORDER: Priority order for decompiler fallback

The cascade module is responsible for:
    - Trying available decompilers in priority order
    - Handling fallback strategies when primary decompiler fails
    - Managing assembly fallback as last resort

Author: Marc Rivero | @seifreed
"""

import logging
from typing import Any

from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.domain.result import Result, ok, err
from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    DecompilationError,
    DecompilerType,
    check_decompiler_plugin_available,
    try_decompile_with_command,
)
from bannedfuncdetector.infrastructure.decompilers.registry import DECOMPILER_INSTANCES
from bannedfuncdetector.infrastructure.decompilers.r2ghidra_decompiler import R2GhidraDecompiler
from bannedfuncdetector.infrastructure.decompilers.r2dec_decompiler import R2DecDecompiler
from bannedfuncdetector.infrastructure.decompilers.decai_decompiler import DecAIDecompiler

# Configure logging
logger = logging.getLogger(__name__)


# =============================================================================
# DECOMPILER CASCADE PRIORITY
# =============================================================================

# Decompilers to try in order of priority for cascade fallback:
# 1. r2ghidra (pdg) - most comprehensive, production-quality Ghidra integration
# 2. r2dec (pdd) - lighter weight, good compatibility
# 3. default (pdc) - always available fallback, basic functionality
DECOMPILER_CASCADE_ORDER: list[tuple[str, str]] = [
    (DecompilerType.R2GHIDRA.value, "pdg"),
    (DecompilerType.R2DEC.value, "pdd"),
    (DecompilerType.DEFAULT.value, "pdc"),
]


# =============================================================================
# DECOMPILATION WITH CLASS INSTANCES
# =============================================================================


def _decompile_with_instance(
    r2: IR2Client,
    function_name: str,
    decompiler_type: DecompilerType,
    options: dict[str, Any],
) -> Result[str, str]:
    """
    Decompile using the appropriate class instance from DECOMPILER_INSTANCES.

    Args:
        r2: r2pipe instance.
        function_name: Name of the function to decompile.
        decompiler_type: Type of decompiler to use.
        options: Decompiler options from configuration.

    Returns:
        Result containing decompiled code or error message.
    """
    clean_error_messages = options.get("clean_error_messages", True)
    use_alternative = options.get("use_alternative_decompiler", True)

    try:
        # Handle each decompiler type explicitly for proper type narrowing
        if decompiler_type == DecompilerType.DECAI:
            decai = DECOMPILER_INSTANCES[DecompilerType.DECAI.value]
            if not isinstance(decai, DecAIDecompiler):
                return err("DecAI decompiler not properly configured")
            # DecAIDecompiler.decompile returns str (extends BaseR2Decompiler)
            result = decai.decompile(r2, function_name)
            return ok(result) if result else err(
                f"DecAI decompilation failed for {function_name}"
            )

        if decompiler_type == DecompilerType.R2GHIDRA:
            ghidra = DECOMPILER_INSTANCES[DecompilerType.R2GHIDRA.value]
            if not isinstance(ghidra, R2GhidraDecompiler):
                return err("R2Ghidra decompiler not properly configured")
            result = ghidra.decompile(
                r2, function_name,
                clean_error_messages=clean_error_messages,
                use_alternative=use_alternative
            )
            return ok(result) if result else err(
                f"R2Ghidra decompilation failed for {function_name}"
            )

        if decompiler_type == DecompilerType.R2DEC:
            r2dec = DECOMPILER_INSTANCES[DecompilerType.R2DEC.value]
            if not isinstance(r2dec, R2DecDecompiler):
                return err("R2Dec decompiler not properly configured")
            result = r2dec.decompile(
                r2, function_name,
                clean_error_messages=clean_error_messages,
                use_alternative=use_alternative
            )
            return ok(result) if result else err(
                f"R2Dec decompilation failed for {function_name}"
            )

        # Default decompiler - uses cascade logic for better results
        return _decompile_with_default_cascade(
            r2, function_name, clean_error_messages, options
        )

    except DecompilationError as e:
        return err(str(e))


# =============================================================================
# DECOMPILATION CASCADE FUNCTIONS
# =============================================================================


def _decompile_with_default_cascade(
    r2: IR2Client,
    function_name: str,
    clean_error_messages: bool,
    options: dict[str, Any],
) -> Result[str, str]:
    """
    Default decompilation with cascade fallback strategy.

    Tries available decompilers in order: r2ghidra, r2dec, then pdc.
    Falls back to assembly disassembly if configured and all decompilers fail.

    Args:
        r2: r2pipe instance connected to a binary.
        function_name: Name of the function to decompile.
        clean_error_messages: Whether to clean error messages from output.
        options: Decompiler options from configuration.

    Returns:
        Result containing decompiled code or error message.
    """
    fallback_to_asm = options.get("fallback_to_asm", True)

    # Try decompilers in priority order
    for decomp_name, command in DECOMPILER_CASCADE_ORDER:
        # Default is always available; others need plugin availability check
        if decomp_name == DecompilerType.DEFAULT.value or check_decompiler_plugin_available(
            decomp_name
        ):
            decompiled = try_decompile_with_command(
                r2, command, function_name, clean_error_messages
            )
            if decompiled:
                return ok(decompiled)

    # Fall back to assembly if enabled
    if fallback_to_asm:
        # Seek to function first before getting assembly
        r2.cmd(f"s {function_name}")
        asm_output = r2.cmd("pdf")
        return ok(asm_output) if asm_output else err("Could not get assembly")

    return err(f"Could not decompile function {function_name}")


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "DECOMPILER_CASCADE_ORDER",
]
