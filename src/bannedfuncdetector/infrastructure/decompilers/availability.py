#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Decompiler Availability Module

This module handles availability checking for decompilers.

Contains:
    - check_decompiler_available(): Check if a decompiler is available
    - get_available_decompiler(): Get the first available decompiler
    - _check_service_decompiler(): Check service-based decompilers (decai)
    - _check_plugin_decompiler(): Check r2 plugin decompilers

Author: Marc Rivero | @seifreed
"""

import logging

from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    DECOMPILER_CONFIG,
    DecompilerType,
    check_decompiler_plugin_available,
)

# Configure logging
logger = logging.getLogger(__name__)


# =============================================================================
# AVAILABILITY CHECKING HELPERS
# =============================================================================


def _check_service_decompiler(print_message: bool) -> bool:
    """
    Check availability of service-based decompilers like decai.

    Args:
        print_message: If True, logs availability messages.

    Returns:
        True if the service decompiler is available, False otherwise.
    """
    is_available = check_decompiler_plugin_available(DecompilerType.DECAI)
    if print_message:
        if is_available:
            logger.info("Plugin decai is available and Ollama is running")
        else:
            logger.warning("Plugin decai is not available or Ollama is not running")
    return is_available


def _check_plugin_decompiler(decompiler_type: str, print_message: bool) -> bool:
    """
    Check availability of r2 plugin decompilers.

    Args:
        decompiler_type: Type of decompiler to check.
        print_message: If True, logs availability messages.

    Returns:
        True if the plugin decompiler is available, False otherwise.
    """
    is_available = check_decompiler_plugin_available(decompiler_type)
    if print_message:
        if is_available:
            logger.info(f"Decompiler {decompiler_type} is available")
        else:
            logger.warning(f"Decompiler {decompiler_type} is not available")
    return is_available


# =============================================================================
# MAIN AVAILABILITY FUNCTIONS
# =============================================================================


def check_decompiler_available(
    decompiler_type: str | DecompilerType, print_message: bool = True
) -> bool:
    """
    Checks if a decompiler is available on the system.

    This function checks various types of decompilers:
    - Service-based decompilers (decai): Checks if the service is running
    - Plugin decompilers (r2ghidra, r2dec): Checks if the plugin is installed
    - Default decompiler: Always available

    Args:
        decompiler_type: Type of decompiler (r2ghidra, r2dec, decai, etc.).
        print_message: If True, logs availability messages.

    Returns:
        True if the decompiler is available, False otherwise.
    """
    if isinstance(decompiler_type, DecompilerType):
        decompiler_type = decompiler_type.value

    config = DECOMPILER_CONFIG.get(decompiler_type)
    if config is None:
        if print_message:
            logger.warning(f"Unknown decompiler type: {decompiler_type}")
        return False

    if config.get("not_decompiler"):
        if print_message:
            logger.warning(
                config.get("message", f"{decompiler_type} is not a decompiler")
            )
        return False

    if config.get("always_available"):
        if print_message:
            logger.info("Default decompiler is available")
        return True

    if config.get("check_service"):
        return _check_service_decompiler(print_message)

    if "check_cmd" in config:
        return _check_plugin_decompiler(decompiler_type, print_message)

    return False


def get_available_decompiler(
    preferred: str | DecompilerType = DecompilerType.DEFAULT,
) -> str:
    """
    Get the first available decompiler, preferring the specified one.

    This function tries the preferred decompiler first, then falls back to
    alternatives in order of priority: r2ghidra, r2dec, default.

    Args:
        preferred: The preferred decompiler to try first.

    Returns:
        The name of an available decompiler.
    """
    # Convert to string if DecompilerType enum
    if isinstance(preferred, DecompilerType):
        preferred = preferred.value

    alternatives = [
        DecompilerType.R2GHIDRA.value,
        DecompilerType.R2DEC.value,
        DecompilerType.DEFAULT.value,
    ]

    if preferred in alternatives:
        alternatives.remove(preferred)
        alternatives.insert(0, preferred)
    elif preferred != "r2ai":  # Don't add r2ai as it's not a decompiler
        alternatives.insert(0, preferred)

    for alt in alternatives:
        if check_decompiler_available(alt, print_message=False):
            return alt

    return DecompilerType.DEFAULT.value


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Main functions
    "check_decompiler_available",
    "get_available_decompiler",
]
