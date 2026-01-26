#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Decompiler Selector Module

This module handles decompiler selection and type resolution.

Contains:
    - select_decompiler(): Select an appropriate decompiler based on availability
    - resolve_to_decompiler_type(): Resolve a decompiler type to its enum form
    - Helper functions for selection logic

Author: Marc Rivero | @seifreed
"""

import logging

from bannedfuncdetector.infrastructure.config_repository import get_default_config
from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    DecompilerType,
)
from bannedfuncdetector.infrastructure.decompilers.availability import (
    check_decompiler_available,
)
from bannedfuncdetector.domain.protocols import IConfigRepository

# Configure logging
logger = logging.getLogger(__name__)


# =============================================================================
# DECOMPILER TYPE RESOLUTION
# =============================================================================


def resolve_to_decompiler_type(
    decompiler_type: str | DecompilerType | None,
    config: IConfigRepository | None = None,
) -> DecompilerType:
    """
    Resolve and normalize a decompiler type to its enum form.

    This is the canonical function for converting string/None/enum inputs
    to a DecompilerType enum. Use this when you need the enum type.

    For selecting an available decompiler with fallback logic, use
    :func:`select_decompiler` instead.

    Args:
        decompiler_type: Type of decompiler to resolve (string, enum, or None).
        config: Configuration repository instance providing decompiler settings.
            Required in v2.0. Use create_config_from_file() or create_config_from_dict().

    Returns:
        Resolved DecompilerType enum value. Returns DEFAULT if None or unknown.

    Example:
        >>> resolve_to_decompiler_type("r2ghidra")
        DecompilerType.R2GHIDRA
        >>> resolve_to_decompiler_type(None)
        DecompilerType.DEFAULT

    .. deprecated::
        Passing None for config is deprecated and will raise an error in v2.0.
    """
    if config is None:
        import warnings
        warnings.warn(
            "Passing None for config is deprecated. Use create_config_from_file() or create_config_from_dict().",
            DeprecationWarning,
            stacklevel=2
        )
        config = get_default_config()
    if decompiler_type is None:
        type_str = config["decompiler"]["type"]
        return DecompilerType.from_string(type_str)

    if isinstance(decompiler_type, DecompilerType):
        return decompiler_type

    return DecompilerType.from_string(decompiler_type)


# =============================================================================
# DECOMPILER SELECTION HELPERS
# =============================================================================


def _resolve_requested_decompiler(
    requested: str | DecompilerType | None,
    config: IConfigRepository | None = None,
) -> str:
    """
    Resolves the requested decompiler to a valid string value.

    Handles None (uses config), DecompilerType enum conversion,
    and invalid r2ai replacement.

    Args:
        requested: The requested decompiler type, or None for config default.
        config: Configuration repository instance providing decompiler settings.
            Required parameter - will raise ValueError if None.

    Returns:
        The resolved decompiler type as a string.

    Raises:
        ValueError: If config is None.

    .. deprecated::
        The config parameter will be required in v2.0. Currently raises
        ValueError if None.
    """
    if config is None:
        raise ValueError(
            "config parameter is required. Use create_config_from_file() or "
            "create_config_from_dict() to create a configuration."
        )
    if requested is None:
        decompiler_config = config["decompiler"]
        decompiler_type: str = decompiler_config["type"]
        return decompiler_type

    if isinstance(requested, DecompilerType):
        requested = requested.value

    if requested == "r2ai":
        logger.warning("r2ai is not a decompiler. Changing to default decompiler.")
        return DecompilerType.DEFAULT.value

    return requested


def _get_alternative_decompilers(requested: str) -> list[str]:
    """
    Gets a list of alternative decompilers to try.

    Decompiler priority fallback chain:
    1. r2ghidra (most comprehensive, production-quality Ghidra integration)
    2. r2dec (lighter weight, good compatibility)
    3. default (pdc - always available fallback, basic functionality)

    DecAI is included if originally requested (requires Ollama service running).

    Args:
        requested: The originally requested decompiler type.

    Returns:
        List of alternative decompiler types to try, excluding the requested one.
    """
    if requested == DecompilerType.DECAI.value:
        alternatives = [
            DecompilerType.DECAI.value,
            DecompilerType.R2GHIDRA.value,
            DecompilerType.R2DEC.value,
            DecompilerType.DEFAULT.value,
        ]
    else:
        alternatives = [
            DecompilerType.R2GHIDRA.value,
            DecompilerType.R2DEC.value,
            DecompilerType.DEFAULT.value,
        ]

    # Remove the already-checked requested decompiler to avoid redundant checks
    if requested in alternatives:
        alternatives.remove(requested)

    return alternatives


def _log_unavailable_decompiler(requested: str) -> None:
    """
    Logs a warning message for an unavailable decompiler.

    Args:
        requested: The decompiler type that was not available.
    """
    if requested == DecompilerType.DECAI.value:
        logger.warning(f"The AI assistant plugin {requested} is not available.")
    else:
        logger.warning(f"The decompiler {requested} is not available.")
    logger.info("Checking available alternatives...")


def _select_best_available(
    alternatives: list[str],
    verbose: bool,
) -> str:
    """
    Selects the best available decompiler from a list of alternatives.

    Args:
        alternatives: List of decompiler types to try in order.
        verbose: If True, logs information about the selection.

    Returns:
        The first available decompiler, or 'default' if none are available.
    """
    for alt in alternatives:
        if check_decompiler_available(alt, print_message=False):
            if verbose:
                if alt == DecompilerType.DECAI.value:
                    logger.info(
                        f"AI assistant plugin '{alt}' is available as an alternative."
                    )
                else:
                    logger.info(f"Decompiler '{alt}' is available as an alternative.")
                logger.info(f"Using '{alt}' automatically.")
            return alt

    if verbose:
        logger.warning("No available alternatives found.")
        logger.info("Using the default decompiler.")
    return DecompilerType.DEFAULT.value


# =============================================================================
# MAIN SELECTION FUNCTION
# =============================================================================


def select_decompiler(
    requested: str | DecompilerType | None = None,
    force: bool = False,
    verbose: bool = False,
    config: IConfigRepository | None = None,
) -> str:
    """
    Selects an appropriate decompiler based on availability.

    This function checks if the requested decompiler is available and falls
    back to alternatives if it is not. The fallback order is:
    1. r2ghidra (best quality)
    2. r2dec (good compatibility)
    3. default (always available)

    Args:
        requested: Decompiler type ('r2ghidra', 'r2dec', 'decai', 'default')
            or None for config default.
        force: Force use without checking availability.
        verbose: Log detailed selection process.
        config: Configuration repository providing decompiler settings.
            Required in v2.0. Use create_config_from_file() or create_config_from_dict().

    Returns:
        Selected decompiler type string.

    .. deprecated::
        Passing None for config is deprecated and will raise an error in v2.0.
    """
    if config is None:
        import warnings
        warnings.warn(
            "Passing None for config is deprecated. Use create_config_from_file() or create_config_from_dict().",
            DeprecationWarning,
            stacklevel=2
        )
        config = get_default_config()
    resolved = _resolve_requested_decompiler(requested, config)

    if verbose:
        logger.info(f"Attempting to use decompiler: {resolved}...")

    if force:
        if verbose:
            logger.info(f"Forcing use of decompiler: {resolved}")
        return resolved

    if check_decompiler_available(resolved, print_message=verbose):
        return resolved

    if verbose:
        _log_unavailable_decompiler(resolved)

    alternatives = _get_alternative_decompilers(resolved)
    return _select_best_available(alternatives, verbose)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Main functions
    "select_decompiler",
    "resolve_to_decompiler_type",
]
