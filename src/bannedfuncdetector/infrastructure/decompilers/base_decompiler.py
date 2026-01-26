#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Base Decompiler Module

This module provides the base class, enums, exceptions, configuration,
and shared utility functions for all decompiler implementations.

Contains:
    - DecompilerType enum
    - Custom exceptions (DecompilationError, etc.)
    - DECOMPILER_CONFIG configuration
    - BaseR2Decompiler abstract base class
    - Utility functions (clean_decompiled_output, etc.)
    - Unified check_decompiler_plugin_available() function

Author: Marc Rivero | @seifreed
"""

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

import requests

from bannedfuncdetector.constants import MIN_DECOMPILED_CODE_LENGTH, MIN_VALID_CODE_LENGTH
from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.infrastructure.adapters.r2_client import R2Client

# Configure logging
logger = logging.getLogger(__name__)

# Patterns to skip when cleaning decompiled output (errors, warnings, etc.)
ERROR_SKIP_PATTERNS: frozenset[str] = frozenset([
    "error:",
    "warn:",
    "warning:",
    "unknown branch",
])


# =============================================================================
# DECOMPILER TYPE ENUM
# =============================================================================


class DecompilerType(str, Enum):
    """
    Enumeration of supported decompiler types.

    This enum provides type-safe access to decompiler type identifiers,
    replacing string literals throughout the codebase.

    Attributes:
        DEFAULT: Built-in radare2 decompiler (pdc command)
        R2GHIDRA: R2Ghidra plugin (pdg command)
        R2DEC: R2Dec plugin (pdd command)
        DECAI: DecAI plugin with AI-based decompilation
    """

    DEFAULT = "default"
    R2GHIDRA = "r2ghidra"
    R2DEC = "r2dec"
    DECAI = "decai"

    @classmethod
    def from_string(cls, value: str | None) -> "DecompilerType":
        """
        Convert a string to DecompilerType, with fallback to DEFAULT.

        Args:
            value: The string value to convert.

        Returns:
            The corresponding DecompilerType or DEFAULT if not found.
        """
        if value is None:
            return cls.DEFAULT

        value_lower = value.lower().strip()

        # Handle r2ai special case - it's not a decompiler
        if value_lower == "r2ai":
            logger.warning("r2ai is not a decompiler, it's an AI assistant. Using default decompiler.")
            return cls.DEFAULT

        for member in cls:
            if member.value == value_lower:
                return member

        logger.warning(f"Unknown decompiler type: {value}. Using default decompiler.")
        return cls.DEFAULT


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================


class DecompilationError(Exception):
    """Base exception for decompilation errors."""


class DecompilerNotAvailableError(DecompilationError):
    """Raised when a decompiler is not available."""


class FunctionNotFoundError(DecompilationError):
    """Raised when a function cannot be found."""


# =============================================================================
# DECOMPILER CONFIGURATION
# =============================================================================


DECOMPILER_CONFIG: dict[str, dict[str, Any]] = {
    "r2ghidra": {"check_cmd": "Lc", "expected": "r2ghidra"},
    "r2dec": {"check_cmd": "Lc", "expected": ["pdd", "r2dec"]},
    "default": {"always_available": True},
    "decai": {"check_service": True, "url": "http://localhost:11434"},
    "r2ai": {
        "not_decompiler": True,
        "message": "r2ai is not a decompiler, it's an AI assistant. Please use a decompiler like r2ghidra or r2dec",
    },
}

# Preferred models for decai (ordered by priority)
DECAI_PREFERRED_MODELS = [
    "qwen2:5b-coder",
    "codellama:7b",
    "llama3",
    "mistral",
    "phi",
]


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def clean_decompiled_output(decompiled_text: str | None) -> str | None:
    """
    Clean decompiled output by removing error messages and warnings.

    Args:
        decompiled_text: The raw decompiled text.

    Returns:
        Cleaned decompiled text or None if input is None/empty.
    """
    if not decompiled_text:
        return decompiled_text

    lines = decompiled_text.splitlines()
    cleaned_lines = []

    for line in lines:
        # Skip error messages and warnings
        if _should_skip_line(line):
            continue
        # Skip empty lines after cleaning
        if line.strip():
            cleaned_lines.append(line)

    return "\n".join(cleaned_lines)


def _should_skip_line(line: str) -> bool:
    """
    Determine if a line should be skipped during output cleaning.

    Args:
        line: A single line of decompiled output.

    Returns:
        True if the line should be skipped, False otherwise.
    """
    line_lower = line.lower()
    return any(pattern in line_lower for pattern in ERROR_SKIP_PATTERNS)


def is_small_function(func: dict[str, Any], threshold: int) -> bool:
    """
    Check if a function is considered small based on its size.

    Args:
        func: Function information dictionary with 'size' key.
        threshold: Size threshold below which functions are considered small.

    Returns:
        True if the function size is below the threshold.
    """
    size = func.get("size", 0)
    return bool(size < threshold) if isinstance(size, int) else False


def is_valid_result(code: str | None) -> bool:
    """
    Check if decompiled code is a valid result.

    Args:
        code: The decompiled code to validate.

    Returns:
        True if the code is valid (non-empty, sufficient length, no errors).
    """
    if not code or len(code) <= MIN_VALID_CODE_LENGTH:
        return False
    return "Error" not in code and "error" not in code.lower()


def try_decompile_with_command(
    r2: IR2Client,
    command: str,
    function_name: str,
    clean_error_messages: bool = True,
) -> str | None:
    """
    Try to decompile with a specific command and handle errors.

    Args:
        r2: r2pipe instance.
        command: The radare2 command to execute.
        function_name: Name of the function to decompile.
        clean_error_messages: Whether to clean error messages from output.

    Returns:
        Decompiled code or None if decompilation failed.
    """
    try:
        r2.cmd(f"s {function_name}")
        decompiled: str | None = r2.cmd(command)

        if clean_error_messages:
            decompiled = clean_decompiled_output(decompiled)

        if decompiled and len(decompiled.strip()) > MIN_DECOMPILED_CODE_LENGTH:
            return decompiled
        return None
    except (RuntimeError, ValueError, OSError, IOError, AttributeError):
        # RuntimeError: r2pipe execution failure
        # ValueError: Invalid data from r2
        # OSError/IOError: File system errors
        # AttributeError: r2 instance in invalid state
        return None


def get_function_info(r2: IR2Client, function_name: str) -> dict[str, Any] | None:
    """
    Gets function information from radare2.

    Args:
        r2: r2pipe instance.
        function_name: Name of the function to look for.

    Returns:
        Function information or None if not found.
    """
    try:
        function_info = r2.cmdj(f"afij @ {function_name}")
        return _normalize_function_info(function_info)
    except (RuntimeError, ValueError) as e:
        # RuntimeError: r2pipe command execution failure
        # ValueError: Invalid JSON response from r2
        logger.error(f"Error getting function information {function_name}: {e}")
        return None
    except (AttributeError, TypeError) as e:
        # AttributeError: r2 instance in invalid state
        # TypeError: Invalid function_info structure
        logger.error(f"Data error getting function information {function_name}: {e}")
        return None


def _normalize_function_info(function_info: Any) -> dict[str, Any] | None:
    """
    Normalize radare2 function info into a single dictionary when possible.

    Args:
        function_info: Function info from radare2 (dict, list, or None).

    Returns:
        Normalized function info dictionary or None.
    """
    if function_info is None:
        return None
    if isinstance(function_info, list):
        return function_info[0] if function_info else None
    if isinstance(function_info, dict):
        return function_info
    return None


def _get_function_offset(
    r2: IR2Client, function_name: str, function_info: Any
) -> int | None:
    """
    Get the function offset from function info or by seeking.

    Args:
        r2: r2pipe instance.
        function_name: Name of the function.
        function_info: Function information dict or list.

    Returns:
        Function offset or None if not found.
    """
    function_info = _normalize_function_info(function_info)
    if function_info:
        # radare2 returns "addr" from afij, "offset" from other commands
        offset = function_info.get("offset") or function_info.get("addr")
        if offset is not None:
            return int(offset) if isinstance(offset, (int, float)) else None

    # Try to use the function name directly as an address
    r2.cmd(f"s {function_name}")
    addr_info = r2.cmdj("sj")

    if addr_info and isinstance(addr_info, dict):
        offset = addr_info.get("offset") or addr_info.get("addr")
        if offset is not None:
            return int(offset) if isinstance(offset, (int, float)) else None

    return None


# =============================================================================
# ABSTRACT BASE CLASS FOR R2-BASED DECOMPILERS
# =============================================================================


class BaseR2Decompiler(ABC):
    """
    Abstract base class for radare2-based decompilers.

    This class provides common functionality for decompilers that use
    radare2 plugins (r2ghidra, r2dec, etc.). Subclasses must implement
    the is_available() method for plugin-specific availability checks.

    Attributes:
        name: Human-readable name of the decompiler.
        command: The radare2 command used for decompilation.

    Thread Safety:
        This class is stateless and thread-safe. Each decompilation uses the
        provided r2pipe instance which should be managed by the caller.
    """

    def __init__(self, name: str, command: str) -> None:
        """
        Initialize the base decompiler.

        Args:
            name: Human-readable name of the decompiler (e.g., 'r2ghidra').
            command: The radare2 command for decompilation (e.g., 'pdg').
        """
        self.name = name
        self.command = command

    def decompile(self, r2: IR2Client, function_name: str) -> str:
        """
        Decompile a function using the configured command.

        Args:
            r2: An active r2pipe instance connected to the binary being analyzed.
            function_name: The name or address of the function to decompile.

        Returns:
            The decompiled pseudocode. Returns empty string if decompilation fails.
        """
        decompiled = try_decompile_with_command(
            r2=r2,
            command=self.command,
            function_name=function_name,
            clean_error_messages=True,
        )
        return decompiled if decompiled else ""

    @abstractmethod
    def is_available(self, r2: IR2Client | None = None) -> bool:
        """
        Check if this decompiler is available.

        Args:
            r2: An optional r2pipe instance (may not be used by all implementations).

        Returns:
            True if the decompiler is available, False otherwise.
        """

    def get_name(self) -> str:
        """Get the human-readable name of this decompiler."""
        return self.name


# =============================================================================
# UNIFIED DECOMPILER AVAILABILITY CHECK
# =============================================================================


def check_decompiler_plugin_available(
    decompiler_type: str | DecompilerType,
) -> bool:
    """
    Unified function to check if a decompiler plugin is available.

    This consolidates the separate check_r2ghidra_available, check_r2dec_available,
    and check_decai_available functions into a single parameterized function.

    Args:
        decompiler_type: The type of decompiler to check.

    Returns:
        True if the decompiler is available, False otherwise.
    """
    if isinstance(decompiler_type, DecompilerType):
        decompiler_type = decompiler_type.value

    config = DECOMPILER_CONFIG.get(decompiler_type)
    if config is None:
        return False

    if config.get("not_decompiler"):
        return False

    if config.get("always_available"):
        return True

    if config.get("check_service"):
        return _check_decai_service_available(config["url"])

    if "check_cmd" in config:
        return _check_r2_plugin_available(config["check_cmd"], config["expected"])

    return False


def _check_r2_plugin_available(check_cmd: str, expected: str | list[str]) -> bool:
    """
    Check if a radare2 plugin is available.

    Args:
        check_cmd: The radare2 command to check plugins.
        expected: Expected string(s) in the output.

    Returns:
        True if the plugin is available, False otherwise.
    """
    try:
        # Open r2 with "-" (no file) to just check plugin availability without loading a binary
        with R2Client.open("-") as r2:
            result = r2.cmd(check_cmd)

        # Support both single string and list of strings for flexible matching
        # (e.g., checking for "ghidra" or ["r2ghidra", "pdg"])
        if isinstance(expected, list):
            return any(exp in result for exp in expected)
        return expected in result
    except (RuntimeError, ValueError, OSError, IOError) as e:
        # RuntimeError: r2pipe execution failure
        # ValueError: Invalid r2 output
        # OSError/IOError: Unable to open r2 instance
        logger.error(f"Error checking r2 plugin: {e}")
        return False
    except (AttributeError, TypeError) as e:
        # AttributeError: r2 instance issues
        # TypeError: Unexpected result type
        logger.error(f"Data error checking r2 plugin: {e}")
        return False


def _check_decai_service_available(url: str) -> bool:
    """
    Check if decai plugin and Ollama service are available.

    Args:
        url: The Ollama service URL.

    Returns:
        True if decai and Ollama are available, False otherwise.
    """
    try:
        with R2Client.open("-") as r2:
            result = r2.cmd("decai -h")

        is_plugin_available = (
            "Usage: decai" in result and "Unknown command" not in result
        )
        if not is_plugin_available:
            return False

        # Check Ollama service
        response = requests.get(f"{url}/api/tags", timeout=1)
        return response.status_code == 200
    except requests.RequestException:
        logger.warning("decai plugin is available but cannot connect to Ollama")
        return False
    except (RuntimeError, ValueError, OSError, IOError) as e:
        # RuntimeError: r2pipe execution failure
        # ValueError: Invalid r2 output
        # OSError/IOError: Unable to open r2 instance
        logger.error(f"Error checking decai availability: {e}")
        return False


# =============================================================================
# DECOMPILATION HELPERS
# =============================================================================


def _try_decompile_pair(
    r2: IR2Client,
    function_name: str,
    primary_cmd: str,
    fallback_cmd: str,
    clean_error_messages: bool,
    use_alternative: bool,
) -> str:
    """
    Try decompiling with a primary command, optionally falling back to another.

    This function attempts to decompile a function using the primary command first.
    If that fails and use_alternative is True, it falls back to the fallback command.

    Args:
        r2: r2pipe instance.
        function_name: Name of the function to decompile.
        primary_cmd: Primary decompilation command (e.g., 'pdg' for r2ghidra).
        fallback_cmd: Fallback decompilation command (e.g., 'pdd' for r2dec).
        clean_error_messages: Whether to clean error messages from output.
        use_alternative: Whether to use fallback command if primary fails.

    Returns:
        Decompiled code string, or empty string if both methods fail.
    """
    # Try primary decompiler first (e.g., r2ghidra's pdg)
    decompiled = try_decompile_with_command(
        r2, primary_cmd, function_name, clean_error_messages
    )
    if decompiled:
        return decompiled
    # Fallback strategy: use alternative decompiler if primary fails
    # (e.g., fall back to r2dec's pdd if r2ghidra fails on complex functions)
    if use_alternative:
        return (
            try_decompile_with_command(
                r2, fallback_cmd, function_name, clean_error_messages
            )
            or ""
        )
    return ""


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enum
    "DecompilerType",
    # Exceptions
    "DecompilationError",
    "DecompilerNotAvailableError",
    "FunctionNotFoundError",
    # Configuration
    "DECOMPILER_CONFIG",
    "DECAI_PREFERRED_MODELS",
    # Constants
    "ERROR_SKIP_PATTERNS",
    # Base class
    "BaseR2Decompiler",
    # Utility functions
    "clean_decompiled_output",
    "is_small_function",
    "is_valid_result",
    "try_decompile_with_command",
    "get_function_info",
    # Availability check functions
    "check_decompiler_plugin_available",
]
