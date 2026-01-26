#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - DecAI Decompiler Module

This module provides the DecAIDecompiler class for AI-based decompilation
using the decai radare2 plugin with Ollama models.

Author: Marc Rivero | @seifreed
"""

import logging

from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    BaseR2Decompiler,
    DECAI_PREFERRED_MODELS,
    DecompilationError,
    DecompilerType,
    FunctionNotFoundError,
    _get_function_offset,
    check_decompiler_plugin_available,
    get_function_info,
    is_valid_result,
)

# Configure logging
logger = logging.getLogger(__name__)


# =============================================================================
# DECAI HELPER FUNCTIONS
# =============================================================================


def _configure_decai_model(r2: IR2Client) -> None:
    """
    Configure decai to use an appropriate AI model.

    This function checks the current decai configuration and only attempts
    to configure Ollama models if no API/model is already set.

    Args:
        r2: r2pipe instance.
    """
    try:
        # Check current configuration
        current_api = r2.cmd("decai -e api").strip()
        current_model = r2.cmd("decai -e model").strip()

        # Extract value after '=' if present (format: "decai -e api=value")
        if "=" in current_api:
            current_api = current_api.split("=")[-1].strip()
        if "=" in current_model:
            current_model = current_model.split("=")[-1].strip()

        # If already configured with a valid API and model, use it
        if current_api and current_model:
            logger.info(f"Using configured decai: api={current_api}, model={current_model}")
            return

        # If API is set but model is empty, list available models for that API
        if current_api and not current_model:
            available = r2.cmd("decai -m?").strip()
            if available:
                # Use first available model
                first_model = available.splitlines()[0].strip()
                if first_model:
                    r2.cmd(f"decai -e model={first_model}")
                    logger.info(f"Using decai with api={current_api}, model={first_model}")
                    return

        # Try to configure Ollama if no API is set
        # Use shell command (!) to run ollama list
        models_output = r2.cmd("!ollama list 2>/dev/null").strip()
        if not models_output or "error" in models_output.lower():
            logger.info("Using default decai configuration (no Ollama detected).")
            return

        models = models_output.splitlines()
        selected_model = None

        for model_line in models:
            for preferred in DECAI_PREFERRED_MODELS:
                if preferred in model_line.lower():
                    model_parts = model_line.split()
                    if model_parts:
                        selected_model = model_parts[0]
                        break
            if selected_model:
                break

        if not selected_model and len(models) > 1:
            model_parts = models[1].split()
            if model_parts:
                selected_model = model_parts[0]

        if selected_model:
            logger.info(f"Using Ollama model: {selected_model}")
            r2.cmd("decai -e api=ollama")
            r2.cmd(f"decai -e model={selected_model}")
        else:
            logger.info("Using default decai configuration.")

    except (RuntimeError, ValueError) as e:
        logger.debug(f"Error configuring decai model: {e}")
        logger.info("Using default decai configuration.")
    except (AttributeError, IndexError) as e:
        logger.debug(f"Error parsing decai configuration: {e}")
        logger.info("Using default decai configuration.")


def _try_decai_decompilation(r2: IR2Client, function_name: str) -> str | None:
    """
    Try various decai decompilation methods.

    This function attempts three different decompilation strategies:
    1. Direct decompilation with 'decai -d'
    2. Recursive decompilation with 'decai -dr'
    3. Direct query with assembly code

    Args:
        r2: r2pipe instance.
        function_name: Name of the function to decompile.

    Returns:
        Decompiled code or None if all methods failed.
    """
    # First attempt: direct decompilation
    decompiled_code = r2.cmd("decai -d")
    if is_valid_result(decompiled_code):
        return decompiled_code

    # Second attempt: recursive decompilation
    logger.info("First method unsuccessful, trying with recursive decompilation...")
    decompiled_code = r2.cmd("decai -dr")
    if is_valid_result(decompiled_code):
        return decompiled_code

    # Third attempt: direct query
    logger.info("Previous methods unsuccessful, trying direct query...")
    asm_code = r2.cmd("pdf")
    query = f"Decompile this assembly code to C:\n{asm_code}"
    decompiled_code = r2.cmd(f"decai -q '{query}'")
    if is_valid_result(decompiled_code):
        return decompiled_code

    return None


def _resolve_function_offset(r2: IR2Client, function_name: str) -> int:
    """
    Resolve and validate function offset for decompilation.

    Args:
        r2: r2pipe instance.
        function_name: Name of the function.

    Returns:
        Function offset.

    Raises:
        FunctionNotFoundError: If the function cannot be found.
    """
    function_info = get_function_info(r2, function_name)
    if function_info is None:
        raise FunctionNotFoundError(f"Could not get function information: {function_name}")

    function_offset = _get_function_offset(r2, function_name, function_info)
    if function_offset is None:
        raise FunctionNotFoundError(f"Could not get valid function information: {function_name}")

    return function_offset


def _fallback_to_r2ghidra(r2: IR2Client) -> str:
    """Fallback decompilation using r2ghidra."""
    logger.warning("Could not decompile with decai, trying with r2ghidra...")
    try:
        return r2.cmd("pdg")
    except (RuntimeError, ValueError, AttributeError) as e:
        raise DecompilationError(f"Error decompiling with decai: {e}") from e


def decompile_with_decai(r2: IR2Client, function_name: str) -> str:
    """
    Decompiles a function using the decai plugin from radare2.

    Args:
        r2: r2pipe instance.
        function_name: Name of the function to decompile.

    Returns:
        Decompiled code or error message.

    Raises:
        DecompilationError: If decompilation fails completely.
        FunctionNotFoundError: If the function cannot be found.
    """
    function_offset = _resolve_function_offset(r2, function_name)

    decai_check = r2.cmd("decai -h")
    if "Unknown command" in decai_check or "RCmd.Use()" in decai_check:
        logger.warning("The decai plugin is not available.")
        logger.info("Trying with r2ghidra decompiler as an alternative.")
        r2.cmd(f"s {function_offset}")
        return r2.cmd("pdg")

    r2.cmd(f"s {function_offset}")

    # sj returns a list (seek stack), find the current position
    current_pos = r2.cmdj("sj")
    if not current_pos:
        raise DecompilationError(f"Could not position at the function address: {function_name}")

    # Handle both list (seek stack) and dict formats
    if isinstance(current_pos, list):
        # Find the entry with "current": true, or use the last entry
        current_entry = next(
            (p for p in current_pos if p.get("current")),
            current_pos[-1] if current_pos else None
        )
        if not current_entry or "offset" not in current_entry:
            raise DecompilationError(f"Could not position at the function address: {function_name}")
    elif isinstance(current_pos, dict):
        if "offset" not in current_pos:
            raise DecompilationError(f"Could not position at the function address: {function_name}")
    else:
        raise DecompilationError(f"Could not position at the function address: {function_name}")

    logger.info(f"Decompiling {function_name} with decai...")
    _configure_decai_model(r2)

    try:
        result = _try_decai_decompilation(r2, function_name)
        if result:
            return result
    except (RuntimeError, ValueError) as e:
        logger.error(f"Error during decompilation with decai: {e}")
    except (DecompilationError, FunctionNotFoundError) as e:
        logger.error(f"Decompilation error with decai: {e}")

    return _fallback_to_r2ghidra(r2)


# =============================================================================
# DECAI DECOMPILER CLASS
# =============================================================================


class DecAIDecompiler(BaseR2Decompiler):
    """
    Specialized decompiler implementation using the decai plugin with AI models.

    The decai plugin uses AI models (via Ollama) to perform decompilation,
    requiring both the decai r2 plugin and a running Ollama service.

    This class extends BaseR2Decompiler but overrides the decompile method
    to use AI-based decompilation instead of a simple radare2 command.

    Thread Safety:
        This class is stateless and thread-safe.

    Example:
        >>> decompiler = DecAIDecompiler()
        >>> if decompiler.is_available(r2):
        ...     result = decompiler.decompile(r2, 'main')
        ...     if result.is_ok():
        ...         print(result.unwrap())
    """

    def __init__(self) -> None:
        """Initialize the DecAI decompiler."""
        # DecAI uses multiple commands internally, so we pass "decai -d" as the nominal command
        super().__init__(name=DecompilerType.DECAI.value, command="decai -d")

    def decompile(self, r2: IR2Client, function_name: str) -> str:
        """
        Decompile a function using AI-based decompilation via decai.

        Overrides the base class method to use multi-step AI-based decompilation
        instead of a simple radare2 command.

        Args:
            r2: An active r2pipe instance connected to the binary being analyzed.
            function_name: The name or address of the function to decompile.

        Returns:
            Decompiled pseudocode on success, empty string on failure.
        """
        try:
            return decompile_with_decai(r2, function_name)
        except (DecompilationError, FunctionNotFoundError) as e:
            logger.error(f"DecAI decompilation failed for {function_name}: {e}")
            return ""
        except (RuntimeError, ValueError) as e:
            # RuntimeError: r2 command execution failure
            # ValueError: Invalid decompilation result
            logger.error(
                f"Runtime error in DecAI decompilation for {function_name}: {e}"
            )
            return ""
        except (AttributeError, TypeError) as e:
            # AttributeError: r2 instance issues
            # TypeError: Unexpected data types
            logger.error(
                f"Data error in DecAI decompilation for {function_name}: {e}"
            )
            return ""

    def is_available(self, r2: IR2Client | None = None) -> bool:
        """
        Check if the decai plugin and Ollama service are available.

        Args:
            r2: An optional r2pipe instance (not used, included for interface compatibility).

        Returns:
            bool: True if decai and Ollama are available, False otherwise.
        """
        return check_decompiler_plugin_available(DecompilerType.DECAI)


__all__ = [
    "DecAIDecompiler",
    "decompile_with_decai",
]
