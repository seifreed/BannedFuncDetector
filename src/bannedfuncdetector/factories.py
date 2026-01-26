#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Factory Implementations

This module provides factory implementations for creating core components
with proper dependency injection. Factories encapsulate object creation
logic and enable easy testing through mock substitution.

The factory pattern is used here to:
1. Centralize object creation logic
2. Enable dependency injection in classes that need to create objects
3. Facilitate testing by allowing mock factory injection
4. Decouple client code from concrete implementations

Dependency Injection Pattern:
    Configuration should be created at application entry points using
    :func:`create_config_from_file` or :func:`create_config_from_dict`
    and passed explicitly to all components that need it.

Author: Marc Rivero | @seifreed
License: GNU General Public License v3 (GPLv3)
"""

import copy
import logging
from typing import TYPE_CHECKING, Any

from .domain.protocols import IR2Client, IConfigRepository
from collections.abc import Callable, KeysView
from .infrastructure.adapters.r2_client import R2Client

if TYPE_CHECKING:
    from .application.binary_analyzer import R2BinaryAnalyzer

logger = logging.getLogger(__name__)


# =============================================================================
# DICTIONARY-BASED CONFIG (for testing and programmatic use)
# =============================================================================


class DictConfig:
    """
    Simple dictionary-based configuration implementing IConfigRepository.

    This class provides an isolated configuration instance that does NOT
    share state with the global singleton. Ideal for testing and scenarios
    requiring independent configuration.

    Attributes:
        _config: Internal dictionary storing configuration values.

    Example:
        >>> config = DictConfig({
        ...     "decompiler": {"type": "r2ghidra"},
        ...     "output": {"directory": "/tmp/output"}
        ... })
        >>> config.get("decompiler")["type"]
        'r2ghidra'
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize with configuration dictionary.

        Args:
            config: Configuration dictionary. If None, uses empty dict.
                    For production use, merge with DEFAULT_CONFIG first.
        """
        self._config: dict[str, Any] = copy.deepcopy(config) if config else {}

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key."""
        value = self._config.get(key, default)
        if isinstance(value, (dict, list)):
            return copy.deepcopy(value)
        return value

    def __getitem__(self, key: str) -> Any:
        """Get configuration value using bracket notation."""
        value = self._config[key]
        if isinstance(value, (dict, list)):
            return copy.deepcopy(value)
        return value

    def __contains__(self, key: str) -> bool:
        """Check if a key exists in configuration."""
        return key in self._config

    def get_output_dir(self) -> str:
        """Get the configured output directory path."""
        output = self._config.get("output", {})
        if isinstance(output, dict):
            directory = output.get("directory", "output")
            return str(directory) if directory is not None else "output"
        return "output"

    def keys(self) -> KeysView[str]:
        """Return configuration keys."""
        return self._config.keys()

    def items(self) -> list[tuple[str, Any]]:
        """Return configuration items (copies of values)."""
        return [
            (k, copy.deepcopy(v) if isinstance(v, (dict, list)) else v)
            for k, v in self._config.items()
        ]

    def to_dict(self) -> dict[str, Any]:
        """Return a deep copy of the entire configuration."""
        return copy.deepcopy(self._config)


# =============================================================================
# R2 CLIENT FACTORY FUNCTION
# =============================================================================

# Default flags for r2pipe connections
DEFAULT_R2_FLAGS: list[str] = ["-2"]  # -2 disables sandbox


def create_r2_client(
    file_path: str,
    flags: list[str] | None = None
) -> IR2Client:
    """
    Factory function for creating R2Client instances.

    Creates real R2Client instances connected to binary files. This function
    can be used directly or passed as a factory to classes that need to
    create R2 connections.

    Args:
        file_path: Path to the binary file to open.
        flags: Optional list of radare2 flags. If None, uses DEFAULT_R2_FLAGS.

    Returns:
        IR2Client: A new client instance connected to the binary.

    Raises:
        FileNotFoundError: If the binary file does not exist.
        RuntimeError: If r2pipe fails to open the binary.

    Thread Safety:
        This function is thread-safe. Each call returns a new independent
        R2Client instance.

    Example:
        >>> with create_r2_client("/path/to/binary") as client:
        ...     client.cmd("aaa")
        ...     functions = client.cmdj("aflj")
        ...     print(f"Found {len(functions)} functions")
    """
    effective_flags = flags if flags is not None else DEFAULT_R2_FLAGS
    logger.debug(f"Creating R2Client for {file_path} with flags {effective_flags}")
    return R2Client.open(file_path, flags=effective_flags)


# =============================================================================
# BINARY ANALYZER FACTORY
# =============================================================================


def create_binary_analyzer(
    config: IConfigRepository,
    decompiler_type: str = "default",
    verbose: bool = False,
    r2_factory: Callable[[str], IR2Client] | None = None
) -> "R2BinaryAnalyzer":
    """
    Factory function for creating R2BinaryAnalyzer instances.

    This factory function constructs an R2BinaryAnalyzer with all its
    dependencies explicitly injected. It eliminates the need for the
    analyzer to access the global CONFIG singleton.

    Args:
        config: Configuration repository providing access to settings.
                This is a required parameter - no fallback to global CONFIG.
        decompiler_type: The type of decompiler to use for analysis.
                        Valid options: 'default', 'r2ghidra', 'r2dec', 'decai'.
        verbose: If True, enables detailed logging output during analysis.
        r2_factory: Factory for creating R2Client instances. If None,
                   uses DefaultR2ClientFactory.

    Returns:
        R2BinaryAnalyzer: A configured analyzer instance ready for use.

    Example:
        >>> from bannedfuncdetector.infrastructure.config_repository import ImmutableConfig
        >>> config = ImmutableConfig()
        >>> analyzer = create_binary_analyzer(
        ...     config=config,
        ...     decompiler_type="r2ghidra",
        ...     verbose=True
        ... )
        >>> result = analyzer.analyze("/path/to/binary")
        >>> print(f"Found {result.insecure_count} banned functions")

    Note:
        The config parameter is required (not optional) to encourage
        explicit dependency injection rather than relying on globals.
    """
    from .application.binary_analyzer import R2BinaryAnalyzer

    # Use provided factory or default function
    effective_factory = r2_factory if r2_factory is not None else create_r2_client

    return R2BinaryAnalyzer(
        decompiler_type=decompiler_type,
        verbose=verbose,
        r2_factory=effective_factory,
        config=config
    )


# =============================================================================
# CONFIGURATION FACTORY
# =============================================================================


def create_config_from_file(config_path: str | None = None) -> IConfigRepository:
    """
    Factory function for creating a configuration instance from a file.

    This function creates and returns a configured ImmutableConfig instance.
    It's the recommended way to obtain configuration at application entry points.

    Args:
        config_path: Path to the configuration file. If None, searches
                    standard locations for config.json.

    Returns:
        IConfigRepository: A configured configuration instance.

    Example:
        >>> config = create_config_from_file("custom_config.json")
        >>> analyzer = create_binary_analyzer(config=config)

    Note:
        This function always returns a new ImmutableConfig instance that
        shares state with the global singleton. For completely isolated
        configuration, use AppConfig.from_dict() directly.
    """
    from .infrastructure.config_repository import load_config, ImmutableConfig

    if config_path:
        load_config(config_path)
    else:
        load_config()

    return ImmutableConfig()


def create_config_from_dict(
    config_dict: dict,
    use_singleton: bool = False
) -> IConfigRepository:
    """
    Factory function for creating a configuration instance from a dictionary.

    This function creates a configuration instance from a provided dictionary,
    useful for testing or programmatic configuration.

    Args:
        config_dict: Dictionary containing configuration values. Will be
                    merged with defaults for any missing keys.
        use_singleton: If True, updates the global singleton (deprecated).
                      If False (default), returns an isolated DictConfig instance.

    Returns:
        IConfigRepository: A configured configuration instance.

    Example:
        >>> config = create_config_from_dict({
        ...     "banned_functions": ["strcpy", "gets"],
        ...     "decompiler": {"type": "r2ghidra"}
        ... })
        >>> analyzer = create_binary_analyzer(config=config)

    Note:
        By default, this function returns a DictConfig instance that does NOT
        share state with the global singleton. This is the recommended pattern
        for testing. Set use_singleton=True only for backward compatibility.
    """
    from .infrastructure.config_repository import deep_merge, DEFAULT_CONFIG

    # Merge with defaults
    merged = deep_merge(DEFAULT_CONFIG, config_dict)

    if use_singleton:
        # Deprecated: Update the global singleton
        from .infrastructure.config_repository import ImmutableConfig
        instance = ImmutableConfig()
        instance._update_internal(merged)
        return instance

    # Preferred: Return isolated DictConfig instance
    return DictConfig(merged)




__all__ = [
    # Configuration Classes
    'DictConfig',
    # R2 Client Factory
    'DEFAULT_R2_FLAGS',
    'create_r2_client',
    # Binary Analyzer Factory
    'create_binary_analyzer',
    # Configuration Factories
    'create_config_from_file',
    'create_config_from_dict',
]
