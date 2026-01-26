#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Protocol Abstractions

Protocol interfaces enabling type-safe dependency injection and clearer
architectural boundaries between components.

This module defines only the protocols that are essential for:
1. Multiple implementations (IDecompiler)
2. Testing with mocks (IR2Client, IConfigRepository)

Author: Marc Rivero | @seifreed
"""

from typing import Any, Protocol, runtime_checkable, TYPE_CHECKING

if TYPE_CHECKING:
    from bannedfuncdetector.domain.result import Result


@runtime_checkable
class IDecompiler(Protocol):
    """
    Protocol for binary decompiler implementations.

    Converts compiled binary code back into human-readable pseudocode.
    Implementations: R2GhidraDecompiler, R2DecDecompiler, DecAIDecompiler, DefaultDecompiler.
    """

    def decompile(self, r2: Any, function_name: str) -> str:
        """
        Decompile a function from a binary to pseudocode.

        Args:
            r2: An active r2pipe instance connected to the binary.
            function_name: Function name or hex address to decompile.

        Returns:
            Decompiled pseudocode as string. Returns error message on failure.
        """
        ...

    def is_available(self, r2: Any) -> bool:
        """
        Check if this decompiler is available and functional.

        Args:
            r2: An r2pipe instance for checking availability.

        Returns:
            True if decompiler is ready to use, False otherwise.
        """
        ...

    def get_name(self) -> str:
        """
        Get the decompiler name (e.g., 'r2ghidra', 'r2dec', 'decai', 'default').
        """
        ...


@runtime_checkable
class IR2Client(Protocol):
    """
    Protocol for r2pipe client abstraction.

    Abstracts the r2pipe interface for easier testing with mock implementations.
    Note: r2pipe instances are NOT thread-safe.
    """

    def cmd(self, command: str) -> str:
        """
        Execute a radare2 command and return output as string.

        Args:
            command: The radare2 command to execute (e.g., 'aaa', 'aflj').

        Returns:
            Command output as string.
        """
        ...

    def cmdj(self, command: str) -> Any:
        """
        Execute a radare2 command and return parsed JSON output.

        Args:
            command: The radare2 command (typically ending with 'j').

        Returns:
            Parsed JSON structure, or None if parsing fails.
        """
        ...

    def quit(self) -> None:
        """Close the r2pipe connection and cleanup resources."""
        ...

    def __enter__(self) -> "IR2Client":
        """Enter context manager."""
        ...

    def __exit__(
        self,
        exc_type: type | None,
        exc_val: BaseException | None,
        exc_tb: Any | None
    ) -> None:
        """Exit context manager, ensuring cleanup."""
        ...


@runtime_checkable
class IConfigRepository(Protocol):
    """
    Protocol for configuration access.

    Provides type-safe access to application settings.
    Implementations must be thread-safe for concurrent read access.
    """

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by key.

        Args:
            key: The configuration key (e.g., 'output', 'decompiler').
            default: Default value if key is not found.

        Returns:
            The configuration value (deep copy for mutable types).
        """
        ...

    def __getitem__(self, key: str) -> Any:
        """
        Get configuration value using bracket notation.

        Raises:
            KeyError: If the key is not found.
        """
        ...

    def get_output_dir(self) -> str:
        """Get the configured output directory path."""
        ...


@runtime_checkable
class IDecompilerOrchestrator(Protocol):
    """
    Protocol for decompilation orchestration.

    Defines the interface for coordinating decompiler selection and execution.
    This protocol abstracts the complexity of managing multiple decompiler backends
    (r2ghidra, r2dec, decai, default) and provides a unified interface for:

    1. Decompiling functions with automatic decompiler selection
    2. Selecting appropriate decompilers based on availability and preferences
    3. Checking decompiler availability at runtime

    Implementations should handle:
    - Decompiler fallback chains when preferred decompiler is unavailable
    - Configuration-driven decompiler selection
    - Thread-safe decompilation operations (note: r2pipe instances are NOT thread-safe)

    Example usage:
        >>> orchestrator: IDecompilerOrchestrator = get_orchestrator()
        >>> # Select best available decompiler
        >>> decompiler = orchestrator.select_decompiler(requested='r2ghidra')
        >>> # Check availability before use
        >>> if orchestrator.check_decompiler_available('r2ghidra'):
        ...     result = orchestrator.decompile_function(r2, 'main', 'r2ghidra')
        ...     if result.is_ok():
        ...         print(result.unwrap())

    See Also:
        - IDecompiler: Protocol for individual decompiler implementations
        - IR2Client: Protocol for r2pipe client abstraction
    """

    def decompile_function(
        self,
        r2: "IR2Client",
        function_name: str,
        decompiler_type: str | None = None,
        **options: Any
    ) -> "Result[str, str]":
        """
        Decompile a function using the configured decompiler.

        This is the primary entry point for function decompilation. It handles
        decompiler selection (if not specified), configuration lookup, and
        delegates to the appropriate decompiler backend.

        Args:
            r2: An active r2pipe client instance connected to the binary.
                The binary should have been analyzed (aaa command) before calling.
            function_name: Name or hex address of the function to decompile.
                Examples: 'main', 'sym.imp.strcpy', '0x00401000'
            decompiler_type: Optional decompiler to use. If None, uses the
                configured default or selects automatically based on availability.
                Valid values: 'r2ghidra', 'r2dec', 'decai', 'default', None
            **options: Additional decompiler-specific options passed to the
                underlying decompiler. Common options include:
                - clean_error_messages (bool): Strip error messages from output
                - use_alternative (bool): Use alternative decompiler on failure
                - fallback_to_asm (bool): Fall back to assembly if decompilation fails

        Returns:
            Result[str, str]: Ok containing the decompiled pseudocode on success,
                or Err containing an error message on failure.

        Raises:
            No exceptions are raised; all errors are returned as Result.Err.

        Example:
            >>> result = orchestrator.decompile_function(r2, 'main', 'r2ghidra')
            >>> match result:
            ...     case Ok(code):
            ...         print(f"Decompiled: {code[:100]}...")
            ...     case Err(error):
            ...         print(f"Failed: {error}")
        """
        ...

    def select_decompiler(
        self,
        requested: str | None = None,
        force: bool = False
    ) -> str:
        """
        Select appropriate decompiler based on availability.

        Implements decompiler selection logic with fallback chains. If the
        requested decompiler is unavailable, automatically selects the best
        available alternative.

        The fallback priority order is:
        1. r2ghidra (most comprehensive, production-quality Ghidra integration)
        2. r2dec (lighter weight, good compatibility)
        3. default (pdc - always available fallback, basic functionality)

        Args:
            requested: The preferred decompiler type to use. If None, uses
                the configured default from config.json. Valid values:
                'r2ghidra', 'r2dec', 'decai', 'default', None
            force: If True, returns the requested decompiler without checking
                availability. Use with caution as this may cause decompilation
                failures if the decompiler is not installed.

        Returns:
            str: The selected decompiler type name (e.g., 'r2ghidra', 'default').
                Always returns a valid decompiler name; defaults to 'default'
                if no other decompiler is available.

        Example:
            >>> # Let orchestrator choose best available
            >>> decompiler = orchestrator.select_decompiler()
            >>> # Request specific decompiler with fallback
            >>> decompiler = orchestrator.select_decompiler('r2ghidra')
            >>> # Force specific decompiler (no availability check)
            >>> decompiler = orchestrator.select_decompiler('r2ghidra', force=True)
        """
        ...

    def check_decompiler_available(self, decompiler_type: str) -> bool:
        """
        Check if a decompiler is available.

        Performs runtime availability checking for the specified decompiler.
        This includes checking for:
        - Plugin installation (r2ghidra, r2dec)
        - External service availability (decai requires Ollama)
        - Basic functionality validation

        Args:
            decompiler_type: The decompiler type to check. Valid values:
                'r2ghidra', 'r2dec', 'decai', 'default'

        Returns:
            bool: True if the decompiler is installed and functional,
                False otherwise. The 'default' decompiler always returns True
                as it uses radare2's built-in pdc command.

        Note:
            Availability checks may involve executing radare2 commands or
            network requests (for decai/Ollama), so they have some overhead.
            Consider caching results if checking repeatedly.

        Example:
            >>> if orchestrator.check_decompiler_available('r2ghidra'):
            ...     print("r2ghidra plugin is installed")
            ... else:
            ...     print("r2ghidra not available, using fallback")
        """
        ...


__all__ = [
    'IDecompiler',
    'IR2Client',
    'IConfigRepository',
    'IDecompilerOrchestrator',
]
