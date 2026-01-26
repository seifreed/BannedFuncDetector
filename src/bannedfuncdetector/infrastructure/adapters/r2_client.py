#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
R2Client - r2pipe wrapper implementing IR2Client.

This module provides a concrete implementation of the IR2Client protocol,
wrapping r2pipe to facilitate dependency injection, testing, and abstraction
of the radare2 interface.

Author: Marc Rivero | @seifreed
"""

import logging
from collections.abc import Callable
from typing import Any

import r2pipe

from bannedfuncdetector.domain.protocols import IR2Client

logger = logging.getLogger(__name__)


class R2Client(IR2Client):
    """
    IR2Client implementation as r2pipe wrapper.

    Provides an abstraction over r2pipe to facilitate testing,
    dependency injection, and connection lifecycle management
    with radare2.

    This class follows the IR2Client protocol defined in protocols.py,
    allowing it to be interchangeable with other implementations
    (such as MockR2Client for testing).

    Attributes:
        _r2: Internal r2pipe instance.
        _file_path: Path to the analyzed binary file.
        _is_closed: Flag indicating if the connection has been closed.

    Thread Safety:
        r2pipe instances are NOT thread-safe. Each thread must
        maintain its own R2Client instance.

    Examples:
        Basic usage:
        >>> client = R2Client("/path/to/binary")
        >>> client.cmd("aaa")  # Analyze all
        >>> functions = client.cmdj("aflj")  # Get functions as JSON
        >>> print(f"Found {len(functions)} functions")
        >>> client.quit()

        As context manager (recommended):
        >>> with R2Client.open("/path/to/binary") as client:
        ...     client.cmd("aaa")
        ...     functions = client.cmdj("aflj")
        ...     for func in functions:
        ...         print(func['name'])

        With custom flags:
        >>> with R2Client.open("/bin/ls", flags=["-2", "-A"]) as client:
        ...     info = client.cmdj("ij")
    """

    def __init__(self, file_path: str, flags: list[str] | None = None) -> None:
        """
        Initialize a new r2pipe connection to the specified binary.

        Args:
            file_path: Absolute or relative path to the binary file to analyze.
                      Must be a valid executable (PE, ELF, Mach-O).
            flags: Optional list of radare2 flags. Defaults to ["-2"]
                  to disable radare2 sandbox.
                  Common flags:
                  - "-2": Disable sandbox
                  - "-A": Full automatic analysis on open
                  - "-w": Open in write mode
                  - "-d": Open in debug mode

        Raises:
            FileNotFoundError: If the file does not exist.
            r2pipe.OpenError: If radare2 cannot open the file.

        Notes:
            - The connection remains open until quit() is called
            - The "-2" flag disables sandbox for better compatibility
            - No automatic analysis is performed; call "aaa" explicitly
        """
        if flags is None:
            flags = ["-2"]

        self._file_path = file_path
        self._is_closed = False

        try:
            self._r2 = r2pipe.open(file_path, flags=flags)
            logger.debug(f"Opened r2pipe connection to {file_path} with flags {flags}")
        except (OSError, IOError) as e:
            # File not found or cannot be opened
            logger.error(f"Failed to open file for r2pipe {file_path}: {e}")
            raise
        except (RuntimeError, ValueError) as e:
            # r2pipe connection or initialization failure
            logger.error(f"Failed to initialize r2pipe for {file_path}: {e}")
            raise

    def cmd(self, command: str) -> str:
        """
        Execute a radare2 command and return the result as string.

        Implements the cmd() method of the IR2Client protocol. This is the
        basic method for executing radare2 commands and getting text output.

        Args:
            command: Radare2 command to execute. Can be any valid
                    radare2 command (e.g., 'aaa', 'pdf @ main', 'ii').

        Returns:
            str: Command output as string. May be empty for commands
                 without output. Output may contain r2 error messages.

        Raises:
            RuntimeError: If attempting to use a closed connection.

        Notes:
            - For structured output, prefer cmdj() when possible
            - Commands may modify radare2's internal state
            - No automatic error handling; check the output

        Examples:
            >>> client.cmd("aaa")  # Analyze all - no output
            ''
            >>> client.cmd("i")  # Binary info
            'file     /bin/ls\\nformat   elf64\\n...'
            >>> disasm = client.cmd("pdf @ main")
            >>> print(disasm)
        """
        result: str = self._run_command(command, self._r2.cmd, "command")
        return result

    def cmdj(self, command: str) -> Any:
        """
        Execute a radare2 command and return the result parsed as JSON.

        Implements the cmdj() method of the IR2Client protocol. This method is
        preferable when extracting structured data from radare2.

        Args:
            command: Radare2 command to execute, typically with 'j' suffix
                    for JSON output (e.g., 'aflj', 'iij', 'pdj').

        Returns:
            Any: Parsed JSON structure. Can be:
                 - dict: For commands like 'ij' (info)
                 - list: For commands like 'aflj' (functions)
                 - primitives: For simple values
                 - None: If output is not valid JSON

        Raises:
            RuntimeError: If attempting to use a closed connection.

        Notes:
            - Most r2 commands support JSON with 'j' suffix
            - Parsing errors return None without raising exception
            - More efficient than manually parsing cmd() output

        Examples:
            >>> functions = client.cmdj("aflj")
            >>> print(type(functions))
            <class 'list'>
            >>> for func in functions:
            ...     print(f"{func['name']} @ {hex(func['offset'])}")

            >>> info = client.cmdj("ij")
            >>> print(info['bin']['arch'])
            'x86'
        """
        return self._run_command(command, self._r2.cmdj, "JSON command")

    def quit(self) -> None:
        """
        Close the r2pipe connection and release resources.

        Implements the quit() method of the IR2Client protocol. Should be called
        when analysis is complete to release system resources.

        Notes:
            - This method is idempotent (can be called multiple times)
            - After quit(), the instance should not be used
            - Called automatically when exiting context manager
            - Handles cleanup even if errors occurred during use

        Examples:
            >>> client = R2Client("/path/to/binary")
            >>> try:
            ...     client.cmd("aaa")
            ... finally:
            ...     client.quit()  # Always clean up resources
        """
        if self._is_closed:
            logger.debug(f"Connection to {self._file_path} already closed")
            return

        if self._r2 is not None:
            try:
                self._r2.quit()
                logger.debug(f"Closed r2pipe connection to {self._file_path}")
            except (RuntimeError, OSError, IOError, AttributeError) as e:
                # RuntimeError: r2pipe internal errors during shutdown
                # OSError/IOError: System-level errors during cleanup
                # AttributeError: r2pipe in invalid state
                logger.warning(f"Error closing r2pipe connection: {e}")
            finally:
                self._r2 = None
                self._is_closed = True

    @classmethod
    def open(cls, file_path: str, flags: list[str] | None = None) -> "R2Client":
        """
        Factory method to create an R2Client instance.

        This alternative construction method facilitates usage as a
        context manager and provides a more fluent interface.

        Args:
            file_path: Path to the binary file to analyze.
            flags: Optional list of radare2 flags.

        Returns:
            R2Client: New instance connected to the binary.

        Raises:
            FileNotFoundError: If the file does not exist.
            r2pipe.OpenError: If radare2 cannot open the file.

        Examples:
            >>> client = R2Client.open("/bin/ls")
            >>> # ... use client ...
            >>> client.quit()

            >>> with R2Client.open("/bin/ls") as client:
            ...     client.cmd("aaa")
        """
        return cls(file_path, flags)

    def __enter__(self) -> "R2Client":
        """
        Context manager support - entry.

        Returns:
            R2Client: The current instance for use in the with block.

        Examples:
            >>> with R2Client.open("/bin/ls") as client:
            ...     functions = client.cmdj("aflj")
        """
        return self

    def __exit__(self, *_args: Any) -> None:
        """
        Context manager support - exit.

        Ensures quit() is called automatically when exiting the with block,
        even if an exception occurs.
        """
        self.quit()

    def _ensure_open(self) -> None:
        """
        Verify the connection is open before executing commands.

        Raises:
            RuntimeError: If the connection has been closed with quit().
        """
        if self._is_closed or self._r2 is None:
            raise RuntimeError(
                f"Cannot execute command on closed R2Client for {self._file_path}. "
                "The connection was closed with quit()."
            )

    def _run_command[T](self, command: str, runner: Callable[[str], T], label: str) -> T:
        """
        Execute a radare2 command through the provided runner.

        Raises:
            RuntimeError: If the r2pipe command execution fails.
            ValueError: If the command produces invalid output.
            OSError: If there's a system-level error during execution.
        """
        self._ensure_open()

        try:
            result = runner(command)
            logger.debug(f"Executed {label}: {command}")
            return result
        except (RuntimeError, ValueError, OSError) as e:
            logger.error(f"Error executing {label} '{command}': {e}")
            raise
        except TypeError as e:
            # TypeError can occur with invalid command arguments
            logger.error(f"Type error executing {label} '{command}': {e}")
            raise RuntimeError(f"Invalid command or arguments: {e}") from e
        except AttributeError as e:
            # AttributeError can occur if r2pipe is in an invalid state
            logger.error(f"Attribute error executing {label} '{command}': {e}")
            raise RuntimeError(f"r2pipe in invalid state: {e}") from e

    def __repr__(self) -> str:
        """
        String representation of the instance for debugging.

        Returns:
            str: Human-readable representation of the instance.
        """
        status = "closed" if self._is_closed else "open"
        return f"R2Client(file_path='{self._file_path}', status='{status}')"
