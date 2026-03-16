#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validators module for BannedFuncDetector - Input validation functions.
Author: Marc Rivero | @seifreed
"""

import os
import asyncio
import shutil
import sys
import logging
from dataclasses import dataclass
from typing import Any
from collections.abc import Sequence, Callable

from .adapters.r2_client import R2Client
from ..constants import MIN_PYTHON_VERSION
from .decompilers.orchestrator import check_decompiler_available
from .file_detection import is_executable_file

logger = logging.getLogger(__name__)

ALLOWED_REQUIREMENT_EXECUTABLES = frozenset({"r2", "python"})

REQUIREMENTS = [
    {"name": "r2", "command": ["r2", "-v"], "expected": "radare2"},
    {
        "name": "r2pipe",
        "command": ["python", "-c", "import r2pipe; print('r2pipe installed')"],
        "expected": "r2pipe installed",
    },
]

DECOMPILER_TYPES = ["default", "r2ghidra", "r2dec", "decai"]


@dataclass(frozen=True)
class _CommandResult:
    """Lightweight result object for command execution."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


def _normalize_command(command: Sequence[str]) -> list[str]:
    """Resolve the executable and return a validated command list."""
    if not command:
        raise ValueError("Command cannot be empty")
    executable = shutil.which(command[0])
    if executable is None:
        raise FileNotFoundError(f"Executable not found: {command[0]}")
    return [executable, *command[1:]]


async def _run_command_async(command: Sequence[str]) -> _CommandResult:
    resolved = _normalize_command(command)
    process = await asyncio.create_subprocess_exec(
        *resolved,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await process.communicate()
    stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
    stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
    return _CommandResult(
        returncode=process.returncode if process.returncode is not None else 0,
        stdout=stdout,
        stderr=stderr,
    )


def _run_async_command(command: Sequence[str]) -> _CommandResult:
    """Run a command through asyncio without shell."""
    return asyncio.run(_run_command_async(command))


def check_python_version() -> None:
    """Ensure the runtime Python version meets the minimum requirement."""
    if sys.version_info < MIN_PYTHON_VERSION:
        current = ".".join(str(part) for part in sys.version_info[:3])
        required = ".".join(str(part) for part in MIN_PYTHON_VERSION)
        logger.error(f"Python {required}+ is required. Detected Python {current}.")
        sys.exit(1)


def _check_single_requirement(req: dict[str, Any]) -> bool:
    """
    Check a single requirement.

    Args:
        req: Dictionary with 'name', 'command', and 'expected' keys.

    Returns:
        bool: True if requirement is met, False otherwise.
    """
    try:
        logger.info(f"Checking {req['name']}...")
        command = req['command']
        if not command or command[0] not in ALLOWED_REQUIREMENT_EXECUTABLES:
            logger.error(f"Blocked unrecognized command: {command}")
            return False
        result = _run_command(command)

        if result.returncode != 0 or req['expected'] not in result.stdout:
            logger.error(f"Error: {req['name']} is not installed or not working properly.")
            logger.error(f"Output: {result.stdout}")
            if result.stderr:
                logger.error(f"Error: {result.stderr}")
            return False

        logger.info(f"{req['name']} is installed correctly.")
        return True
    except (OSError, IOError, RuntimeError) as e:
        # OSError/IOError: File not found or system error
        # RuntimeError: command runner reported non-zero return code check failure
        logger.error(f"Error checking {req['name']}: {str(e)}")
        return False
    except (KeyError, TypeError) as e:
        # KeyError: Missing required fields in req dict
        # TypeError: Invalid data types
        logger.error(f"Configuration error checking {req['name']}: {str(e)}")
        return False


def _run_command(
    command: Sequence[str],
    *,
    run_fn: Callable[[Sequence[str]], _CommandResult] = _run_async_command,
) -> _CommandResult:
    """
    Execute a validated local command with safe defaults.

    The command is validated against an allowlist before execution, and executed
    without shell expansion.
    """
    resolved = list(command)
    if not resolved or resolved[0] not in ALLOWED_REQUIREMENT_EXECUTABLES:
        raise ValueError(f"Blocked unrecognized command: {resolved}")
    return run_fn(resolved)


def _check_available_decompilers() -> None:
    """Check which decompilers are available on the system."""
    logger.info("Checking available decompilers...")

    temp_binary = "/bin/ls"
    if not os.path.exists(temp_binary):
        logger.warning(f"Could not find a binary to check decompilers: {temp_binary}")
        return

    try:
        with R2Client.open(temp_binary):
            available_decompilers = [
                decompiler
                for decompiler in DECOMPILER_TYPES
                if check_decompiler_available(decompiler, print_message=False)
            ]

            for decompiler in available_decompilers:
                logger.info(f"Decompiler {decompiler} is available.")

            for decompiler in [d for d in DECOMPILER_TYPES if d not in available_decompilers]:
                logger.warning(f"Decompiler {decompiler} is not available.")

            if not available_decompilers:
                logger.warning("Warning: No decompilers found.")
                logger.warning("Analysis will be limited to searching for banned functions by name.")

    except (RuntimeError, ValueError, OSError, IOError) as e:
        # RuntimeError: r2pipe execution failure
        # ValueError: Invalid decompiler data
        # OSError/IOError: File system errors
        logger.error(f"Error checking decompilers: {str(e)}")
    except (AttributeError, TypeError) as e:
        # AttributeError: r2 client issues
        # TypeError: Invalid data types
        logger.error(f"Data error checking decompilers: {str(e)}")


def check_requirements(skip_requirements: bool = True) -> bool:
    """
    Verifies that all requirements to run the tool are met.

    Args:
        skip_requirements: If True, skips the requirements check.

    Returns:
        bool: True if all requirements are met, False otherwise.
    """
    if skip_requirements:
        return True

    all_requirements_met = all(_check_single_requirement(req) for req in REQUIREMENTS)

    try:
        _check_available_decompilers()
    except ImportError:
        logger.warning("Could not import decompilers module to check decompilers.")

    return all_requirements_met


def validate_binary_file(file_path: str) -> bool:
    """
    Validates that a file exists and is a valid binary.

    Args:
        file_path: Path to the file to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    if not os.path.exists(file_path):
        logger.error(f"File {file_path} does not exist.")
        return False

    if not is_executable_file(file_path, "any"):
        logger.error(f"File {file_path} is not a valid binary.")
        return False

    return True
