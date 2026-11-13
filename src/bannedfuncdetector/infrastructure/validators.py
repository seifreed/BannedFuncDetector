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

# Cap requirement-check subprocesses so a hung tool (e.g. r2 blocked on I/O)
# cannot freeze the CLI; asyncio communicate() has no deadline of its own.
_COMMAND_TIMEOUT_SECONDS = 30.0

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


async def _run_command_async(
    command: Sequence[str], *, timeout: float = _COMMAND_TIMEOUT_SECONDS
) -> _CommandResult:
    resolved = _normalize_command(command)
    process = await asyncio.create_subprocess_exec(
        *resolved,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )
    except (asyncio.TimeoutError, TimeoutError):
        # A hung requirement check must not freeze the tool: terminate it and
        # report a failed command instead of blocking forever.
        logger.error(
            "Requirement command timed out after %ss",
            timeout,
            extra={
                "operation": "requirement_check",
                "event_name": "requirement_command_timeout",
                "duration_ms": round(timeout * 1000, 2),
                "outcome": "timeout",
                "error_type": "TimeoutError",
            },
        )
        process.kill()
        await process.wait()
        return _CommandResult(returncode=1, stdout="", stderr="timeout")
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
        logger.error(
            "Python %s+ is required. Detected Python %s.",
            required,
            current,
            extra={
                "operation": "runtime_validation",
                "event_name": "python_version_unsupported",
                "outcome": "error",
                "error_code": 1,
            },
        )
        sys.exit(1)


def _check_single_requirement(req: dict[str, Any]) -> bool:
    """
    Check a single requirement.

    Args:
        req: Dictionary with 'name', 'command', and 'expected' keys.

    Returns:
        bool: True if requirement is met, False otherwise.
    """
    name = str(req.get("name", "unknown"))
    try:
        logger.info("Checking %s...", name)
        command = req["command"]
        if not command or command[0] not in ALLOWED_REQUIREMENT_EXECUTABLES:
            logger.error(
                "Blocked unrecognized requirement command",
                extra={
                    "operation": "requirement_check",
                    "event_name": "requirement_command_blocked",
                    "outcome": "blocked",
                    "error_type": "ValueError",
                },
            )
            return False
        result = _run_command(command)

        if result.returncode != 0 or req["expected"] not in result.stdout:
            failure_extra: dict[str, object] = {
                "operation": "requirement_check",
                "event_name": "requirement_check_failed",
                "outcome": "error",
            }
            if result.returncode != 0:
                failure_extra["error_code"] = result.returncode
            logger.error(
                "Requirement check failed for %s (exit_code=%s, output_matched=%s)",
                name,
                result.returncode,
                req["expected"] in result.stdout,
                extra=failure_extra,
            )
            return False

        logger.info("%s is installed correctly.", name)
        return True
    except (OSError, IOError, RuntimeError) as e:
        # OSError/IOError: File not found or system error
        # RuntimeError: command runner reported non-zero return code check failure
        command_extra: dict[str, object] = {
            "operation": "requirement_check",
            "event_name": "requirement_command_failed",
            "outcome": "error",
            "error_type": type(e).__name__,
        }
        if isinstance(e, OSError) and e.errno is not None:
            command_extra["error_code"] = e.errno
        logger.error("Requirement command failed for %s", name, extra=command_extra)
        return False
    except (KeyError, TypeError) as e:
        # KeyError: Missing required fields in req dict
        # TypeError: Invalid data types
        logger.error(
            "Invalid configuration for requirement %s",
            name,
            extra={
                "operation": "requirement_check",
                "event_name": "requirement_configuration_error",
                "outcome": "error",
                "error_type": type(e).__name__,
            },
        )
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
        raise ValueError("Blocked unrecognized command")
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

            for decompiler in [
                d for d in DECOMPILER_TYPES if d not in available_decompilers
            ]:
                logger.warning(f"Decompiler {decompiler} is not available.")

            if not available_decompilers:
                logger.warning("Warning: No decompilers found.")
                logger.warning(
                    "Analysis will be limited to searching for banned functions by name."
                )

    except (RuntimeError, ValueError, OSError, IOError) as e:
        # RuntimeError: r2pipe execution failure
        # ValueError: Invalid decompiler data
        # OSError/IOError: File system errors
        logger.error(f"Error checking decompilers: {str(e)}")
    except (AttributeError, TypeError) as e:
        # AttributeError: r2 client issues
        # TypeError: Invalid data types
        logger.error(f"Data error checking decompilers: {str(e)}")


def _check_file_type_detection() -> None:
    """Report whether libmagic is available for file-type detection.

    Its absence is otherwise a silent degradation: detection still runs but
    falls back to magic-byte sniffing, which is weaker on packed binaries.
    """
    from .file_detection import is_magic_available

    if is_magic_available():
        logger.info("python-magic (libmagic) is available for file-type detection.")
    else:
        logger.warning(
            "python-magic/libmagic is not available; file-type detection falls "
            "back to magic-byte sniffing, which is less reliable for packed or "
            "obfuscated binaries."
        )


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

    _check_file_type_detection()

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
