#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validators module for BannedFuncDetector - Input validation functions.
Author: Marc Rivero | @seifreed
"""

import os
import sys
import subprocess  # nosec B404
import logging
from typing import Any

from .adapters.r2_client import R2Client
from .config_repository import get_default_config
from ..domain.protocols import IConfigRepository
from ..constants import MIN_PYTHON_VERSION
from .decompilers.orchestrator import check_decompiler_available
from ..file_detection import is_executable_file

logger = logging.getLogger(__name__)

REQUIREMENTS = [
    {"name": "r2", "command": ["r2", "-v"], "expected": "radare2"},
    {
        "name": "r2pipe",
        "command": ["python", "-c", "import r2pipe; print('r2pipe installed')"],
        "expected": "r2pipe installed",
    },
]

DECOMPILER_TYPES = ["default", "r2ghidra", "r2dec", "decai"]


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
        result = subprocess.run(req['command'], capture_output=True, text=True)  # nosec B603

        if result.returncode != 0 or req['expected'] not in result.stdout:
            logger.error(f"Error: {req['name']} is not installed or not working properly.")
            logger.error(f"Output: {result.stdout}")
            if result.stderr:
                logger.error(f"Error: {result.stderr}")
            return False

        logger.info(f"{req['name']} is installed correctly.")
        return True
    except (subprocess.SubprocessError, OSError, IOError) as e:
        # SubprocessError: Command execution failed
        # OSError/IOError: File not found or system error
        logger.error(f"Error checking {req['name']}: {str(e)}")
        return False
    except (KeyError, TypeError) as e:
        # KeyError: Missing required fields in req dict
        # TypeError: Invalid data types
        logger.error(f"Configuration error checking {req['name']}: {str(e)}")
        return False


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


def check_requirements(
    skip_requirements: bool = True,
    config: IConfigRepository | None = None
) -> bool:
    """
    Verifies that all requirements to run the tool are met.

    Args:
        skip_requirements: If True, skips the requirements check.
        config: Configuration repository instance providing requirement settings.
            Reserved for future use when requirements may be configurable.
            If None, falls back to global config (deprecated pattern).

    Returns:
        bool: True if all requirements are met, False otherwise.
    """
    # config parameter reserved for future use
    if config is None:
        _ = get_default_config()
    else:
        _ = config

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
