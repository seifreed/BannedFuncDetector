#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Tool for detecting banned functions in binary files
Author: Marc Rivero | @seifreed

This module serves as the main orchestrator, delegating to specialized modules:
- cli.py: Command line argument parsing
- validators.py: Input validation and requirements checking
- reporting.py: Report generation and display
- factories.py: Dependency injection factories

Dependency Injection Pattern:
    Configuration is loaded once at the entry point (main()) and passed
    explicitly to all components that need it. This enables:
    - Testability: Components can be tested with mock configurations
    - Clarity: Dependencies are visible in function signatures
    - Flexibility: Different configurations for different contexts
"""

import os
import sys
import logging
from typing import Any

from .domain.result import Ok

# Import from new modules
from .cli import parse_arguments
from .infrastructure.validators import check_python_version, check_requirements
from .presentation.reporting import display_final_results

# Import factories for dependency injection
from .factories import create_config_from_file

# Import application layer directly
from .application.binary_analyzer import analyze_binary
from .application.directory_scanner import analyze_directory

# Logger will be configured in main()
logger = logging.getLogger(__name__)


def _unwrap_or_log(
    result: Any,
    context: str,
) -> Any | None:
    """
    Unwrap a Result, logging the error if it's an Err.

    Args:
        result: The Result to unwrap.
        context: Context string for the error message.

    Returns:
        The unwrapped value on success, None on error.
    """
    if isinstance(result, Ok):
        return result.value
    logger.error(f"{context}: {result.error}")
    return None


def _configure_logging() -> None:
    """Configure logging at application startup."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)s] %(message)s'
    )


def _validate_requirements(skip_requirements: bool) -> None:
    """
    Validate system requirements before analysis.

    Args:
        skip_requirements: If True, skip the requirements check.

    Raises:
        SystemExit: If requirements are not met.
    """
    if skip_requirements:
        return

    logger.info("Checking system requirements...")
    if not check_requirements(False):
        logger.error("Not all system requirements are met.")
        sys.exit(1)
    logger.info("Requirements check completed.")


def _analyze_single_file(args: Any, config: Any) -> Any:
    """
    Analyze a single binary file.

    Args:
        args: Command line arguments.
        config: Application configuration.

    Returns:
        Analysis result or None on error.
    """
    analysis_result = analyze_binary(
        binary_path=args.file,
        output_dir=args.output,
        decompiler_type=args.decompiler,
        verbose=args.verbose,
        config=config,
    )
    return _unwrap_or_log(analysis_result, "Analysis failed")


def _analyze_directory_path(args: Any, config: Any) -> Any:
    """
    Analyze a directory of binaries.

    Args:
        args: Command line arguments.
        config: Application configuration.

    Returns:
        Analysis result or None on error.
    """
    dir_result = analyze_directory(
        directory=args.directory,
        output_dir=args.output,
        decompiler_type=args.decompiler,
        verbose=args.verbose,
        config=config,
    )
    return _unwrap_or_log(dir_result, "Directory analysis failed")


def main() -> int:
    """
    Main program function.

    This is the primary entry point for BannedFuncDetector. It follows the
    dependency injection pattern by:
    1. Loading configuration once at startup
    2. Passing configuration explicitly to all components

    Returns:
        int: Exit code (0 for success).
    """
    _configure_logging()
    check_python_version()
    args = parse_arguments()
    _validate_requirements(args.skip_requirements)

    # Load configuration once at entry point (Dependency Injection pattern)
    config = create_config_from_file()
    os.makedirs(args.output, exist_ok=True)

    result: Any = None
    if args.file:
        result = _analyze_single_file(args, config)
    elif args.directory:
        result = _analyze_directory_path(args, config)

    display_final_results(result)
    return 0


if __name__ == "__main__":
    main()
