"""Preparation helpers for directory analysis."""

from __future__ import annotations

import logging
from pathlib import Path

from collections.abc import Callable

from bannedfuncdetector.application.analysis_error import (
    DirectoryExecutionError,
    ExecutionFailure,
)
from .directory_results import directory_error_from_exception
from bannedfuncdetector.domain.result import Err, Result, err, ok

logger = logging.getLogger(__name__)


def validate_directory(directory: str) -> Result[Path, ExecutionFailure]:
    """Validate that a directory exists and is accessible."""
    try:
        path = Path(directory)
        if not path.exists():
            error_msg = f"The directory {directory} does not exist."
            logger.error(error_msg)
            return err(
                ExecutionFailure(
                    error=DirectoryExecutionError(
                        category="Input error",
                        context=directory,
                        message=error_msg,
                    )
                )
            )
        if not path.is_dir():
            error_msg = f"The path {directory} is not a directory."
            logger.error(error_msg)
            return err(
                ExecutionFailure(
                    error=DirectoryExecutionError(
                        category="Input error",
                        context=directory,
                        message=error_msg,
                    )
                )
            )
        return ok(path)
    except (
        AttributeError,
        TypeError,
        KeyError,
        OSError,
        IOError,
        RuntimeError,
        ValueError,
    ) as exc:
        logger.error("Error validating directory %s: %s", directory, exc)
        return err(
            ExecutionFailure(
                error=directory_error_from_exception(exc, context=directory)
            )
        )


def discover_executable_files(
    directory: str,
    verbose: bool = False,
    *,
    file_finder: Callable[[str, str], list[str]],
) -> Result[list[str], ExecutionFailure]:
    """Discover executable files inside a directory."""
    try:
        executable_files = file_finder(directory, "any")

        if not executable_files:
            error_msg = f"No executable files found in {directory}."
            logger.warning(error_msg)
            return err(
                ExecutionFailure(
                    error=DirectoryExecutionError(
                        category="Input error",
                        context=directory,
                        message=error_msg,
                    )
                )
            )

        if verbose:
            logger.info(
                f"Found {len(executable_files)} executable files in {directory}."
            )

        return ok(executable_files)
    except (
        AttributeError,
        TypeError,
        KeyError,
        OSError,
        IOError,
        RuntimeError,
        ValueError,
    ) as exc:
        logger.error("Error discovering executable files in %s: %s", directory, exc)
        return err(
            ExecutionFailure(
                error=directory_error_from_exception(exc, context=directory)
            )
        )


def prepare_directory_analysis(
    directory: str,
    verbose: bool,
    *,
    file_finder: Callable[[str, str], list[str]],
) -> Result[list[str], ExecutionFailure]:
    """Validate the input directory and discover executable files."""
    validation_result = validate_directory(directory)
    if isinstance(validation_result, Err):
        return validation_result

    executable_files_result = discover_executable_files(
        directory,
        verbose,
        file_finder=file_finder,
    )
    if isinstance(executable_files_result, Err):
        return executable_files_result

    return ok(executable_files_result.unwrap())


__all__ = [
    "discover_executable_files",
    "prepare_directory_analysis",
    "validate_directory",
]
