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
from bannedfuncdetector.application.observability import safe_exception_fields

logger = logging.getLogger(__name__)


def validate_directory(directory: str) -> Result[Path, ExecutionFailure]:
    """Validate that a directory exists and is accessible."""
    try:
        path = Path(directory)
        if not path.exists():
            error_msg = f"The directory {directory} does not exist."
            logger.error(
                "Directory does not exist",
                extra={
                    "event_name": "directory_validation_failed",
                    "outcome": "error",
                    "error_category": "Input error",
                },
            )
            return err(
                ExecutionFailure(
                    error=DirectoryExecutionError(
                        category="Input error",
                        context=directory,
                        message=error_msg,
                    ),
                    logged=True,
                )
            )
        if not path.is_dir():
            error_msg = f"The path {directory} is not a directory."
            logger.error(
                "Path is not a directory",
                extra={
                    "event_name": "directory_validation_failed",
                    "outcome": "error",
                    "error_category": "Input error",
                },
            )
            return err(
                ExecutionFailure(
                    error=DirectoryExecutionError(
                        category="Input error",
                        context=directory,
                        message=error_msg,
                    ),
                    logged=True,
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
        logger.error(
            "Directory validation failed",
            extra={
                "event_name": "directory_validation_failed",
                "outcome": "error",
                "error_category": "Input error",
                **safe_exception_fields(exc),
            },
        )
        return err(
            ExecutionFailure(
                error=directory_error_from_exception(exc, context=directory),
                logged=True,
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
            logger.error(
                "No executable files found",
                extra={
                    "event_name": "executable_discovery_failed",
                    "outcome": "error",
                    "error_category": "Input error",
                },
            )
            return err(
                ExecutionFailure(
                    error=DirectoryExecutionError(
                        category="Input error",
                        context=directory,
                        message=error_msg,
                    ),
                    logged=True,
                )
            )

        if verbose:
            logger.info(
                "Executable files discovered",
                extra={
                    "event_name": "executable_discovery_completed",
                    "outcome": "success",
                    "file_count": len(executable_files),
                },
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
        logger.error(
            "Executable discovery failed",
            extra={
                "event_name": "executable_discovery_failed",
                "outcome": "error",
                "error_category": "I/O error",
                **safe_exception_fields(exc),
            },
        )
        return err(
            ExecutionFailure(
                error=directory_error_from_exception(exc, context=directory),
                logged=True,
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
