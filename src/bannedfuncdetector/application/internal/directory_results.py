#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Result collection and persistence helpers for directory analysis."""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
from collections.abc import Callable, Iterator

from bannedfuncdetector.application.analysis_error import (
    DirectoryExecutionError,
    ExecutionFailure,
)
from bannedfuncdetector.domain.types import classify_error
from bannedfuncdetector.application.analysis_outcome import (
    BinaryAnalysisOutcome,
    DirectoryAnalysisOutcome,
    OperationalNotice,
)
from bannedfuncdetector.application.result_serializers import directory_outcome_to_dict
from bannedfuncdetector.domain import AnalysisResult
from bannedfuncdetector.domain.result import Err, Ok, Result, err

logger = logging.getLogger(__name__)

DirectoryWorkerResult = Result[BinaryAnalysisOutcome, ExecutionFailure]


def directory_error_from_exception(
    exc: Exception,
    *,
    context: str,
) -> DirectoryExecutionError:
    """Build a structured directory-execution error from an exception."""
    category = classify_error(exc)
    return DirectoryExecutionError(
        category=category,
        context=context,
        message=str(exc),
    )


def error_result_from_exception(
    exc: Exception,
    *,
    context: str,
    logger_message: str | None = None,
) -> DirectoryWorkerResult:
    """Convert a handled execution exception into a normalized Result error."""
    error = directory_error_from_exception(exc, context=context)

    if logger_message is not None:
        logger.error("%s %s: %s", error.category, logger_message, exc)
    return err(ExecutionFailure(error=error))


def normalize_directory_result(
    executable_file: str,
    result: Result[BinaryAnalysisOutcome, ExecutionFailure],
) -> DirectoryWorkerResult:
    """Convert a worker Result into the structured directory-result contract."""
    if isinstance(result, Ok):
        return result
    return err(
        ExecutionFailure(
            error=DirectoryExecutionError(
                category="Analysis error",
                context=executable_file,
                message=str(result.error),
            )
        )
    )


def handle_directory_future(
    future: concurrent.futures.Future,
    executable_file: str,
) -> tuple[str, DirectoryWorkerResult]:
    """Normalize one completed future into the directory-analysis result tuple."""
    try:
        result = future.result()
        return executable_file, normalize_directory_result(executable_file, result)
    except (
        AttributeError,
        TypeError,
        KeyError,
        OSError,
        IOError,
        RuntimeError,
        ValueError,
    ) as exc:
        return executable_file, error_result_from_exception(
            exc,
            context=executable_file,
            logger_message=f"analyzing {executable_file}",
        )


def collect_directory_results(
    result_iter: Iterator[tuple[str, DirectoryWorkerResult]],
    verbose: bool,
    on_result: Callable[[str, AnalysisResult, bool], None],
) -> tuple[list[AnalysisResult], tuple[OperationalNotice, ...]]:
    """Collect successful directory-analysis results from an iterator."""
    results: list[AnalysisResult] = []
    notices: list[OperationalNotice] = []
    for executable_file, result in result_iter:
        if isinstance(result, Ok):
            unwrapped = result.unwrap()
            report = unwrapped.report
            notices.extend(unwrapped.operational_notices)
            results.append(report)
            on_result(executable_file, report, verbose)
        elif isinstance(result, Err):
            logger.error("Analysis failed for %s: %s", executable_file, result.error)
            if hasattr(result.error, "operational_notices"):
                notices.extend(result.error.operational_notices)
    return results, tuple(notices)


def persist_directory_summary(
    output_dir: str, summary: DirectoryAnalysisOutcome, verbose: bool = False
) -> None:
    """Persist the directory-analysis aggregate as JSON."""
    summary_file = os.path.join(output_dir, "summary.json")
    with open(summary_file, "w", encoding="utf-8") as handle:
        json.dump(directory_outcome_to_dict(summary), handle, indent=4)
    if verbose:
        logger.info(f"Summary saved to {summary_file}")


__all__ = [
    "collect_directory_results",
    "directory_error_from_exception",
    "error_result_from_exception",
    "handle_directory_future",
    "normalize_directory_result",
    "persist_directory_summary",
]
