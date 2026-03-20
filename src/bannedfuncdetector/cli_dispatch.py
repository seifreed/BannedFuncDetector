#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dispatch helpers for CLI-driven analysis flows."""

from __future__ import annotations

import logging
from typing import Any, Protocol, TypeVar

from .application.contracts import (
    AnalysisRuntime,
    BinaryAnalysisRequest,
    DirectoryAnalysisRequest,
)
from .application.types import BinaryAnalysisResultType, DirectoryAnalysisResultType
from .domain.result import Ok, Result
from .presentation.error_formatting import format_execution_error

T = TypeVar("T")
E = TypeVar("E")


class AnalyzeBinaryCallable(Protocol):
    def __call__(
        self,
        binary_path: str,
        *,
        request: BinaryAnalysisRequest,
    ) -> BinaryAnalysisResultType: ...


class AnalyzeDirectoryCallable(Protocol):
    def __call__(
        self,
        directory: str,
        *,
        request: DirectoryAnalysisRequest,
    ) -> DirectoryAnalysisResultType: ...


def unwrap_or_log(
    result: Result[T, E],
    context: str,
    *,
    logger: logging.Logger,
) -> T | None:
    """Return the inner value from a Result or log the error."""
    if isinstance(result, Ok):
        return result.value
    logger.error(f"{context}: {format_execution_error(result.error)}")
    return None


def analyze_single_file_path(
    args: Any,
    wiring: AnalysisRuntime,
    *,
    analyze_binary: AnalyzeBinaryCallable,
    logger: logging.Logger,
) -> Any:
    """Dispatch CLI file analysis to the application boundary."""
    analysis_result = analyze_binary(
        binary_path=args.file,
        request=BinaryAnalysisRequest.for_runtime(
            wiring,
            output_dir=args.output,
            decompiler_type=args.decompiler,
            verbose=args.verbose,
            force_decompiler=args.force_decompiler,
            skip_banned=args.skip_banned,
            skip_analysis=args.skip_analysis,
        ),
    )
    return unwrap_or_log(analysis_result, "Analysis failed", logger=logger)


def analyze_directory_path(
    args: Any,
    wiring: AnalysisRuntime,
    *,
    analyze_directory: AnalyzeDirectoryCallable,
    logger: logging.Logger,
) -> Any:
    """Dispatch CLI directory analysis to the application boundary."""
    dir_result = analyze_directory(
        directory=args.directory,
        request=DirectoryAnalysisRequest.for_runtime(
            wiring,
            output_dir=args.output,
            decompiler_type=args.decompiler,
            parallel=args.parallel,
            verbose=args.verbose,
            force_decompiler=args.force_decompiler,
            skip_banned=args.skip_banned,
            skip_analysis=args.skip_analysis,
        ),
    )
    return unwrap_or_log(dir_result, "Directory analysis failed", logger=logger)


def dispatch_cli_analysis(
    args: Any,
    wiring: AnalysisRuntime,
    *,
    analyze_binary: AnalyzeBinaryCallable,
    analyze_directory: AnalyzeDirectoryCallable,
    logger: logging.Logger,
) -> Any | None:
    """Dispatch CLI arguments to the selected application use case."""
    if args.file:
        return analyze_single_file_path(
            args,
            wiring,
            analyze_binary=analyze_binary,
            logger=logger,
        )
    if args.directory:
        return analyze_directory_path(
            args,
            wiring,
            analyze_directory=analyze_directory,
            logger=logger,
        )
    return None


__all__ = [
    "analyze_directory_path",
    "analyze_single_file_path",
    "dispatch_cli_analysis",
    "unwrap_or_log",
]
