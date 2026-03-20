#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Public request contracts for analysis use cases."""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from bannedfuncdetector.application.analysis_runtime import (
    AnalysisRuntime,
    BinaryRuntimeServices,
    DirectoryRuntimeServices,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from bannedfuncdetector.domain import BannedFunction


@dataclass(frozen=True, kw_only=True)
class FunctionAnalysisRequest:
    """Public contract for analyzing a single discovered function."""

    runtime: AnalysisRuntime
    banned_functions: set[str] | None = None
    decompiler_type: str = "default"
    verbose: bool = False
    skip_banned: bool = False
    skip_analysis: bool = False


@dataclass(frozen=True, kw_only=True)
class BinaryAnalysisRequest:
    """Public contract for analyzing one binary file."""

    runtime: AnalysisRuntime
    output_dir: str | None = None
    decompiler_type: str | None = None
    verbose: bool = False
    worker_limit: int | None = None
    force_decompiler: bool = False
    skip_banned: bool = False
    skip_analysis: bool = False
    parallel_executor: "Callable[..., list[BannedFunction]] | None" = None

    @classmethod
    def for_runtime(
        cls,
        runtime: AnalysisRuntime,
        *,
        output_dir: str | None = None,
        decompiler_type: str | None = None,
        verbose: bool = False,
        worker_limit: int | None = None,
        force_decompiler: bool = False,
        skip_banned: bool = False,
        skip_analysis: bool = False,
        parallel_executor: "Callable[..., list[BannedFunction]] | None" = None,
    ) -> "BinaryAnalysisRequest":
        """Build a single-binary request from runtime plus caller-facing flags."""
        return cls(
            runtime=runtime,
            output_dir=output_dir,
            decompiler_type=decompiler_type,
            verbose=verbose,
            worker_limit=worker_limit,
            force_decompiler=force_decompiler,
            skip_banned=skip_banned,
            skip_analysis=skip_analysis,
            parallel_executor=parallel_executor,
        )


@dataclass(frozen=True, kw_only=True)
class DirectoryAnalysisRequest:
    """Public contract for analyzing all binaries in a directory."""

    runtime: AnalysisRuntime
    output_dir: str | None = None
    decompiler_type: str | None = None
    max_workers: int | None = None
    parallel: bool = True
    verbose: bool = False
    force_decompiler: bool = False
    skip_banned: bool = False
    skip_analysis: bool = False

    @classmethod
    def for_runtime(
        cls,
        runtime: AnalysisRuntime,
        *,
        output_dir: str | None = None,
        decompiler_type: str | None = None,
        max_workers: int | None = None,
        parallel: bool = True,
        verbose: bool = False,
        force_decompiler: bool = False,
        skip_banned: bool = False,
        skip_analysis: bool = False,
    ) -> "DirectoryAnalysisRequest":
        """Build a directory-analysis request from runtime plus caller-facing flags."""
        return cls(
            runtime=runtime,
            output_dir=output_dir,
            decompiler_type=decompiler_type,
            max_workers=max_workers,
            parallel=parallel,
            verbose=verbose,
            force_decompiler=force_decompiler,
            skip_banned=skip_banned,
            skip_analysis=skip_analysis,
        )


__all__ = [
    "AnalysisRuntime",
    "BinaryRuntimeServices",
    "DirectoryRuntimeServices",
    "FunctionAnalysisRequest",
    "BinaryAnalysisRequest",
    "DirectoryAnalysisRequest",
]
