#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Internal execution plans for analysis use cases."""

from dataclasses import dataclass
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ..contracts.analysis import AnalysisRuntime
from ..analysis_error import ExecutionFailure

if TYPE_CHECKING:
    from bannedfuncdetector.application.analysis_outcome import BinaryAnalysisOutcome
    from bannedfuncdetector.domain.protocols import (
        IConfigRepository,
        IDecompilerOrchestrator,
        IR2Client,
    )
    from bannedfuncdetector.domain.result import Result
    from .directory_runners import CompletedFutures, ExecutorFactory


@dataclass(frozen=True, kw_only=True)
class FunctionScanPlan:
    """Internal plan for scanning extracted functions inside one binary."""

    verbose: bool = False
    worker_limit: int | None = None
    decompiler_type: str = "default"
    config: "IConfigRepository"
    skip_banned: bool = False
    skip_analysis: bool = False
    decompiler_orchestrator: "IDecompilerOrchestrator | None" = None


@dataclass(frozen=True, kw_only=True)
class ParallelWorkPlan:
    """Internal plan for parallel work scheduling."""

    verbose: bool = False
    worker_limit: int | None = None
    use_processes: bool = False
    config: "IConfigRepository"


@dataclass(frozen=True, kw_only=True)
class DirectoryScanPlan:
    """Immutable internal execution plan for the directory-analysis use case."""

    runtime: AnalysisRuntime
    output_dir: str | None = None
    decompiler_type: str = "default"
    max_workers: int | None = None
    verbose: bool = False
    parallel: bool = True
    force_decompiler: bool = False
    skip_banned: bool = False
    skip_analysis: bool = False
    worker_entrypoint: "Callable[[DirectoryWorkerJob], Result[BinaryAnalysisOutcome, ExecutionFailure]] | None" = (None)
    parallel_executor_factory: "ExecutorFactory | None" = None
    completed_futures: "CompletedFutures | None" = None


@dataclass(frozen=True, kw_only=True)
class BinaryScanPlan:
    """Validated execution plan for a single-binary analysis use case."""

    output_dir: str | None
    decompiler_type: str
    verbose: bool
    worker_limit: int | None
    runtime: AnalysisRuntime
    force_decompiler: bool
    skip_banned: bool
    skip_analysis: bool
    decompiler_orchestrator: "IDecompilerOrchestrator | None"


@dataclass(frozen=True, kw_only=True)
class DirectoryWorkerJob:
    """Serializable job payload for one directory-analysis worker process."""

    executable_file: str
    output_dir: str | None
    decompiler_type: str
    verbose: bool
    config_dict: dict[str, Any]
    config_factory: "Callable[[dict[str, Any]], IConfigRepository]"
    r2_factory: "Callable[[str], IR2Client]"
    binary_opener: "Callable[[str, bool, Callable[[str], IR2Client]], IR2Client]"
    r2_closer: "Callable[[IR2Client], Any]"
    orchestrator_factory: (
        "Callable[[IConfigRepository], IDecompilerOrchestrator] | None"
    ) = None
    force_decompiler: bool = False
    skip_banned: bool = False
    skip_analysis: bool = False


__all__ = [
    "FunctionScanPlan",
    "ParallelWorkPlan",
    "DirectoryScanPlan",
    "BinaryScanPlan",
    "DirectoryWorkerJob",
]
