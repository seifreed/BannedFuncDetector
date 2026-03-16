from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bannedfuncdetector.application.analysis_outcome import BinaryAnalysisOutcome
    from bannedfuncdetector.domain.protocols import IConfigRepository, IDecompilerOrchestrator, IR2Client
    from bannedfuncdetector.domain.result import Result
    from bannedfuncdetector.application.internal.execution_plans import DirectoryWorkerJob
    from bannedfuncdetector.application.internal.directory_runners import CompletedFutures, ExecutorFactory
    from collections.abc import Callable
    from bannedfuncdetector.application.analysis_error import ExecutionFailure


@dataclass(frozen=True, kw_only=True)
class BinaryRuntimeServices:
    binary_opener: "Callable[[str, bool, Callable[[str], IR2Client]], IR2Client]"
    r2_closer: "Callable[[IR2Client], Result[None, str]]"


@dataclass(frozen=True, kw_only=True)
class DirectoryRuntimeServices:
    file_finder: "Callable[[str, str], list[str]] | None" = None
    worker_entrypoint: "Callable[[DirectoryWorkerJob], Result[BinaryAnalysisOutcome, ExecutionFailure]] | None" = None
    executor_factory: "ExecutorFactory | None" = None
    completed_futures: "CompletedFutures | None" = None


@dataclass(frozen=True, kw_only=True)
class AnalysisRuntime:
    config: "IConfigRepository"
    r2_factory: "Callable[[str], IR2Client]"
    config_factory: "Callable[[dict[str, object]], IConfigRepository] | None" = None
    decompiler_orchestrator: "IDecompilerOrchestrator | None" = None
    orchestrator_factory: "Callable[[IConfigRepository], IDecompilerOrchestrator] | None" = None
    binary: BinaryRuntimeServices
    directory: DirectoryRuntimeServices = DirectoryRuntimeServices()


__all__ = [
    "AnalysisRuntime",
    "BinaryRuntimeServices",
    "DirectoryRuntimeServices",
]
