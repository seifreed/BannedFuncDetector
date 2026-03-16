"""Parallel and sequential execution runners for directory analysis."""

from __future__ import annotations

import concurrent.futures
import logging
from concurrent.futures import Future
from collections.abc import Callable, Iterator
from typing import Iterable, Protocol, TypeAlias

from bannedfuncdetector.application.analysis_error import ExecutionFailure
from bannedfuncdetector.application.analysis_outcome import BinaryAnalysisOutcome
from bannedfuncdetector.application.types import BinaryAnalysisResultType
from bannedfuncdetector.application.analysis_runtime import BinaryRuntimeServices
from bannedfuncdetector.domain.result import Result

from .directory_results import error_result_from_exception, handle_directory_future, normalize_directory_result
from .directory_workers import analyze_binary_job, analyze_binary_job_from_worker_payload, serialize_config
from .execution_plans import DirectoryScanPlan, DirectoryWorkerJob

logger = logging.getLogger(__name__)


class ExecutorLike(Protocol):
    def __enter__(self) -> "ExecutorLike": ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: object | None,
    ) -> bool | None: ...
    def submit(
        self,
        fn: Callable[[DirectoryWorkerJob], BinaryAnalysisResultType],
        job: DirectoryWorkerJob,
    ) -> Future[BinaryAnalysisResultType]: ...
    def shutdown(self, wait: bool = True) -> None: ...


ExecutorFactory: TypeAlias = Callable[..., ExecutorLike]
CompletedFutures: TypeAlias = Callable[[Iterable[concurrent.futures.Future[BinaryAnalysisResultType]]], Iterable[concurrent.futures.Future[BinaryAnalysisResultType]]]


def iter_parallel_directory_results(
    executable_files: list[str],
    plan: DirectoryScanPlan,
    max_workers: int,
) -> Iterator[tuple[str, Result[BinaryAnalysisOutcome, ExecutionFailure]]]:
    """Yield per-file results from process-based directory execution."""
    if plan.verbose:
        logger.info(f"Starting parallel analysis with {max_workers} workers...")

    config = plan.runtime.config
    config_factory = plan.runtime.config_factory
    if config_factory is None:
        raise ValueError("config_factory is required for directory analysis")
    serialized_config = serialize_config(config)
    jobs = [
        DirectoryWorkerJob(
            executable_file=executable_file,
            output_dir=plan.output_dir,
            decompiler_type=plan.decompiler_type,
            verbose=plan.verbose,
            config_dict=serialized_config,
            config_factory=config_factory,
            r2_factory=plan.runtime.r2_factory,
            binary_opener=plan.runtime.binary.binary_opener,
            r2_closer=plan.runtime.binary.r2_closer,
            orchestrator_factory=plan.runtime.orchestrator_factory,
            force_decompiler=plan.force_decompiler,
            skip_banned=plan.skip_banned,
            skip_analysis=plan.skip_analysis,
        )
        for executable_file in executable_files
    ]
    worker = plan.worker_entrypoint or analyze_binary_job_from_worker_payload
    pool_factory = plan.parallel_executor_factory or concurrent.futures.ProcessPoolExecutor
    completed_iterator = plan.completed_futures or concurrent.futures.as_completed

    with pool_factory(max_workers=max_workers) as executor:
        futures: dict[concurrent.futures.Future[BinaryAnalysisResultType], str] = {
            executor.submit(worker, job): job.executable_file
            for job in jobs
        }

        for future in completed_iterator(futures.keys()):
            yield handle_directory_future(future, futures[future])


def iter_sequential_directory_results(
    executable_files: list[str],
    plan: DirectoryScanPlan,
) -> Iterator[tuple[str, Result[BinaryAnalysisOutcome, ExecutionFailure]]]:
    """Yield per-file results from sequential directory execution."""
    if plan.verbose:
        logger.info("Starting sequential analysis...")

    config = plan.runtime.config
    r2_factory = plan.runtime.r2_factory
    decompiler_orchestrator = plan.runtime.decompiler_orchestrator

    for executable_file in executable_files:
        try:
            if plan.verbose:
                logger.info(f"Analyzing {executable_file}...")
            result = analyze_binary_job(
                executable_file,
                plan.output_dir,
                plan.decompiler_type,
                plan.verbose,
                config,
                r2_factory,
                BinaryRuntimeServices(
                    binary_opener=plan.runtime.binary.binary_opener,
                    r2_closer=plan.runtime.binary.r2_closer,
                ),
                decompiler_orchestrator=decompiler_orchestrator,
                force_decompiler=plan.force_decompiler,
                skip_banned=plan.skip_banned,
                skip_analysis=plan.skip_analysis,
            )
            yield executable_file, normalize_directory_result(executable_file, result)
        except (AttributeError, TypeError, KeyError, OSError, IOError, RuntimeError, ValueError) as exc:
            yield executable_file, error_result_from_exception(
                exc,
                context=executable_file,
                logger_message=f"analyzing {executable_file}",
            )


__all__ = [
    "iter_parallel_directory_results",
    "iter_sequential_directory_results",
]
