import logging

from bannedfuncdetector.application.contracts import DirectoryAnalysisRequest
from bannedfuncdetector.application.internal import DirectoryScanPlan
from bannedfuncdetector.domain import AnalysisResult

logger = logging.getLogger(__name__)


def directory_scan_plan_from_request(
    request: DirectoryAnalysisRequest,
) -> DirectoryScanPlan:
    resolved_decompiler = (
        request.decompiler_type
        if request.decompiler_type is not None
        else request.runtime.config.get("decompiler", {}).get("type", "default")
    )
    return DirectoryScanPlan(
        output_dir=request.output_dir,
        decompiler_type=resolved_decompiler,
        max_workers=request.max_workers,
        verbose=request.verbose,
        parallel=request.parallel,
        runtime=request.runtime,
        force_decompiler=request.force_decompiler,
        skip_banned=request.skip_banned,
        skip_analysis=request.skip_analysis,
        worker_entrypoint=request.runtime.directory.worker_entrypoint,
        parallel_executor_factory=request.runtime.directory.executor_factory,
        completed_futures=request.runtime.directory.completed_futures,
    )


def log_analysis_result(file_path: str, result: AnalysisResult, verbose: bool) -> None:
    logger.log(
        logging.INFO if verbose else logging.DEBUG,
        "Directory file analysis completed",
        extra={
            "operation": "directory_analysis",
            "event_name": "directory_file_analysis_completed",
            "outcome": "issues_found" if result.has_issues else "clean",
            "insecure_count": result.insecure_count,
            "total_functions": result.total_functions,
        },
    )


__all__ = ["directory_scan_plan_from_request", "log_analysis_result"]
