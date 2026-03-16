"""Directory-analysis use case boundary."""
from bannedfuncdetector.domain.result import Err, err, ok
from bannedfuncdetector.application.types import DirectoryAnalysisResultType
from bannedfuncdetector.application.contracts import DirectoryAnalysisRequest
from bannedfuncdetector.application.analysis_error import DirectoryExecutionError, ExecutionFailure
from bannedfuncdetector.application.internal.directory_boundary import (
    directory_scan_plan_from_request,
    log_analysis_result,
)
from bannedfuncdetector.application.internal.directory_preparation import (
    prepare_directory_analysis as _prepare_directory_analysis_impl,
)
from bannedfuncdetector.application.internal.directory_execution import (
    run_directory_analysis,
)


def analyze_directory(
    directory: str,
    *,
    request: DirectoryAnalysisRequest,
) -> DirectoryAnalysisResultType:
    resolved_options = directory_scan_plan_from_request(request)
    file_finder = request.runtime.directory.file_finder
    if file_finder is None:
        return err(
            ExecutionFailure(
                error=DirectoryExecutionError(
                    category="Configuration error",
                    context=directory,
                    message="file_finder is required for directory analysis",
                )
            )
        )
    preparation_result = _prepare_directory_analysis_impl(
        directory, request.verbose, file_finder=file_finder,
    )
    if isinstance(preparation_result, Err):
        return preparation_result

    summary = run_directory_analysis(
        directory,
        preparation_result.unwrap(),
        resolved_options,
        log_analysis_result,
    )
    return ok(summary)


__all__ = [
    "analyze_directory",
]
