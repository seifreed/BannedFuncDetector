import logging
from collections.abc import Callable

from bannedfuncdetector.analyzer_exceptions import AnalysisError
from bannedfuncdetector.application.analysis_error import (
    BinaryExecutionError,
    ExecutionFailure,
)
from bannedfuncdetector.application.contracts import BinaryAnalysisRequest
from bannedfuncdetector.application.internal import BinaryScanPlan
from bannedfuncdetector.domain import BannedFunction, FunctionDescriptor
from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.domain.result import Err, Ok, Result, err, ok
from bannedfuncdetector.domain.types import classify_error
from bannedfuncdetector.application.types import BinaryAnalysisResultType

from ..analysis_outcome import BinaryAnalysisOutcome, OperationalNotice
from .reporting import _create_analysis_report, _save_analysis_results
from .session_setup import setup_binary_analysis
from .selection import _validate_and_resolve_params
from .detection_execution import _execute_detection

logger = logging.getLogger(__name__)


def _analysis_error(
    binary_path: str, phase: str, exc: Exception
) -> BinaryAnalysisResultType:
    if isinstance(exc, AnalysisError):
        category = "Analysis error"
    else:
        category = classify_error(exc)
    error = BinaryExecutionError(
        category=category,
        phase=phase,
        context=binary_path,
        message=str(exc),
    )
    logger.error(str(error))
    return err(ExecutionFailure(error=error))


def _finalize_analysis(
    binary_path: str,
    functions: list[FunctionDescriptor],
    results: list[BannedFunction],
    output_dir: str | None,
    verbose: bool,
) -> BinaryAnalysisResultType:
    report = _create_analysis_report(binary_path, functions, results)
    if output_dir:
        _save_analysis_results(report, output_dir, binary_path, verbose)
    return ok(BinaryAnalysisOutcome(report=report))


def resolve_analysis_setup(
    binary_path: str,
    request: BinaryAnalysisRequest,
) -> Result[
    tuple[BinaryScanPlan, IR2Client, list[FunctionDescriptor]], ExecutionFailure
]:
    params_result = _validate_and_resolve_params(
        binary_path,
        request,
    )
    if isinstance(params_result, Err):
        return err(
            ExecutionFailure(
                error=BinaryExecutionError(
                    category="Configuration error",
                    context=binary_path,
                    message=params_result.error,
                )
            )
        )
    params = params_result.unwrap()
    setup_result = setup_binary_analysis(binary_path, params)
    if isinstance(setup_result, Err):
        return setup_result
    r2, functions = setup_result.unwrap()
    return ok((params, r2, functions))


def run_detection_with_cleanup(
    binary_path: str,
    request: BinaryAnalysisRequest,
    *,
    detect_impl: Callable[
        [IR2Client, list[FunctionDescriptor], BinaryScanPlan], list[BannedFunction]
    ],
) -> BinaryAnalysisResultType:
    setup_result = resolve_analysis_setup(binary_path, request)
    if isinstance(setup_result, Err):
        return setup_result

    params, r2, functions = setup_result.unwrap()
    result: BinaryAnalysisResultType
    try:
        results = detect_impl(r2, functions, params)
    except (
        AnalysisError,
        RuntimeError,
        ValueError,
        OSError,
        IOError,
        KeyError,
        AttributeError,
        TypeError,
    ) as exc:
        result = _analysis_error(binary_path, "during detection", exc)
    else:
        try:
            result = _finalize_analysis(
                binary_path,
                functions,
                results,
                params.output_dir,
                params.verbose,
            )
        except (
            AnalysisError,
            RuntimeError,
            ValueError,
            OSError,
            IOError,
            KeyError,
            AttributeError,
            TypeError,
        ) as exc:
            result = _analysis_error(binary_path, "while finalizing analysis", exc)
    r2_closer = params.runtime.binary.r2_closer
    if r2_closer is None:
        return result
    cleanup_error = r2_closer(r2)
    if isinstance(cleanup_error, Ok):
        return result

    cleanup_message = f"cleanup failed: {cleanup_error.error if isinstance(cleanup_error, Err) else str(cleanup_error)}"
    if isinstance(result, Err):
        current = result.error
        return err(
            ExecutionFailure(
                error=current.error,
                operational_notices=current.operational_notices
                + (OperationalNotice(message=cleanup_message, file_path=binary_path),),
            )
        )

    if isinstance(result, Ok):
        outcome = result.unwrap()
        return ok(
            BinaryAnalysisOutcome(
                report=outcome.report,
                operational_notices=outcome.operational_notices
                + (OperationalNotice(message=cleanup_message, file_path=binary_path),),
            )
        )
    return result


def run_binary_analysis(
    binary_path: str,
    *,
    request: BinaryAnalysisRequest,
    analyze_function_impl: Callable[..., Result[BannedFunction, str]],
) -> BinaryAnalysisResultType:
    return run_detection_with_cleanup(
        binary_path,
        request,
        detect_impl=lambda r2, functions, params: _execute_detection(
            r2,
            functions,
            params,
            request.parallel_executor,
            analyze_function_impl,
        ),
    )


__all__ = ["run_binary_analysis"]
