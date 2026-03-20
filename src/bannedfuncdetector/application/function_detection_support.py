import concurrent.futures
import logging

from bannedfuncdetector.application.analysis_runtime import BinaryRuntimeServices
from bannedfuncdetector.application.contracts import (
    AnalysisRuntime,
    FunctionAnalysisRequest,
)
from bannedfuncdetector.domain import BannedFunction
from bannedfuncdetector.domain.protocols import IDecompilerOrchestrator, IR2Client
from bannedfuncdetector.domain.result import Result, ok as _ok
from bannedfuncdetector.domain.types import classify_error
from .internal import FunctionScanPlan

logger = logging.getLogger(__name__)


def log_function_result(detection: BannedFunction, verbose: bool) -> None:
    if verbose:
        logger.info(
            f"Insecure function found: {detection.name} at {hex(detection.address)}"
        )


def log_parallel_future_error(exc: BaseException, verbose: bool) -> None:
    if not verbose:
        return
    if isinstance(exc, concurrent.futures.CancelledError):
        logger.warning("Function analysis task was cancelled")
        return
    prefix = classify_error(exc) if isinstance(exc, Exception) else "Error"
    logger.error(f"{prefix} analyzing a function: {exc}")


def build_function_analysis_request(
    r2: IR2Client,
    options: FunctionScanPlan,
    banned_functions_set: set[str],
) -> FunctionAnalysisRequest:
    binary = getattr(getattr(options, "runtime", None), "binary", None)
    if binary is None:
        binary = BinaryRuntimeServices(
            binary_opener=lambda path, verbose, r2_factory: r2,
            r2_closer=lambda _r2: _ok(None),
        )
    return FunctionAnalysisRequest(
        runtime=AnalysisRuntime(
            config=options.config,
            r2_factory=lambda _binary_path: r2,
            binary=binary,
            decompiler_orchestrator=options.decompiler_orchestrator,
        ),
        banned_functions=banned_functions_set,
        decompiler_type=options.decompiler_type,
        verbose=options.verbose,
        skip_banned=options.skip_banned,
        skip_analysis=options.skip_analysis,
    )


def log_selected_decompiler(
    decompiler_type: str,
    *,
    verbose: bool,
    decompiler_orchestrator: IDecompilerOrchestrator | None,
) -> None:
    if not verbose:
        return
    if (
        decompiler_orchestrator is None
        or decompiler_orchestrator.check_decompiler_available(decompiler_type)
    ):
        logger.info(f"Using decompiler: {decompiler_type}")


def process_parallel_results(
    futures: list[concurrent.futures.Future[Result[BannedFunction, str]]],
    verbose: bool = False,
) -> list[BannedFunction]:
    results: list[BannedFunction] = []
    for future in concurrent.futures.as_completed(futures):
        try:
            result = future.result()
            if result.is_ok():
                detection = result.unwrap()
                results.append(detection)
                log_function_result(detection, verbose)
        except (
            RuntimeError,
            ValueError,
            KeyError,
            AttributeError,
            TypeError,
            OSError,
            IOError,
            concurrent.futures.CancelledError,
        ) as exc:
            log_parallel_future_error(exc, verbose)
    return results


__all__ = [
    "build_function_analysis_request",
    "log_function_result",
    "log_selected_decompiler",
    "log_parallel_future_error",
    "process_parallel_results",
]
