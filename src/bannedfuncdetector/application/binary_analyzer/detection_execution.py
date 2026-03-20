from collections.abc import Callable

from bannedfuncdetector.application.internal import BinaryScanPlan, FunctionScanPlan
from bannedfuncdetector.domain import BannedFunction, FunctionDescriptor
from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.domain.result import Result


def _execute_custom_parallel_detection(
    parallel_executor: Callable[..., list[BannedFunction]],
    r2: IR2Client,
    functions: list[FunctionDescriptor],
    params: BinaryScanPlan,
) -> list[BannedFunction]:
    return parallel_executor(
        r2,
        functions,
        params.decompiler_type,
        params.verbose,
        params.worker_limit,
        params.runtime.config,
    )


def _build_analysis_options(params: BinaryScanPlan) -> FunctionScanPlan:
    return FunctionScanPlan(
        verbose=params.verbose,
        worker_limit=params.worker_limit,
        decompiler_type=params.decompiler_type,
        config=params.runtime.config,
        skip_banned=params.skip_banned,
        skip_analysis=params.skip_analysis,
        decompiler_orchestrator=params.decompiler_orchestrator,
    )


def _execute_default_detection(
    r2: IR2Client,
    functions: list[FunctionDescriptor],
    params: BinaryScanPlan,
    function_analyzer: Callable[..., Result[BannedFunction, str]],
) -> list[BannedFunction]:
    from bannedfuncdetector.application.function_detection_runtime import (
        run_intra_binary_detection,
    )

    return run_intra_binary_detection(
        r2,
        functions,
        _build_analysis_options(params),
        function_analyzer=function_analyzer,
    )


def _execute_detection(
    r2: IR2Client,
    functions: list[FunctionDescriptor],
    params: BinaryScanPlan,
    parallel_executor: Callable[..., list[BannedFunction]] | None,
    function_analyzer: Callable[..., Result[BannedFunction, str]],
) -> list[BannedFunction]:
    if parallel_executor is not None:
        return _execute_custom_parallel_detection(
            parallel_executor,
            r2,
            functions,
            params,
        )
    return _execute_default_detection(r2, functions, params, function_analyzer)


__all__: list[str] = []  # internal module; use explicit imports
