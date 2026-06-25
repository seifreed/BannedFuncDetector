import logging
from collections.abc import Callable

from bannedfuncdetector.analyzer_exceptions import TransientR2Error
from bannedfuncdetector.application.internal import FunctionScanPlan
from bannedfuncdetector.domain import BannedFunction, FunctionDescriptor
from bannedfuncdetector.domain.banned_functions import get_banned_functions_set
from bannedfuncdetector.domain.protocols import (
    IConfigRepository,
    IDecompilerOrchestrator,
    IR2Client,
)
from bannedfuncdetector.domain.result import Result

from .function_detection_support import (
    build_function_analysis_request,
    log_function_result,
)
from .function_detection_support import log_selected_decompiler

logger = logging.getLogger(__name__)


def _r2_session_alive(r2: IR2Client) -> bool:
    """Whether the r2 process still responds.

    On very large binaries r2 can be killed mid-scan; per-function errors are
    swallowed into ``Err`` so the loop finishes and returns a silently-partial
    result. A cheap no-op probe distinguishes "finished" from "r2 died".
    """
    try:
        r2.cmd("")
        return True
    except (TransientR2Error, RuntimeError, OSError, IOError, ValueError):
        return False


def resolve_banned_functions(
    options: FunctionScanPlan,
    banned_functions_provider: Callable[[IConfigRepository], set[str]] | None,
) -> set[str]:
    return (banned_functions_provider or get_banned_functions_set)(options.config)


def analyze_functions_in_binary(
    r2: IR2Client,
    functions: list[FunctionDescriptor],
    banned_functions_set: set[str],
    options: FunctionScanPlan,
    *,
    function_analyzer: Callable[..., Result[BannedFunction, str]] | None,
) -> list[BannedFunction]:
    if function_analyzer is None:
        raise ValueError(
            "function_analyzer must be provided. "
            "Pass analyze_function from binary_analyzer when calling this function."
        )

    request = build_function_analysis_request(r2, options, banned_functions_set)
    results: list[BannedFunction] = []
    for func in functions:
        result = function_analyzer(r2, func, request=request)
        if result.is_ok():
            detection = result.unwrap()
            results.append(detection)
            log_function_result(detection, options.verbose)

    if functions and not _r2_session_alive(r2):
        logger.warning(
            "radare2 session ended before all %d functions were analyzed; "
            "results are incomplete.",
            len(functions),
        )
    return results


def run_intra_binary_detection(
    r2: IR2Client,
    functions: list[FunctionDescriptor],
    options: FunctionScanPlan,
    *,
    function_analyzer: Callable[..., Result[BannedFunction, str]] | None,
    banned_functions_provider: Callable[[IConfigRepository], set[str]] | None = None,
    decompiler_orchestrator: IDecompilerOrchestrator | None = None,
) -> list[BannedFunction]:
    log_selected_decompiler(
        options.decompiler_type,
        verbose=options.verbose,
        decompiler_orchestrator=decompiler_orchestrator
        or options.decompiler_orchestrator,
    )
    return analyze_functions_in_binary(
        r2,
        functions,
        resolve_banned_functions(options, banned_functions_provider),
        options,
        function_analyzer=function_analyzer,
    )


__all__ = [
    "analyze_functions_in_binary",
    "resolve_banned_functions",
    "run_intra_binary_detection",
]
