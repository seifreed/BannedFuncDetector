"""Function-level analysis helpers for binary analysis."""

import logging

from bannedfuncdetector.analyzer_exceptions import AnalysisError
from bannedfuncdetector.application.contracts import FunctionAnalysisRequest
from bannedfuncdetector.domain import BannedFunction, FunctionDescriptor
from bannedfuncdetector.domain.protocols import IDecompilerOrchestrator, IR2Client
from bannedfuncdetector.domain.banned_functions import get_highest_risk_category
from bannedfuncdetector.domain.result import Err, Ok, Result, err, ok
from bannedfuncdetector.domain.types import classify_error

from .detection import (
    _check_function_name_banned,
    _decompile_and_search,
    _validate_analysis_inputs,
)

logger = logging.getLogger(__name__)


def _function_analysis_error(exc: Exception) -> Result[BannedFunction, str]:
    """Convert handled function-analysis exceptions into Result errors."""
    if isinstance(exc, AnalysisError):
        prefix = "Analysis error analyzing function"
    else:
        prefix = f"{classify_error(exc)} analyzing function"
    logger.error(f"{prefix}: {exc}")
    return err(f"{prefix}: {exc}")


def _resolve_banned_inputs(
    func: FunctionDescriptor,
    request: FunctionAnalysisRequest,
) -> Result[set[str], str]:
    """Resolve validated banned-function inputs for one function analysis."""
    return _validate_analysis_inputs(func, request.banned_functions)


def _merge_detections(
    name_result: BannedFunction,
    code_result: BannedFunction,
) -> BannedFunction:
    """Merge name-match and decompilation detections into a single result."""
    all_calls = tuple(sorted(set(name_result.banned_calls) | set(code_result.banned_calls)))
    category = get_highest_risk_category(all_calls)
    return BannedFunction(
        name=name_result.name,
        address=name_result.address,
        size=name_result.size,
        banned_calls=all_calls,
        detection_method="name+decompilation",
        category=category,
    )


def _run_detection_steps(
    r2: IR2Client,
    func: FunctionDescriptor,
    validated_banned: set[str],
    decompiler_type: str,
    verbose: bool,
    *,
    skip_banned: bool,
    skip_analysis: bool,
    decompiler_orchestrator: IDecompilerOrchestrator | None,
) -> Result[BannedFunction, str]:
    """Run the enabled detection steps for one function."""
    if skip_banned and skip_analysis:
        return err(f"Skipped: both detection methods disabled for {func.name}")

    name_detection: BannedFunction | None = None

    if not skip_banned:
        name_match_result = _check_function_name_banned(
            func.name,
            func.address,
            validated_banned,
            verbose,
        )
        if isinstance(name_match_result, Ok):
            name_detection = name_match_result.unwrap()

    code_detection: BannedFunction | None = None

    if not skip_analysis:
        decompile_result = _decompile_and_search(
            r2,
            func.name,
            func.address,
            validated_banned,
            decompiler_type,
            verbose,
            decompiler_orchestrator=decompiler_orchestrator,
        )
        if isinstance(decompile_result, Ok):
            code_detection = decompile_result.unwrap()

    # Merge both detection results if available
    if name_detection and code_detection:
        return ok(_merge_detections(name_detection, code_detection))
    if code_detection:
        return ok(code_detection)
    if name_detection:
        return ok(name_detection)

    return err(f"No banned functions found in {func.name}")


def analyze_function(
    r2: IR2Client,
    func: FunctionDescriptor,
    *,
    request: FunctionAnalysisRequest,
) -> Result[BannedFunction, str]:
    """Analyze a single function for banned or insecure calls."""
    validated_banned_result = _resolve_banned_inputs(func, request)
    if isinstance(validated_banned_result, Err):
        return validated_banned_result

    validated_banned = validated_banned_result.unwrap()
    try:
        return _run_detection_steps(
            r2,
            func,
            validated_banned,
            request.decompiler_type,
            request.verbose,
            skip_banned=request.skip_banned,
            skip_analysis=request.skip_analysis,
            decompiler_orchestrator=request.runtime.decompiler_orchestrator,
        )
    except (
        AnalysisError,
        KeyError,
        AttributeError,
        TypeError,
        RuntimeError,
        ValueError,
        OSError,
        IOError,
    ) as exc:
        return _function_analysis_error(exc)


__all__ = ["analyze_function"]
