import logging

from bannedfuncdetector.analyzer_exceptions import (
    BinaryNotFoundError,
    DecompilerNotAvailableError,
)
from bannedfuncdetector.application.analysis_error import (
    BinaryExecutionError,
    ExecutionFailure,
)
from bannedfuncdetector.application.contracts import BinaryAnalysisRequest
from bannedfuncdetector.application.internal import BinaryScanPlan
from bannedfuncdetector.observability import safe_exception_fields, safe_stack_trace
from bannedfuncdetector.domain.protocols import IDecompilerOrchestrator
from bannedfuncdetector.domain.result import Err, Result, err, ok

from .runtime import _validate_binary_input

logger = logging.getLogger(__name__)


def _selection_error(
    exc: Exception,
    binary_path: str,
) -> ExecutionFailure:
    binary_not_found = isinstance(exc, BinaryNotFoundError)
    category = "Input error" if binary_not_found else "Configuration error"
    phase = "validating_binary" if binary_not_found else "selecting_decompiler"
    error_message = (
        f"Binary not found: {exc}"
        if binary_not_found
        else f"Decompiler not available: {exc}"
    )
    logger.error(
        "Binary input validation failed"
        if binary_not_found
        else "Decompiler selection failed",
        extra={
            "operation": "binary_analysis",
            "event_name": "analysis_error",
            "outcome": "error",
            "error_category": category,
            "error_phase": phase,
            "stack_trace": safe_stack_trace(exc),
            **safe_exception_fields(exc),
        },
    )
    return ExecutionFailure(
        error=BinaryExecutionError(
            category=category,
            phase=phase,
            context=binary_path,
            message=error_message,
        ),
        logged=True,
    )


def _resolve_decompiler_selection(
    binary_path: str,
    requested_decompiler: str | None,
    force_decompiler: bool,
    decompiler_orchestrator: IDecompilerOrchestrator | None,
) -> Result[tuple[IDecompilerOrchestrator | None, str], ExecutionFailure]:
    try:
        _validate_binary_input(binary_path)
        if decompiler_orchestrator is None:
            return ok((None, requested_decompiler or "default"))
        final_decompiler = decompiler_orchestrator.select_decompiler(
            requested=requested_decompiler,
            force=force_decompiler,
        )
        return ok((decompiler_orchestrator, final_decompiler))
    except (BinaryNotFoundError, DecompilerNotAvailableError) as exc:
        return err(_selection_error(exc, binary_path))


def _validate_and_resolve_params(
    binary_path: str,
    request: BinaryAnalysisRequest,
) -> Result[BinaryScanPlan, ExecutionFailure]:
    decompiler_orchestrator = request.runtime.decompiler_orchestrator
    selection_result = _resolve_decompiler_selection(
        binary_path,
        request.decompiler_type,
        request.force_decompiler,
        None if request.skip_analysis else decompiler_orchestrator,
    )
    if isinstance(selection_result, Err):
        return selection_result
    resolved_orchestrator, final_decompiler = selection_result.unwrap()
    return ok(
        BinaryScanPlan(
            output_dir=request.output_dir,
            decompiler_type=final_decompiler,
            verbose=request.verbose,
            worker_limit=request.worker_limit,
            runtime=request.runtime,
            force_decompiler=request.force_decompiler,
            skip_banned=request.skip_banned,
            skip_analysis=request.skip_analysis,
            decompiler_orchestrator=resolved_orchestrator,
        )
    )


__all__: list[str] = []  # internal module; use explicit imports
