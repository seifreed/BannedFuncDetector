import logging

from bannedfuncdetector.analyzer_exceptions import (
    BinaryNotFoundError,
    DecompilerNotAvailableError,
)
from bannedfuncdetector.application.contracts import BinaryAnalysisRequest
from bannedfuncdetector.application.internal import BinaryScanPlan
from bannedfuncdetector.domain.protocols import IDecompilerOrchestrator
from bannedfuncdetector.domain.result import Err, Result, err, ok

from .runtime import _validate_binary_input

logger = logging.getLogger(__name__)


def _selection_error(
    exc: Exception,
) -> Result[tuple[IDecompilerOrchestrator | None, str], str]:
    if isinstance(exc, BinaryNotFoundError):
        return err(f"Binary not found: {exc}")
    return err(f"Decompiler not available: {exc}")


def _resolve_decompiler_selection(
    binary_path: str,
    requested_decompiler: str | None,
    force_decompiler: bool,
    decompiler_orchestrator: IDecompilerOrchestrator | None,
) -> Result[tuple[IDecompilerOrchestrator | None, str], str]:
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
        return _selection_error(exc)


def _validate_and_resolve_params(
    binary_path: str,
    request: BinaryAnalysisRequest,
) -> Result[BinaryScanPlan, str]:
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
