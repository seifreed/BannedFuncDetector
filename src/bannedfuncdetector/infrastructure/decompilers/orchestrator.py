"""Stable facade for decompiler orchestration."""

from bannedfuncdetector.domain import BannedFunction, FunctionDescriptor
from bannedfuncdetector.domain.protocols import IConfigRepository, IR2Client
from bannedfuncdetector.domain.types import DecompilationResultType

from .availability import check_decompiler_available, get_available_decompiler
from .base_decompiler import DecompilerType
from .orchestrator_dispatch import decompile_function as _dispatch_decompile_function
from .orchestrator_service import (
    DecompilerOrchestrator,
    create_decompiler_orchestrator,
    decompile_with_selected_decompiler as _service_decompile_with_selected_decompiler,
)
from .selector import resolve_to_decompiler_type, select_decompiler


def decompile_function(
    r2: IR2Client,
    function_name: str,
    decompiler_type: str | DecompilerType | None = None,
    *,
    config: IConfigRepository,
) -> DecompilationResultType:
    """Facade entrypoint for single-function decompilation."""
    return _dispatch_decompile_function(
        r2,
        function_name,
        decompiler_type,
        config=config,
    )


def decompile_with_selected_decompiler(
    r2: IR2Client,
    functions: list[FunctionDescriptor],
    verbose: bool = True,
    decompiler_type: str | DecompilerType | None = None,
    *,
    config: IConfigRepository,
) -> list[BannedFunction]:
    """Facade entrypoint for multi-function decompilation scans."""
    return _service_decompile_with_selected_decompiler(
        r2,
        functions,
        verbose=verbose,
        decompiler_type=decompiler_type,
        config=config,
        decompile_function_impl=decompile_function,
    )


__all__ = [
    "decompile_function",
    "decompile_with_selected_decompiler",
    "check_decompiler_available",
    "get_available_decompiler",
    "select_decompiler",
    "resolve_to_decompiler_type",
    "DecompilerOrchestrator",
    "create_decompiler_orchestrator",
]
