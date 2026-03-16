"""Binary session setup helpers."""

from __future__ import annotations

from bannedfuncdetector.application.analysis_error import BinaryExecutionError, ExecutionFailure
from bannedfuncdetector.domain import FunctionDescriptor
from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.domain.result import Err, Ok, Result, err, ok

from ..internal import BinaryScanPlan
from ..analysis_outcome import OperationalNotice
from .runtime import _extract_functions, _setup_analysis_error


def setup_binary_analysis(
    binary_path: str,
    params: BinaryScanPlan,
) -> Result[tuple[IR2Client, list[FunctionDescriptor]], ExecutionFailure]:
    """Open one binary session and return the client plus extracted functions."""
    opener = params.runtime.binary.binary_opener
    closer = params.runtime.binary.r2_closer
    if opener is None:
        return err(
            ExecutionFailure(
                error=BinaryExecutionError(
                    category="Configuration error",
                    context=binary_path,
                    message="binary_opener is required but was not provided",
                ),
            )
        )
    if closer is None:
        return err(
            ExecutionFailure(
                error=BinaryExecutionError(
                    category="Configuration error",
                    context=binary_path,
                    message="r2_closer is required but was not provided",
                ),
            )
        )
    try:
        r2 = opener(
            binary_path,
            params.verbose,
            params.runtime.r2_factory,
        )
        functions_result = _extract_functions(r2, params.verbose)

        if isinstance(functions_result, Err):
            cleanup_error = closer(r2)
            if isinstance(cleanup_error, Err):
                cleanup_message = cleanup_error.error
                if not isinstance(cleanup_message, str):
                    cleanup_message = str(cleanup_message)
                return err(
                    ExecutionFailure(
                        error=BinaryExecutionError(
                            category="Runtime error",
                            context=binary_path,
                            message=functions_result.error,
                        ),
                        operational_notices=(
                            OperationalNotice(
                                message=f"cleanup failed: {cleanup_message}",
                                file_path=binary_path,
                            ),
                        ),
                    )
                )
            return err(
                ExecutionFailure(
                    error=BinaryExecutionError(
                        category="Runtime error",
                        context=binary_path,
                        message=functions_result.error,
                    ),
                )
            )

        if isinstance(functions_result, Ok):
            return ok((r2, functions_result.unwrap()))
        return err(ExecutionFailure(error=BinaryExecutionError(category="Runtime error", context=binary_path, message="Unexpected function extraction response")))
    except (OSError, IOError, ValueError, RuntimeError) as exc:
        return err(ExecutionFailure(error=_setup_analysis_error(binary_path, exc)))


__all__ = ["setup_binary_analysis"]
