"""Runtime helpers for binary validation and function extraction."""
import logging
import os
from typing import Any, cast

from bannedfuncdetector.analyzer_exceptions import BinaryNotFoundError
from bannedfuncdetector.application.analysis_error import BinaryExecutionError
from bannedfuncdetector.domain import FunctionDescriptor
from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.domain.result import Result, err, ok
from bannedfuncdetector.domain.types import classify_error
from bannedfuncdetector.application.dto_mappers import function_descriptor_from_dto

logger = logging.getLogger(__name__)


def _extract_functions_error(exc: Exception) -> Result[list[FunctionDescriptor], str]:
    """Convert function-extraction failures into Result errors."""
    from bannedfuncdetector.domain.error_types import ErrorCategory
    category = classify_error(exc)
    message = f"{category} extracting functions from binary: {exc}"
    if category != ErrorCategory.DATA:
        logger.error(message)
    return err(message)


def _setup_analysis_error(
    binary_path: str,
    exc: Exception,
) -> BinaryExecutionError:
    """Convert binary setup failures into a structured execution error."""
    category = classify_error(exc)
    logger.error("%s opening binary %s: %s", category, binary_path, exc)
    return BinaryExecutionError(
        category=category,
        phase="opening binary",
        context=binary_path,
        message=str(exc),
    )


def _validate_binary_input(binary_path: str) -> None:
    """Validate that the target binary exists before analysis."""
    if not os.path.exists(binary_path):
        error_msg = f"The file {binary_path} does not exist."
        logger.error(error_msg)
        raise BinaryNotFoundError(error_msg)


def _extract_functions(r2: IR2Client, verbose: bool = False) -> Result[list[FunctionDescriptor], str]:
    """Extract discovered functions and convert them into domain entities."""
    try:
        if verbose:
            logger.info("Getting function list...")

        functions = r2.cmdj("aflj")
        if not functions:
            error_msg = "No functions found in the binary."
            if verbose:
                logger.warning(error_msg)
            return err(error_msg)

        if verbose:
            logger.info(f"Found {len(functions)} functions.")

        raw_functions = cast(list[dict[str, Any]], functions)
        function_list = [function_descriptor_from_dto(func) for func in raw_functions]
        return ok(function_list)
    except (KeyError, AttributeError, TypeError, RuntimeError, ValueError, OSError, IOError) as exc:
        return _extract_functions_error(exc)


__all__: list[str] = []  # internal module; use explicit imports
