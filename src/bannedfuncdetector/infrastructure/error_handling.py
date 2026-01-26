#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Unified Error Handling

This module provides a unified error handling decorator that eliminates
repeated error handling patterns across the codebase. The @handle_errors
decorator wraps functions and converts exceptions to Result[T, str] types.

Author: Marc Rivero | @seifreed
"""

import functools
import logging
from typing import TypeVar, Callable, ParamSpec, overload

from bannedfuncdetector.domain.result import Result, err

# Configure module logger
logger = logging.getLogger(__name__)

# Type variables for generic type support
T = TypeVar('T')
P = ParamSpec('P')


class ErrorCategory:
    """
    Enumeration of error categories for classification.

    Each category groups related exception types together for
    consistent handling and messaging.
    """
    DATA = "data"
    RUNTIME = "runtime"
    IO = "io"
    ANALYSIS = "analysis"


# Exception groups by category
EXCEPTION_GROUPS: dict[str, tuple[type[Exception], ...]] = {
    ErrorCategory.DATA: (KeyError, AttributeError, TypeError),
    ErrorCategory.RUNTIME: (RuntimeError, ValueError),
    ErrorCategory.IO: (OSError, IOError),
}


def _format_error_message(
    category: str,
    operation_name: str,
    exception: Exception,
) -> str:
    """
    Format a standardized error message.

    Args:
        category: The error category (data, runtime, io).
        operation_name: Human-readable description of the operation.
        exception: The caught exception.

    Returns:
        Formatted error message string.
    """
    category_labels = {
        ErrorCategory.DATA: "Data error",
        ErrorCategory.RUNTIME: "Runtime error",
        ErrorCategory.IO: "I/O error",
        ErrorCategory.ANALYSIS: "Analysis error",
    }
    label = category_labels.get(category, "Error")
    return f"{label} {operation_name}: {str(exception)}"


def _log_error(
    category: str,
    func_name: str,
    exception: Exception,
    should_log: bool,
) -> None:
    """
    Log an error if logging is enabled for the category.

    Args:
        category: The error category.
        func_name: Name of the function where error occurred.
        exception: The caught exception.
        should_log: Whether to log this error.
    """
    if should_log:
        logger.error(f"{category.capitalize()} error in {func_name}: {exception}")


@overload
def handle_errors(
    operation_name: str,
) -> Callable[[Callable[P, Result[T, str]]], Callable[P, Result[T, str]]]: ...


@overload
def handle_errors(
    operation_name: str,
    *,
    log_data_errors: bool = False,
    log_runtime_errors: bool = True,
    log_io_errors: bool = True,
    include_analysis_errors: bool = False,
) -> Callable[[Callable[P, Result[T, str]]], Callable[P, Result[T, str]]]: ...


def handle_errors(
    operation_name: str,
    *,
    log_data_errors: bool = False,
    log_runtime_errors: bool = True,
    log_io_errors: bool = True,
    include_analysis_errors: bool = False,
) -> Callable[[Callable[P, Result[T, str]]], Callable[P, Result[T, str]]]:
    """
    Decorator to handle common errors and convert them to Result.Err.

    This decorator wraps functions returning Result[T, str] and catches standard
    exception groups, converting them to Err results with descriptive messages.
    It provides a unified approach to error handling across the codebase.

    Args:
        operation_name: Human-readable description of the operation for error messages.
            Example: "analyzing binary", "decompiling function", "loading config".
        log_data_errors: If True, logs KeyError/AttributeError/TypeError exceptions.
            Default is False since these often indicate expected conditions.
        log_runtime_errors: If True, logs RuntimeError/ValueError exceptions.
            Default is True since these often indicate unexpected failures.
        log_io_errors: If True, logs OSError/IOError exceptions.
            Default is True since these indicate system-level problems.
        include_analysis_errors: If True, also catches AnalysisError exceptions.
            Default is False. Set to True for analysis-related functions.

    Returns:
        Decorator function that wraps the target function with error handling.

    Example:
        Basic usage:

        >>> @handle_errors("loading configuration")
        ... def load_config(path: str) -> Result[dict, str]:
        ...     with open(path) as f:
        ...         return ok(json.load(f))

        With custom logging options:

        >>> @handle_errors("analyzing binary", log_data_errors=True)
        ... def analyze_binary(path: str) -> Result[AnalysisResult, str]:
        ...     # Analysis code here
        ...     return ok(result)

        For analysis functions:

        >>> @handle_errors("processing function", include_analysis_errors=True)
        ... def process_function(r2, func) -> Result[DetectionResult, str]:
        ...     # Function processing with possible AnalysisError
        ...     return ok(detection)

    Notes:
        - The decorated function must return Result[T, str]
        - Exceptions are converted to Err(error_message)
        - Original function signature and docstring are preserved
        - Thread-safe: no shared state between calls
    """
    # Logging flags by category
    logging_flags: dict[str, bool] = {
        ErrorCategory.DATA: log_data_errors,
        ErrorCategory.RUNTIME: log_runtime_errors,
        ErrorCategory.IO: log_io_errors,
        ErrorCategory.ANALYSIS: log_runtime_errors,  # Analysis errors follow runtime logging
    }

    def decorator(func: Callable[P, Result[T, str]]) -> Callable[P, Result[T, str]]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[T, str]:
            try:
                return func(*args, **kwargs)
            except EXCEPTION_GROUPS[ErrorCategory.DATA] as e:
                _log_error(ErrorCategory.DATA, func.__name__, e, logging_flags[ErrorCategory.DATA])
                return err(_format_error_message(ErrorCategory.DATA, operation_name, e))
            except EXCEPTION_GROUPS[ErrorCategory.RUNTIME] as e:
                _log_error(ErrorCategory.RUNTIME, func.__name__, e, logging_flags[ErrorCategory.RUNTIME])
                return err(_format_error_message(ErrorCategory.RUNTIME, operation_name, e))
            except EXCEPTION_GROUPS[ErrorCategory.IO] as e:
                _log_error(ErrorCategory.IO, func.__name__, e, logging_flags[ErrorCategory.IO])
                return err(_format_error_message(ErrorCategory.IO, operation_name, e))

        # If analysis errors should be included, wrap with additional handler
        if include_analysis_errors:
            return _wrap_with_analysis_errors(wrapper, operation_name, logging_flags, func.__name__)

        return wrapper
    return decorator


def _wrap_with_analysis_errors(
    inner_wrapper: Callable[P, Result[T, str]],
    operation_name: str,
    logging_flags: dict[str, bool],
    func_name: str,
) -> Callable[P, Result[T, str]]:
    """
    Wrap a function to also handle AnalysisError exceptions.

    Args:
        inner_wrapper: The already-wrapped function.
        operation_name: Operation description for error messages.
        logging_flags: Dictionary of logging flags by category.
        func_name: Original function name for logging.

    Returns:
        Wrapper function that also catches AnalysisError.
    """
    # Import here to avoid circular imports
    from bannedfuncdetector.analyzer_exceptions import AnalysisError

    @functools.wraps(inner_wrapper)
    def analysis_wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[T, str]:
        try:
            return inner_wrapper(*args, **kwargs)
        except AnalysisError as e:
            _log_error(ErrorCategory.ANALYSIS, func_name, e, logging_flags[ErrorCategory.ANALYSIS])
            return err(_format_error_message(ErrorCategory.ANALYSIS, operation_name, e))

    return analysis_wrapper


def handle_errors_sync(
    operation_name: str,
    *,
    log_errors: bool = True,
    reraise: bool = False,
    default_value: bool | None = None,
) -> Callable[[Callable[P, bool]], Callable[P, bool]]:
    """
    Decorator for non-Result functions that need error handling.

    This decorator is for functions that don't return Result types but
    still need consistent error handling. It catches exceptions and
    either returns a default value or re-raises.

    Args:
        operation_name: Human-readable description of the operation.
        log_errors: If True, logs all caught exceptions.
        reraise: If True, re-raises exceptions after logging.
        default_value: Value to return when exception is caught (if not reraising).

    Returns:
        Decorator function.

    Example:
        >>> @handle_errors_sync("checking plugin availability", default_value=False)
        ... def check_plugin_available(name: str) -> bool:
        ...     return name in available_plugins
    """
    def decorator(func: Callable[P, bool]) -> Callable[P, bool]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> bool:
            try:
                return func(*args, **kwargs)
            except (KeyError, AttributeError, TypeError, RuntimeError,
                    ValueError, OSError, IOError) as e:
                if log_errors:
                    logger.error(f"Error in {func.__name__} ({operation_name}): {e}")
                if reraise:
                    raise
                return default_value if default_value is not None else False

        return wrapper
    return decorator


__all__ = [
    'handle_errors',
    'handle_errors_sync',
    'ErrorCategory',
    'EXCEPTION_GROUPS',
]
