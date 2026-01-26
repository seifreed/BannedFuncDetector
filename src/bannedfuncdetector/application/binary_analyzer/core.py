#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Binary Analyzer Core

This module provides the main analyze_binary() function and R2BinaryAnalyzer class
for detecting banned/insecure functions in binary files.

Author: Marc Rivero | @seifreed
"""
import os
import logging
from typing import Any, Callable

from bannedfuncdetector.domain.protocols import IR2Client, IConfigRepository, IDecompilerOrchestrator
from bannedfuncdetector.infrastructure.config_repository import get_default_config
from bannedfuncdetector.domain.result import Result, Ok, Err, ok, err
from bannedfuncdetector.domain.types import (
    DetectionResult,
    FunctionInfo,
    AnalysisResultType,
)
from bannedfuncdetector.domain.config_types import BinaryAnalysisOptions
from bannedfuncdetector.analyzer_exceptions import AnalysisError
from bannedfuncdetector.domain import AnalysisResult, BannedFunction

from .operations import (
    _extract_functions,
    _parse_result_address,
    _validate_and_resolve_params,
    _setup_binary_analysis,
    _execute_detection,
    _validate_binary_input,
)
from .detection import (
    _validate_analysis_inputs,
    _check_function_name_banned,
    _decompile_and_search,
)
from .reporting import _create_analysis_report, _save_analysis_results

# Configure module logger
logger = logging.getLogger(__name__)


# =============================================================================
# Single Function Analysis
# =============================================================================

def _analyze_function_core(
    r2: IR2Client,
    func: FunctionInfo,
    validated_banned: set[str],
    decompiler_type: str,
    verbose: bool,
) -> Result[DetectionResult, str]:
    """
    Core function analysis logic with decorator-based error handling.

    Args:
        r2: An r2pipe instance connected to the binary.
        func: Function info dict with 'name' and 'offset' keys.
        validated_banned: Validated set of banned function names.
        decompiler_type: Decompiler to use.
        verbose: Enable verbose logging.

    Returns:
        Result[DetectionResult, str]: Ok with detection result if banned functions found,
            Err with error message if analysis failed or no banned functions detected.
    """
    from bannedfuncdetector.infrastructure import handle_errors

    @handle_errors("analyzing function", include_analysis_errors=True)
    def _inner() -> Result[DetectionResult, str]:
        func_name = func.get("name", "")
        func_addr = func.get("offset", 0)

        # Check if function name matches banned list
        name_match_result = _check_function_name_banned(
            func_name, func_addr, validated_banned, verbose
        )
        if isinstance(name_match_result, Ok):
            return name_match_result

        # Decompile and search for banned calls
        decompile_result = _decompile_and_search(
            r2, func_name, func_addr, validated_banned, decompiler_type, verbose
        )
        if isinstance(decompile_result, Ok):
            return decompile_result

        return err(f"No banned functions found in {func_name}")

    return _inner()


def analyze_function(
    r2: IR2Client,
    func: FunctionInfo,
    banned_functions: set[str] | None = None,
    decompiler_type: str = "default",
    verbose: bool = False,
    config: IConfigRepository | None = None
) -> Result[DetectionResult, str]:
    """
    Analyzes a single function for banned/insecure function calls.

    Performs name-based and decompilation-based detection for banned calls.

    Args:
        r2: An r2pipe instance connected to the binary.
        func: Function info dict with 'name' and 'offset' keys.
        banned_functions: Set of banned function names (uses defaults if None).
        decompiler_type: Decompiler to use ('default', 'r2ghidra', 'r2dec', 'decai').
        verbose: Enable verbose logging.
        config: Configuration repository instance providing analysis settings.

    Returns:
        Result[DetectionResult, str]: Ok with detection result if banned functions found,
            Err with error message if analysis failed or no banned functions detected.

    .. deprecated::
        Passing None for config is deprecated and will raise an error in v2.0.
    """
    if config is None:
        import warnings
        warnings.warn(
            "Passing None for config is deprecated. Use create_config_from_file() or create_config_from_dict().",
            DeprecationWarning,
            stacklevel=2
        )
        config = get_default_config()
    validated_banned_result = _validate_analysis_inputs(func, banned_functions)
    if isinstance(validated_banned_result, Err):
        return validated_banned_result

    validated_banned = validated_banned_result.unwrap()

    return _analyze_function_core(
        r2, func, validated_banned, decompiler_type, verbose
    )


# =============================================================================
# Binary Analysis Main Function
# =============================================================================

def _finalize_analysis(
    binary_path: str,
    functions: list[FunctionInfo],
    results: list[DetectionResult],
    output_dir: str | None,
    verbose: bool,
) -> AnalysisResultType:
    """
    Create analysis report and optionally save results.

    Args:
        binary_path: Path to the analyzed binary.
        functions: List of all functions found in the binary.
        results: List of detection results.
        output_dir: Optional output directory for saving results.
        verbose: Enable verbose logging.

    Returns:
        AnalysisResultType: Ok with analysis report dictionary.
    """
    report = _create_analysis_report(binary_path, functions, results)

    if output_dir:
        _save_analysis_results(report, output_dir, binary_path, verbose)

    return ok(report)


def analyze_binary(
    binary_path: str,
    options: BinaryAnalysisOptions | None = None,
    *,
    output_dir: str | None = None,
    decompiler_type: str | None = None,
    verbose: bool = False,
    worker_limit: int | None = None,
    config: IConfigRepository | None = None,
    parallel_executor: Callable[..., list[DetectionResult]] | None = None,
    decompiler_orchestrator: IDecompilerOrchestrator | None = None
) -> AnalysisResultType:
    """
    Analyzes a single binary file for banned/insecure functions.

    Opens the binary with radare2, extracts functions, and detects banned calls.

    Args:
        binary_path: Path to the binary file to analyze.
        options: BinaryAnalysisOptions containing output_dir, decompiler_type,
            verbose, worker_limit, and config. If provided, individual keyword
            arguments are ignored (except parallel_executor and decompiler_orchestrator).
        output_dir: Directory for JSON output (None to skip saving).
        decompiler_type: Decompiler ('default', 'r2ghidra', 'r2dec', 'decai').
        verbose: Enable detailed logging.
        worker_limit: Max concurrent workers (default from config).
        config: Configuration repository instance providing analysis settings.
        parallel_executor: Optional custom parallel executor (for dependency injection).
        decompiler_orchestrator: Optional IDecompilerOrchestrator instance for DI.

    Returns:
        AnalysisResultType: Ok with analysis result dict, or Err with error message.

    .. deprecated::
        Passing None for config is deprecated and will raise an error in v2.0.
    """
    # Step 1: Validate and resolve parameters
    params_result = _validate_and_resolve_params(
        binary_path, options, output_dir, decompiler_type,
        verbose, worker_limit, config, decompiler_orchestrator
    )
    if isinstance(params_result, Err):
        return params_result

    params = params_result.unwrap()

    # Step 2: Setup binary analysis (open r2, extract functions)
    setup_result = _setup_binary_analysis(binary_path, params)
    if isinstance(setup_result, Err):
        return setup_result

    r2, functions = setup_result.unwrap()

    # Step 3: Execute detection with proper cleanup
    try:
        results = _execute_detection(
            r2, functions, params, parallel_executor, analyze_function
        )

        # Step 4: Finalize analysis (create report, save results)
        return _finalize_analysis(
            binary_path, functions, results, params.output_dir, params.verbose
        )

    except (AnalysisError, RuntimeError) as e:
        logger.error(f"Error during detection for {binary_path}: {str(e)}")
        return err(f"Detection error: {str(e)}")
    finally:
        r2.quit()


# =============================================================================
# PROTOCOL IMPLEMENTATION: IBinaryAnalyzer
# =============================================================================

class R2BinaryAnalyzer:
    """
    Implementation of IBinaryAnalyzer protocol using r2pipe.

    This class wraps the existing analyze_binary() functionality to provide
    a clean, protocol-compliant interface for binary analysis.

    Attributes:
        decompiler_type: The type of decompiler to use for analysis.
        verbose: Whether to enable verbose logging output.
        _config: Configuration repository instance for dependency injection.
        _r2_factory: Factory callable for creating R2Client instances.
    """

    _config: IConfigRepository

    def __init__(
        self,
        decompiler_type: str = "default",
        verbose: bool = False,
        r2_factory: Callable[[str], IR2Client] | None = None,
        config: IConfigRepository | None = None
    ):
        """
        Initialize the R2BinaryAnalyzer.

        Args:
            decompiler_type: Decompiler type ('default', 'r2ghidra', 'r2dec', 'decai').
            verbose: Enable detailed logging output.
            r2_factory: Factory callable for creating R2Client instances.
            config: Configuration repository instance.

        .. deprecated::
            Passing None for config is deprecated and will raise an error in v2.0.
        """
        self.decompiler_type = decompiler_type
        self.verbose = verbose
        if r2_factory is None:
            from bannedfuncdetector.factories import create_r2_client
            r2_factory = create_r2_client
        self._r2_factory = r2_factory
        if config is None:
            import warnings
            warnings.warn(
                "Passing None for config is deprecated. Use create_config_from_file() or create_config_from_dict().",
                DeprecationWarning,
                stacklevel=2
            )
            self._config = get_default_config()
        else:
            self._config = config

    def _create_empty_analysis_result(self, file_path: str) -> AnalysisResult:
        """Create an empty AnalysisResult for failed analyses."""
        from datetime import datetime
        return AnalysisResult(
            file_name=os.path.basename(file_path),
            file_path=os.path.abspath(file_path),
            total_functions=0,
            detected_functions=tuple(),
            analysis_date=datetime.now().isoformat(),
            analyzer="R2BinaryAnalyzer - BannedFuncDetector"
        )

    def _convert_to_banned_functions(self, raw_results: list[Any]) -> list[BannedFunction]:
        """Convert raw detection results to BannedFunction instances."""
        detected: list[BannedFunction] = []
        for entry in raw_results:
            detected.append(BannedFunction(
                name=entry.get('name', 'unknown'),
                address=_parse_result_address(entry.get('address')),
                size=entry.get('size', 0),
                banned_calls=tuple(entry.get('banned_functions', [])),
                detection_method=entry.get('detection_method', 'unknown'),
                category=entry.get('type', None)
            ))
        return detected

    def analyze(self, file_path: str) -> AnalysisResult:
        """
        Perform comprehensive analysis on a binary file.

        Args:
            file_path: Absolute path to the binary file to analyze.

        Returns:
            AnalysisResult: Immutable dataclass with analysis results.
        """
        from datetime import datetime

        analysis_result = analyze_binary(
            binary_path=file_path,
            output_dir=None,
            decompiler_type=self.decompiler_type,
            verbose=self.verbose,
            worker_limit=None,
            config=self._config
        )

        if analysis_result.is_err():
            return self._create_empty_analysis_result(file_path)

        raw_result = analysis_result.unwrap()
        detected_functions = self._convert_to_banned_functions(raw_result.get('results', []))

        return AnalysisResult(
            file_name=os.path.basename(file_path),
            file_path=os.path.abspath(file_path),
            total_functions=raw_result.get('total_functions', 0),
            detected_functions=tuple(detected_functions),
            analysis_date=datetime.now().isoformat(),
            analyzer="R2BinaryAnalyzer - BannedFuncDetector"
        )

    def get_functions(self, r2: IR2Client) -> list[FunctionInfo]:
        """
        Extract all functions from a binary using an active r2pipe instance.

        Args:
            r2: An active r2pipe instance connected to the binary.

        Returns:
            List of function dictionaries.
        """
        functions_result = _extract_functions(r2, verbose=self.verbose)
        if isinstance(functions_result, Err):
            return []
        return functions_result.unwrap()


__all__ = [
    "analyze_function",
    "analyze_binary",
    "R2BinaryAnalyzer",
    "_validate_binary_input",
]
