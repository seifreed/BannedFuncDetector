#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Directory Scanner

This module provides directory discovery and scanning functionality
for analyzing multiple binary files in a directory.

Author: Marc Rivero | @seifreed
"""
import os
import json
import concurrent.futures
import logging
from pathlib import Path
from typing import Any
from collections.abc import Iterator

from bannedfuncdetector.infrastructure.config_repository import get_default_config
from bannedfuncdetector.domain.protocols import IConfigRepository
from bannedfuncdetector.file_detection import find_executable_files
from bannedfuncdetector.domain.result import Result, Ok, Err, ok, err
from bannedfuncdetector.domain.types import AnalysisReport
from bannedfuncdetector.domain.config_types import DirectoryAnalysisOptions
from bannedfuncdetector.infrastructure import handle_errors

# Configure module logger
logger = logging.getLogger(__name__)


# =============================================================================
# Directory Validation Functions
# =============================================================================

@handle_errors("validating directory")
def _validate_directory(directory: str) -> Result[Path, str]:
    """
    Validate that a directory exists and is accessible.

    Args:
        directory: Path to the directory to validate.

    Returns:
        Result[Path, str]: Ok with Path object if valid directory,
            or Err with error message if invalid.

    Note:
        Uses @handle_errors decorator for standardized exception handling.
    """
    path = Path(directory)
    if not path.exists():
        error_msg = f"The directory {directory} does not exist."
        logger.error(error_msg)
        return err(error_msg)
    if not path.is_dir():
        error_msg = f"The path {directory} is not a directory."
        logger.error(error_msg)
        return err(error_msg)
    return ok(path)


# =============================================================================
# Executable Discovery Functions
# =============================================================================

@handle_errors("discovering executable files")
def _discover_executable_files(directory: str, verbose: bool = False) -> Result[list[str], str]:
    """
    Discovers PE/ELF/Mach-O executable files in the directory.

    Args:
        directory: Path to the directory to search.
        verbose: If True, enables verbose logging output.

    Returns:
        Result[list[str], str]: Ok with list of paths to executable files,
            or Err with error message if no files were found.

    Note:
        Uses @handle_errors decorator for standardized exception handling.
    """
    executable_files = find_executable_files(directory, file_type="any")

    if not executable_files:
        error_msg = f"No executable files found in {directory}."
        logger.warning(error_msg)
        return err(error_msg)

    if verbose:
        logger.info(f"Found {len(executable_files)} executable files in {directory}.")

    return ok(executable_files)


# =============================================================================
# Analysis Helper Functions
# =============================================================================

def _log_analysis_result(file_path: str, result: AnalysisReport, verbose: bool) -> None:
    """
    Log analysis results for a single file when verbose is enabled.

    Args:
        file_path: Path to the analyzed file.
        result: Analysis result dictionary.
        verbose: If True, logs the result.
    """
    if not verbose:
        return
    logger.info(f"Analysis completed for {file_path}.")
    logger.info(f"    Insecure functions found: {result['unsafe_functions']}")


def _generate_summary(
    directory: str,
    executable_files: list[str],
    results: list[AnalysisReport]
) -> dict[str, Any]:
    """
    Generates the summary data structure for directory analysis.

    Args:
        directory: Path to the analyzed directory.
        executable_files: List of all executable files found.
        results: List of analysis results.

    Returns:
        A dictionary containing the summary data.
    """
    return {
        "directory": directory,
        "total_files": len(executable_files),
        "analyzed_files": len(results),
        "results": results
    }


def _analyze_binary_file(
    executable_file: str,
    output_dir: str | None,
    decompiler_type: str,
    verbose: bool,
    config: IConfigRepository | None = None
) -> Result[AnalysisReport, str]:
    """
    Analyze a single binary file with shared configuration.

    Args:
        executable_file: Path to the executable file to analyze.
        output_dir: Directory for output files.
        decompiler_type: Type of decompiler to use.
        verbose: If True, enables verbose logging.
        config: Configuration repository instance providing analysis settings.
            Required parameter - will raise ValueError if None.

    Returns:
        Result[AnalysisReport, str]: Ok with analysis result dictionary,
            or Err with error message if analysis failed.

    Raises:
        ValueError: If config is None.

    .. deprecated::
        The config parameter will be required in v2.0. Currently raises
        ValueError if None.
    """
    from .binary_analyzer import analyze_binary

    if config is None:
        raise ValueError(
            "config parameter is required. Use create_config_from_file() or "
            "create_config_from_dict() to create a configuration."
        )
    result = analyze_binary(
        executable_file,
        output_dir=output_dir,
        decompiler_type=decompiler_type,
        verbose=verbose,
        worker_limit=config.get("worker_limit", 10),
        config=config,
    )
    # Return the Result directly (no unwrapping needed)
    return result


# =============================================================================
# Parallel Directory Analysis Functions
# =============================================================================

def _handle_future_result(
    future: concurrent.futures.Future,
    executable_file: str,
) -> tuple[str, Result[AnalysisReport, str], Exception | None]:
    """
    Handle the result of a completed future.

    Args:
        future: Completed future from ProcessPoolExecutor.
        executable_file: Path to the executable file being analyzed.

    Returns:
        Tuple of (file_path, Result, exception).
    """
    try:
        result = future.result()
        return executable_file, result, None
    except (OSError, IOError) as e:
        logger.error(f"I/O error analyzing {executable_file}: {e}")
        return executable_file, err(f"I/O error: {str(e)}"), None
    except (RuntimeError, ValueError) as e:
        logger.error(f"Runtime error analyzing {executable_file}: {e}")
        return executable_file, err(f"Runtime error: {str(e)}"), None
    except (AttributeError, TypeError, KeyError) as e:
        logger.error(f"Data error analyzing {executable_file}: {e}")
        return executable_file, err(f"Data error: {str(e)}"), None


def _iter_parallel_results(
    executable_files: list[str],
    output_dir: str | None,
    decompiler_type: str,
    max_workers: int,
    verbose: bool,
    config: IConfigRepository | None = None
) -> Iterator[tuple[str, Result[AnalysisReport, str], Exception | None]]:
    """
    Yield per-file analysis results from parallel execution.

    Args:
        executable_files: List of executable file paths to analyze.
        output_dir: Directory for output files.
        decompiler_type: Type of decompiler to use.
        max_workers: Maximum number of parallel workers.
        verbose: If True, enables verbose logging.
        config: Configuration repository instance.

    Yields:
        Tuples of (file_path, Result, exception) for each file.
    """
    if verbose:
        logger.info(f"Starting parallel analysis with {max_workers} workers...")

    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures: dict[concurrent.futures.Future, str] = {
            executor.submit(
                _analyze_binary_file, executable_file, output_dir, decompiler_type, verbose, None
            ): executable_file
            for executable_file in executable_files
        }

        for future in concurrent.futures.as_completed(futures):
            yield _handle_future_result(future, futures[future])


def _iter_sequential_results(
    executable_files: list[str],
    output_dir: str | None,
    decompiler_type: str,
    verbose: bool,
    config: IConfigRepository | None = None
) -> Iterator[tuple[str, Result[AnalysisReport, str], Exception | None]]:
    """
    Yield per-file analysis results from sequential execution.

    Args:
        executable_files: List of executable file paths to analyze.
        output_dir: Directory for output files.
        decompiler_type: Type of decompiler to use.
        verbose: If True, enables verbose logging.
        config: Configuration repository instance providing analysis settings.
            Required parameter - will raise ValueError if None.

    Yields:
        Tuples of (file_path, Result, exception) for each file.

    Raises:
        ValueError: If config is None.

    .. deprecated::
        The config parameter will be required in v2.0. Currently raises
        ValueError if None.
    """
    if config is None:
        raise ValueError(
            "config parameter is required. Use create_config_from_file() or "
            "create_config_from_dict() to create a configuration."
        )
    if verbose:
        logger.info("Starting sequential analysis...")

    for executable_file in executable_files:
        try:
            if verbose:
                logger.info(f"Analyzing {executable_file}...")

            result = _analyze_binary_file(
                executable_file,
                output_dir,
                decompiler_type,
                verbose,
                config,
            )
            yield executable_file, result, None
        except (OSError, IOError) as e:
            logger.error(f"I/O error analyzing {executable_file}: {e}")
            yield executable_file, err(f"I/O error: {str(e)}"), None
        except (RuntimeError, ValueError) as e:
            # RuntimeError: r2pipe or analysis execution failure
            # ValueError: Invalid data or configuration errors
            logger.error(f"Runtime error analyzing {executable_file}: {e}")
            yield executable_file, err(f"Runtime error: {str(e)}"), None
        except (AttributeError, TypeError, KeyError) as e:
            # Data structure or type errors during analysis
            logger.error(f"Data error analyzing {executable_file}: {e}")
            yield executable_file, err(f"Data error: {str(e)}"), None


def _collect_analysis_results(
    result_iter: Iterator[tuple[str, Result[AnalysisReport, str], Exception | None]],
    verbose: bool
) -> list[AnalysisReport]:
    """
    Collect successful analysis results from an iterator.

    Args:
        result_iter: Iterator yielding (file_path, Result, exception) tuples.
        verbose: If True, enables verbose logging.

    Returns:
        List of successful analysis results.
    """
    results: list[AnalysisReport] = []
    for executable_file, result, error in result_iter:
        if error is not None:
            if verbose:
                logger.error(f"Error analyzing {executable_file}: {str(error)}")
            continue
        # Check if Result is Ok and unwrap
        if isinstance(result, Ok):
            unwrapped_result = result.unwrap()
            results.append(unwrapped_result)
            _log_analysis_result(executable_file, unwrapped_result, verbose)
        elif isinstance(result, Err) and verbose:
            logger.error(f"Analysis failed for {executable_file}: {result.error}")
    return results


def _process_directory_results(
    executable_files: list[str],
    output_dir: str | None,
    decompiler_type: str,
    max_workers: int,
    verbose: bool,
    parallel: bool,
    config: IConfigRepository | None = None
) -> list[AnalysisReport]:
    """
    Process all files in a directory (parallel or sequential).

    Args:
        executable_files: List of executable file paths to analyze.
        output_dir: Directory for output files.
        decompiler_type: Type of decompiler to use.
        max_workers: Maximum number of parallel workers.
        verbose: If True, enables verbose logging.
        parallel: If True, uses parallel processing.
        config: Configuration repository instance providing analysis settings.
            Required parameter - will raise ValueError if None.

    Returns:
        List of analysis results.

    Raises:
        ValueError: If config is None.

    .. deprecated::
        The config parameter will be required in v2.0. Currently raises
        ValueError if None.
    """
    if config is None:
        raise ValueError(
            "config parameter is required. Use create_config_from_file() or "
            "create_config_from_dict() to create a configuration."
        )
    if parallel:
        return _collect_analysis_results(
            _iter_parallel_results(
                executable_files, output_dir, decompiler_type, max_workers, verbose, config
            ),
            verbose,
        )
    else:
        return _collect_analysis_results(
            _iter_sequential_results(
                executable_files, output_dir, decompiler_type, verbose, config
            ),
            verbose,
        )


# =============================================================================
# Summary and Output Functions
# =============================================================================

def _save_directory_results(
    output_dir: str,
    summary: dict[str, Any],
    verbose: bool = False
) -> None:
    """
    Saves the directory analysis summary to a JSON file.

    Args:
        output_dir: Directory where results should be saved.
        summary: The summary dictionary to save.
        verbose: If True, enables verbose logging output.
    """
    summary_file = os.path.join(output_dir, "summary.json")
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=4)

    if verbose:
        logger.info(f"Summary saved to {summary_file}")


# =============================================================================
# Main Directory Analysis Function
# =============================================================================


def _prepare_directory_analysis(
    directory: str,
    verbose: bool,
) -> Result[list[str], str]:
    """
    Validates directory and discovers executable files for analysis.

    Performs input validation on the directory path and discovers
    PE/ELF/Mach-O executable files within the directory.

    Args:
        directory: Path to the directory to analyze.
        verbose: If True, enables verbose logging output.

    Returns:
        Result containing list of executable file paths if successful,
        or Err with error message if validation fails or no files found.
    """
    validation_result = _validate_directory(directory)
    if isinstance(validation_result, Err):
        return validation_result

    executable_files_result = _discover_executable_files(directory, verbose)
    if isinstance(executable_files_result, Err):
        return executable_files_result

    return ok(executable_files_result.unwrap())


def _execute_directory_analysis(
    directory: str,
    executable_files: list[str],
    options: DirectoryAnalysisOptions,
) -> dict[str, Any]:
    """
    Executes the core directory analysis logic.

    Processes all executable files in the directory, generates a summary,
    and optionally saves results to disk.

    Args:
        directory: Path to the directory being analyzed.
        executable_files: List of executable file paths to analyze.
        options: Directory analysis options containing output_dir, decompiler_type,
            max_workers, verbose, parallel, and config. The config field is required.

    Returns:
        Summary dictionary containing analysis results.

    Raises:
        ValueError: If options.config is None.

    .. deprecated::
        The options.config field will be required in v2.0. Currently raises
        ValueError if None.
    """
    if options.config is None:
        raise ValueError(
            "options.config is required. Use create_config_from_file() or "
            "create_config_from_dict() to create a configuration."
        )
    config = options.config

    if options.output_dir:
        os.makedirs(options.output_dir, exist_ok=True)

    # Resolve max_workers - use provided value or fall back to config default
    max_workers = options.max_workers if options.max_workers is not None else config.get("max_workers", 4)

    results = _process_directory_results(
        executable_files, options.output_dir, options.decompiler_type, max_workers,
        options.verbose, options.parallel, config
    )

    summary = _generate_summary(directory, executable_files, results)

    if options.output_dir:
        _save_directory_results(options.output_dir, summary, options.verbose)

    return summary


def _resolve_analysis_params(
    decompiler_type: str | None,
    max_workers: int | None,
    config: IConfigRepository,
) -> tuple[str, int]:
    """Resolve decompiler type and max_workers from config if not provided."""
    resolved_decompiler = decompiler_type if decompiler_type is not None else config["decompiler"]["type"]
    resolved_workers = max_workers if max_workers is not None else config.get("max_workers", 4)
    return resolved_decompiler, resolved_workers


def analyze_directory(
    directory: str,
    options: DirectoryAnalysisOptions | None = None,
    *,
    output_dir: str | None = None,
    decompiler_type: str | None = None,
    max_workers: int | None = None,
    verbose: bool = False,
    parallel: bool = True,
    config: IConfigRepository | None = None
) -> Result[dict[str, Any], str]:
    """
    Analyzes all PE binaries in a directory for banned/insecure functions.

    Args:
        directory: Path to the directory containing PE binaries to analyze.
        options: DirectoryAnalysisOptions containing output_dir, decompiler_type,
            max_workers, verbose, parallel, and config. If provided, individual
            keyword arguments are ignored.
        output_dir: Directory where results should be saved. None to skip saving.
            Deprecated: Use options parameter instead.
        decompiler_type: Decompiler to use ('default', 'r2ghidra', 'r2dec', 'decai').
            Deprecated: Use options parameter instead.
        max_workers: Maximum parallel workers. None uses config default.
            Deprecated: Use options parameter instead.
        verbose: Enable detailed logging output.
            Deprecated: Use options parameter instead.
        parallel: Use parallel processing (ProcessPoolExecutor).
            Deprecated: Use options parameter instead.
        config: Configuration repository instance providing analysis settings.
            Required in v2.0. Use create_config_from_file() or create_config_from_dict().

    Returns:
        Result with analysis summary dict, or Err if directory invalid.

    .. deprecated::
        Passing None for config is deprecated and will raise an error in v2.0.
    """
    # Support both options object and individual parameters for backward compatibility
    if options is not None:
        if options.config is None:
            import warnings
            warnings.warn(
                "Passing None for config is deprecated. Use create_config_from_file() or create_config_from_dict().",
                DeprecationWarning,
                stacklevel=2
            )
            resolved_options = DirectoryAnalysisOptions(
                output_dir=options.output_dir,
                decompiler_type=options.decompiler_type,
                max_workers=options.max_workers,
                verbose=options.verbose,
                parallel=options.parallel,
                config=get_default_config(),
            )
        else:
            resolved_options = options
        resolved_verbose = options.verbose
    else:
        if config is None:
            import warnings
            warnings.warn(
                "Passing None for config is deprecated. Use create_config_from_file() or create_config_from_dict().",
                DeprecationWarning,
                stacklevel=2
            )
            resolved_config = get_default_config()
        else:
            resolved_config = config
        # Resolve decompiler_type from config if not provided
        resolved_decompiler = (
            decompiler_type if decompiler_type is not None
            else resolved_config["decompiler"]["type"]
        )
        resolved_options = DirectoryAnalysisOptions(
            output_dir=output_dir,
            decompiler_type=resolved_decompiler,
            max_workers=max_workers,
            verbose=verbose,
            parallel=parallel,
            config=resolved_config,
        )
        resolved_verbose = verbose

    preparation_result = _prepare_directory_analysis(directory, resolved_verbose)
    if isinstance(preparation_result, Err):
        return preparation_result

    executable_files = preparation_result.unwrap()

    summary = _execute_directory_analysis(directory, executable_files, resolved_options)
    return ok(summary)


__all__ = [
    "analyze_directory",
]
