#!/usr/bin/env python3
"""CLI entry point and convenience library API for BannedFuncDetector."""

import os
import logging

from .cli import parse_arguments
from .cli_bootstrap import configure_logging, validate_requirements
from .cli_dispatch import dispatch_cli_analysis
from .infrastructure.validators import check_python_version, check_requirements
from .presentation.reporting import display_final_results
from .factories import create_application_wiring
from .application.binary_analyzer import analyze_binary as _analyze_binary
from .application.directory_scanner import analyze_directory as _analyze_directory
from .application.contracts import (
    BinaryAnalysisRequest,
    DirectoryAnalysisRequest,
)
from .application.analysis_outcome import (
    BinaryAnalysisOutcome,
    DirectoryAnalysisOutcome,
)
from .application.analysis_error import ExecutionFailure
from .domain.result import Result

logger = logging.getLogger(__name__)


def analyze_file(
    file_path: str,
    decompiler_type: str = "default",
    output_dir: str = "output",
    *,
    verbose: bool = False,
    force_decompiler: bool = False,
    skip_banned: bool = False,
    skip_analysis: bool = False,
) -> Result[BinaryAnalysisOutcome, ExecutionFailure]:
    """Analyze a single binary for banned functions.

    Convenience wrapper that builds the default application wiring internally.
    Returns ``Ok(outcome)`` on success or ``Err(failure)`` on error.
    """
    wiring = create_application_wiring()
    request = BinaryAnalysisRequest.for_runtime(
        wiring,
        output_dir=output_dir,
        decompiler_type=decompiler_type,
        verbose=verbose,
        force_decompiler=force_decompiler,
        skip_banned=skip_banned,
        skip_analysis=skip_analysis,
    )
    return _analyze_binary(file_path, request=request)


def analyze_directory(
    directory: str,
    output_dir: str = "output",
    decompiler_type: str = "default",
    *,
    parallel: bool = False,
    max_workers: int | None = None,
    verbose: bool = False,
    force_decompiler: bool = False,
    skip_banned: bool = False,
    skip_analysis: bool = False,
) -> Result[DirectoryAnalysisOutcome, ExecutionFailure]:
    """Analyze every executable in a directory for banned functions.

    Convenience wrapper that builds the default application wiring internally.
    Returns ``Ok(outcome)`` on success or ``Err(failure)`` on error.
    """
    wiring = create_application_wiring()
    request = DirectoryAnalysisRequest.for_runtime(
        wiring,
        output_dir=output_dir,
        decompiler_type=decompiler_type,
        parallel=parallel,
        max_workers=max_workers,
        verbose=verbose,
        force_decompiler=force_decompiler,
        skip_banned=skip_banned,
        skip_analysis=skip_analysis,
    )
    return _analyze_directory(directory, request=request)


def main() -> int:
    """Run the CLI entry point."""
    configure_logging()
    check_python_version()
    args = parse_arguments()
    validate_requirements(
        args.skip_requirements,
        check_requirements=check_requirements,
        logger=logger,
    )

    if args.check_requirements and not args.file and not args.directory:
        return 0

    if args.skip_banned and args.skip_analysis:
        logger.warning(
            "Both --skip-banned and --skip-analysis are set: no detection runs, "
            "so a result of zero findings means nothing was checked, not that the "
            "target is clean."
        )

    wiring = create_application_wiring()
    try:
        os.makedirs(args.output, exist_ok=True)
    except OSError as exc:
        logger.error("Cannot use output directory '%s': %s", args.output, exc)
        return 1
    result = dispatch_cli_analysis(
        args,
        wiring,
        analyze_binary=_analyze_binary,
        analyze_directory=_analyze_directory,
        logger=logger,
    )

    if result is None:
        logger.error("Analysis failed. No results produced.")
        return 1

    display_final_results(result)
    return 0


if __name__ == "__main__":
    main()
