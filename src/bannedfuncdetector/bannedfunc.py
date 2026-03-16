#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CLI entry point for BannedFuncDetector."""

import os
import logging

from .cli import parse_arguments
from .cli_bootstrap import configure_logging, validate_requirements
from .cli_dispatch import dispatch_cli_analysis
from .infrastructure.validators import check_python_version, check_requirements
from .presentation.reporting import display_final_results
from .factories import create_application_wiring
from .application.binary_analyzer import analyze_binary
from .application.directory_scanner import analyze_directory

logger = logging.getLogger(__name__)


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

    wiring = create_application_wiring()
    os.makedirs(args.output, exist_ok=True)
    result = dispatch_cli_analysis(
        args,
        wiring,
        analyze_binary=analyze_binary,
        analyze_directory=analyze_directory,
        logger=logger,
    )

    if result is None:
        logger.error("Analysis failed. No results produced.")
        return 1

    display_final_results(result)
    return 0


if __name__ == "__main__":
    main()
