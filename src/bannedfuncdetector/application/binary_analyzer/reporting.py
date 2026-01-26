#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Analysis Reporting

This module provides functions for creating and saving analysis reports.

Author: Marc Rivero | @seifreed
"""
import os
import json
import logging
from typing import Any

from bannedfuncdetector.domain.types import (
    DetectionResult,
    FunctionInfo,
    AnalysisReport,
)

# Configure module logger
logger = logging.getLogger(__name__)


# =============================================================================
# Analysis Report Functions
# =============================================================================

def _create_analysis_report(
    binary_path: str,
    functions: list[FunctionInfo] | list[dict[str, Any]],
    detected: list[DetectionResult]
) -> AnalysisReport:
    """
    Creates the analysis report dictionary.

    Args:
        binary_path: Path to the analyzed binary.
        functions: List of all functions found in the binary.
        detected: List of detection results for banned functions.

    Returns:
        A dictionary containing the complete analysis report.
    """
    return {
        "binary": binary_path,
        "total_functions": len(functions),
        "unsafe_functions": len(detected),
        "results": detected
    }


def _save_analysis_results(
    report: AnalysisReport,
    output_dir: str,
    binary_path: str,
    verbose: bool = False
) -> str:
    """
    Saves the analysis results to a JSON file.

    Args:
        report: The analysis report dictionary to save.
        output_dir: Directory where results should be saved.
        binary_path: Path to the analyzed binary (used for filename).
        verbose: If True, enables verbose logging output.

    Returns:
        The path to the saved output file.
    """
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(
        output_dir,
        f"{os.path.basename(binary_path)}_banned_functions.json"
    )

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4)

    if verbose:
        logger.info(f"Results saved to {output_file}")

    return output_file


__all__ = [
    "_create_analysis_report",
    "_save_analysis_results",
]
