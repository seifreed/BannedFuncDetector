#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reporting module for BannedFuncDetector - Report generation and display.

This module is part of the presentation layer and handles report generation,
formatting, and display for the BannedFuncDetector tool.

Author: Marc Rivero | @seifreed
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from bannedfuncdetector.application.analysis_outcome import BinaryAnalysisOutcome, DirectoryAnalysisOutcome
from bannedfuncdetector.domain import AnalysisResult, BannedFunction

logger = logging.getLogger(__name__)


def display_final_results(result: BinaryAnalysisOutcome | DirectoryAnalysisOutcome) -> None:
    """
    Displays the final results of the analysis.

    Args:
        result: The analysis result entity.
    """
    if not result:
        logger.warning("No results found or errors occurred during analysis.")
        return

    logger.info("Analysis completed.")
    results_list = _normalize_results(result)
    total_files = len(results_list)
    total_banned = sum(_count_detected_functions(r) for r in results_list)

    logger.info(f"Total files analyzed: {total_files}")
    logger.info(f"Insecure functions found: {total_banned}")
    for notice in result.operational_notices:
        if notice.file_path:
            logger.warning(f"Operational notice for {notice.file_path}: {notice.message}")
        else:
            logger.warning(f"Operational notice: {notice.message}")

    if total_banned > 0:
        logger.warning("Detected insecure functions:")
        for file_result in results_list:
            _log_detected_functions(_get_detected_functions(file_result))


def _normalize_results(result: BinaryAnalysisOutcome | DirectoryAnalysisOutcome) -> list[AnalysisResult]:
    """Normalize result payload into a list of analysis entities."""
    if isinstance(result, BinaryAnalysisOutcome):
        return [result.report]
    return list(result.summary.analyzed_results)


def _log_detected_functions(detected: Sequence[BannedFunction]) -> None:
    """Log detected insecure functions in a consistent format."""
    for func in detected:
        address = _format_address(func.address)
        logger.warning(f"  - {func.name} at {address}")
        logger.warning(f"    Banned functions: {', '.join(func.banned_calls)}")


def _get_detected_functions(file_result: AnalysisResult) -> list[BannedFunction]:
    """Return detected function details from the current domain result."""
    return list(file_result.detected_functions)


def _count_detected_functions(file_result: AnalysisResult) -> int:
    """Count findings for the current domain result format."""
    return file_result.insecure_count


def _format_address(address: Any) -> str:
    """
    Format an address value for display.
    """
    if isinstance(address, int):
        return hex(address)
    if isinstance(address, str):
        return address
    return hex(0)


__all__ = [
    "display_final_results",
]
