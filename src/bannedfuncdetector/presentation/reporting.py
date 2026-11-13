"""
Reporting module for BannedFuncDetector - Report generation and display.

This module is part of the presentation layer and handles report generation,
formatting, and display for the BannedFuncDetector tool.

Author: Marc Rivero | @seifreed
"""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from typing import Any

from bannedfuncdetector.application.analysis_outcome import (
    BinaryAnalysisOutcome,
    DirectoryAnalysisOutcome,
)
from bannedfuncdetector.domain import AnalysisResult, BannedFunction

logger = logging.getLogger(__name__)


def display_final_results(
    result: BinaryAnalysisOutcome | DirectoryAnalysisOutcome,
) -> None:
    """
    Displays the final results of the analysis.

    Args:
        result: The analysis result entity.
    """
    if not result:
        logger.warning(
            "No analysis results available",
            extra={
                "operation": "final_report",
                "event_name": "analysis_summary",
                "outcome": "empty",
                "file_count": 0,
                "insecure_count": 0,
            },
        )
        return

    results_list = _normalize_results(result)
    total_files = _total_files_count(result)
    total_banned = sum(_count_detected_functions(r) for r in results_list)

    logger.info(
        "Analysis completed: %d files analyzed, %d insecure functions found",
        total_files,
        total_banned,
        extra={
            "operation": "final_report",
            "event_name": "analysis_summary",
            "outcome": "issues_found" if total_banned else "clean",
            "file_count": total_files,
            "insecure_count": total_banned,
        },
    )
    for notice in result.operational_notices:
        extra: dict[str, str] = {
            "event_name": "operational_notice",
            "outcome": "degraded",
        }
        if notice.file_path:
            extra["file_name"] = os.path.basename(notice.file_path)
        logger.warning("Operational notice", extra=extra)

    if total_banned > 0:
        for file_result in results_list:
            _log_detected_functions(
                _get_detected_functions(file_result), file_result.file_name
            )


def _normalize_results(
    result: BinaryAnalysisOutcome | DirectoryAnalysisOutcome,
) -> list[AnalysisResult]:
    """Normalize result payload into a list of analysis entities."""
    if isinstance(result, BinaryAnalysisOutcome):
        return [result.report]
    return list(result.summary.analyzed_results)


def _total_files_count(
    result: BinaryAnalysisOutcome | DirectoryAnalysisOutcome,
) -> int:
    """Total files the analysis covered.

    For a directory this is every file found (``summary.total_files``), not
    just the ones that produced a result — binaries that fail to open are still
    part of the run and must be counted.
    """
    if isinstance(result, BinaryAnalysisOutcome):
        return 1
    return result.summary.total_files


def _log_detected_functions(detected: Sequence[BannedFunction], file_name: str) -> None:
    """Log detected insecure functions in a consistent format."""
    for func in detected:
        address = _format_address(func.address)
        logger.warning(
            "Insecure function detected: %s at %s",
            func.name,
            address,
            extra={
                "event_name": "banned_function_detected",
                "outcome": "success",
                "file_name": file_name,
                "function_name": func.name,
                "address": func.address,
                "detection_method": func.detection_method,
                "banned_calls": ",".join(func.banned_calls),
            },
        )


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
