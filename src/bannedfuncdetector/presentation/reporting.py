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
from typing import Any

logger = logging.getLogger(__name__)


def display_final_results(result: Any) -> None:
    """
    Displays the final results of the analysis.

    Args:
        result: The analysis result (dict or list of dicts).
    """
    if not result:
        logger.warning("No results found or errors occurred during analysis.")
        return

    logger.info("Analysis completed.")
    results_list = _normalize_results(result)
    total_files = len(results_list)
    total_banned = sum(len(r.get("insecure_functions_details", [])) for r in results_list)

    logger.info(f"Total files analyzed: {total_files}")
    logger.info(f"Insecure functions found: {total_banned}")

    if total_banned > 0:
        logger.warning("Detected insecure functions:")
        for file_result in results_list:
            _log_detected_functions(file_result.get("insecure_functions_details", []))


def _normalize_results(result: Any) -> list[dict]:
    """
    Normalize result payload into a list of result dictionaries.
    """
    if isinstance(result, list):
        return result
    return [result]


def _log_detected_functions(detected: list[dict]) -> None:
    """
    Log detected insecure functions in a consistent format.
    """
    for func in detected:
        address = _format_address(func.get('address', 0))
        logger.warning(f"  - {func['name']} at {address}")
        if 'banned_functions' in func:
            logger.warning(f"    Banned functions: {', '.join(func['banned_functions'])}")


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
