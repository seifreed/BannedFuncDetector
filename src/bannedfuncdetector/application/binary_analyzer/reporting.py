#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Report creation and persistence for binary analysis."""

import os
import json
import logging
from datetime import datetime

from bannedfuncdetector.domain import AnalysisResult, BannedFunction, FunctionDescriptor
from bannedfuncdetector.application.dto_mappers import detection_entity_from_dto
from bannedfuncdetector.application.result_serializers import analysis_result_to_dict

logger = logging.getLogger(__name__)


def _create_analysis_report(
    binary_path: str,
    functions: list[FunctionDescriptor],
    detected: list[BannedFunction],
) -> AnalysisResult:
    """Build the analysis aggregate for one binary."""
    findings = tuple(
        (
            finding
            if isinstance(finding, BannedFunction)
            else detection_entity_from_dto(finding)
        )
        for finding in detected
    )
    return AnalysisResult(
        file_name=os.path.basename(binary_path),
        file_path=os.path.abspath(binary_path),
        total_functions=len(functions),
        detected_functions=findings,
        analysis_date=datetime.now().isoformat(),
    )


def _save_analysis_results(
    report: AnalysisResult, output_dir: str, binary_path: str, verbose: bool = False
) -> str:
    """Save one analysis aggregate as JSON and return the output path."""
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(
        output_dir, f"{os.path.basename(binary_path)}_banned_functions.json"
    )

    with open(output_file, "w", encoding="utf-8") as handle:
        json.dump(analysis_result_to_dict(report), handle, indent=4)

    if verbose:
        logger.info(f"Results saved to {output_file}")

    return output_file


__all__: list[str] = []  # internal module; use explicit imports
