"""Serialization helpers for domain analysis results."""

from __future__ import annotations

from bannedfuncdetector.application.analysis_outcome import (
    DirectoryAnalysisOutcome,
    OperationalNotice,
)
from bannedfuncdetector.domain import (
    AnalysisResult,
    BannedFunction,
    DirectoryAnalysisSummary,
)


def banned_function_to_dict(entity: BannedFunction) -> dict[str, object]:
    """Serialize a domain detection entity for JSON/reporting boundaries."""
    return {
        "name": entity.name,
        "address": hex(entity.address),
        "size": entity.size,
        "banned_functions": list(entity.banned_calls),
        "detection_method": entity.detection_method,
        "type": entity.category,
    }


def analysis_result_to_dict(entity: AnalysisResult) -> dict[str, object]:
    """Serialize a binary-analysis aggregate for JSON/reporting boundaries."""
    return {
        "binary": entity.file_path,
        "file_name": entity.file_name,
        "total_functions": entity.total_functions,
        "unsafe_functions": entity.insecure_count,
        "results": [
            banned_function_to_dict(finding) for finding in entity.detected_functions
        ],
        "analysis_date": entity.analysis_date,
        "analyzer": entity.analyzer,
    }


def directory_summary_to_dict(entity: DirectoryAnalysisSummary) -> dict[str, object]:
    """Serialize a directory-analysis aggregate for JSON/reporting boundaries."""
    return {
        "directory": entity.directory,
        "total_files": entity.total_files,
        "analyzed_files": entity.analyzed_files,
        "results": [
            analysis_result_to_dict(result) for result in entity.analyzed_results
        ],
    }


def directory_outcome_to_dict(entity: DirectoryAnalysisOutcome) -> dict[str, object]:
    payload = directory_summary_to_dict(entity.summary)
    if entity.operational_notices:
        payload["operational_notices"] = [
            operational_notice_to_dict(notice) for notice in entity.operational_notices
        ]
    return payload


def operational_notice_to_dict(entity: OperationalNotice) -> dict[str, object]:
    return {
        "message": entity.message,
        "file_path": entity.file_path,
    }


__all__ = [
    "analysis_result_to_dict",
    "banned_function_to_dict",
    "directory_outcome_to_dict",
    "directory_summary_to_dict",
    "operational_notice_to_dict",
]
