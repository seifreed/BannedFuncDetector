from __future__ import annotations

from dataclasses import dataclass

from bannedfuncdetector.domain import (
    AnalysisResult,
    DirectoryAnalysisSummary,
    FunctionDescriptor,
)


@dataclass(frozen=True)
class OperationalNotice:
    message: str
    file_path: str | None = None


@dataclass(frozen=True)
class BinaryAnalysisOutcome:
    report: AnalysisResult
    operational_notices: tuple[OperationalNotice, ...] = ()


@dataclass(frozen=True)
class FunctionDiscoveryOutcome:
    functions: tuple[FunctionDescriptor, ...]


@dataclass(frozen=True)
class DirectoryAnalysisOutcome:
    summary: DirectoryAnalysisSummary
    operational_notices: tuple[OperationalNotice, ...] = ()


__all__ = [
    "OperationalNotice",
    "BinaryAnalysisOutcome",
    "FunctionDiscoveryOutcome",
    "DirectoryAnalysisOutcome",
]
