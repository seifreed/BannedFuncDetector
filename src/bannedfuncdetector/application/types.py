from __future__ import annotations

from typing import TypeAlias

from .analysis_error import ExecutionFailure
from bannedfuncdetector.domain.result import Result

from .analysis_outcome import BinaryAnalysisOutcome, DirectoryAnalysisOutcome, FunctionDiscoveryOutcome

BinaryAnalysisResultType: TypeAlias = Result[BinaryAnalysisOutcome, ExecutionFailure]
FunctionDiscoveryResultType: TypeAlias = Result[FunctionDiscoveryOutcome, str]
DirectoryAnalysisResultType: TypeAlias = Result[DirectoryAnalysisOutcome, ExecutionFailure]

__all__ = [
    "BinaryAnalysisResultType",
    "FunctionDiscoveryResultType",
    "DirectoryAnalysisResultType",
]
