"""Domain error category enumeration."""

from enum import StrEnum


class ErrorCategory(StrEnum):
    DATA = "Data error"
    RUNTIME = "Runtime error"
    IO = "I/O error"
    ANALYSIS = "Analysis error"
    ERROR = "Error"


__all__ = ["ErrorCategory"]
