from __future__ import annotations

from dataclasses import dataclass

from .analysis_outcome import OperationalNotice


@dataclass(frozen=True)
class ApplicationExecutionError:
    category: str
    context: str
    message: str
    phase: str | None = None

    def __str__(self) -> str:
        parts = [self.category]
        if self.phase:
            parts.append(self.phase)
        parts.append(f"for {self.context}: {self.message}")
        return " ".join(parts)


@dataclass(frozen=True)
class ExecutionFailure:
    error: ApplicationExecutionError
    operational_notices: tuple[OperationalNotice, ...] = ()

    def __str__(self) -> str:
        rendered = str(self.error)
        if self.operational_notices:
            notices = "; ".join(notice.message for notice in self.operational_notices)
            return f"{rendered}; notices: {notices}"
        return rendered

    def __contains__(self, item: object) -> bool:
        """Allow direct substring checks on failures in tests and callers."""
        return str(item) in str(self)


@dataclass(frozen=True)
class BinaryExecutionError(ApplicationExecutionError):
    pass


@dataclass(frozen=True)
class DirectoryExecutionError(ApplicationExecutionError):
    pass


__all__ = [
    "ApplicationExecutionError",
    "BinaryExecutionError",
    "DirectoryExecutionError",
    "ExecutionFailure",
]
