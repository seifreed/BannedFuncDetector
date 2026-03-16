"""Protocol-facing function-discovery service."""

from __future__ import annotations

from bannedfuncdetector.application.analysis_outcome import FunctionDiscoveryOutcome
from bannedfuncdetector.application.types import FunctionDiscoveryResultType
from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.domain.result import Err, err, ok

from .runtime import _extract_functions


class R2FunctionDiscoveryService:
    """Discover functions from an already-open r2 session."""

    def __init__(self, *, verbose: bool = False):
        self.verbose = verbose

    def get_functions(self, r2: IR2Client) -> FunctionDiscoveryResultType:
        result = _extract_functions(r2, verbose=self.verbose)
        if isinstance(result, Err):
            return err(result.error)
        return ok(FunctionDiscoveryOutcome(functions=tuple(result.unwrap())))


__all__ = ["R2FunctionDiscoveryService"]
