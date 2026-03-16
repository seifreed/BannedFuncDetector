"""Protocol-facing analyzer implementation."""
from collections.abc import Callable

from bannedfuncdetector.application.analysis_runtime import BinaryRuntimeServices
from bannedfuncdetector.application.contracts import AnalysisRuntime, BinaryAnalysisRequest
from bannedfuncdetector.domain.protocols import IConfigRepository, IR2Client
from bannedfuncdetector.application.types import BinaryAnalysisResultType

from .core import analyze_binary


class R2BinaryAnalyzer:
    """Protocol-facing analyzer for full binary analysis."""

    _config: IConfigRepository

    def __init__(
        self,
        decompiler_type: str = "default",
        verbose: bool = False,
        *,
        r2_factory: Callable[[str], IR2Client],
        config: IConfigRepository,
        binary_services: BinaryRuntimeServices,
    ):
        self.decompiler_type = decompiler_type
        self.verbose = verbose
        self._r2_factory = r2_factory
        self._binary_services = binary_services
        if config is None:
            raise ValueError("config is required for R2BinaryAnalyzer")
        self._config = config

    def analyze(self, file_path: str) -> BinaryAnalysisResultType:
        """Perform analysis on one binary file."""
        return analyze_binary(
            binary_path=file_path,
            request=BinaryAnalysisRequest(
                runtime=AnalysisRuntime(
                    config=self._config,
                    r2_factory=self._r2_factory,
                    binary=self._binary_services,
                ),
                decompiler_type=self.decompiler_type,
                verbose=self.verbose,
            ),
        )

__all__ = ["R2BinaryAnalyzer"]
