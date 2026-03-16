"""Public binary-analysis entry points."""

from bannedfuncdetector.application.contracts import BinaryAnalysisRequest
from bannedfuncdetector.application.types import BinaryAnalysisResultType

from .binary_flow_runtime import run_binary_analysis
from .function_analysis import analyze_function


def analyze_binary(
    binary_path: str,
    *,
    request: BinaryAnalysisRequest,
) -> BinaryAnalysisResultType:
    return run_binary_analysis(
        binary_path,
        request=request,
        analyze_function_impl=analyze_function,
    )
__all__ = ["analyze_function", "analyze_binary"]
