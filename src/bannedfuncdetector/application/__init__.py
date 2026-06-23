"""Application layer public surface."""

from .._lazy import lazy_exports

__all__ = [
    "R2BinaryAnalyzer",
    "analyze_binary",
    "analyze_function",
    "analyze_directory",
]

_EXPORTS: dict[str, tuple[str, str]] = {
    "R2BinaryAnalyzer": (
        "bannedfuncdetector.application.binary_analyzer",
        "R2BinaryAnalyzer",
    ),
    "analyze_binary": (
        "bannedfuncdetector.application.binary_analyzer",
        "analyze_binary",
    ),
    "analyze_function": (
        "bannedfuncdetector.application.binary_analyzer",
        "analyze_function",
    ),
    "analyze_directory": (
        "bannedfuncdetector.application.directory_scanner",
        "analyze_directory",
    ),
}


__getattr__ = lazy_exports(__name__, _EXPORTS, globals())
