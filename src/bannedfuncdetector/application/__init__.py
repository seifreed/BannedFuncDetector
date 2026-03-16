"""Application layer public surface."""

from importlib import import_module
from typing import Any

__all__ = [
    "R2BinaryAnalyzer",
    "analyze_binary",
    "analyze_function",
    "analyze_directory",
]

_EXPORTS: dict[str, tuple[str, str]] = {
    "R2BinaryAnalyzer": ("bannedfuncdetector.application.binary_analyzer", "R2BinaryAnalyzer"),
    "analyze_binary": ("bannedfuncdetector.application.binary_analyzer", "analyze_binary"),
    "analyze_function": ("bannedfuncdetector.application.binary_analyzer", "analyze_function"),
    "analyze_directory": ("bannedfuncdetector.application.directory_scanner", "analyze_directory"),
}


def __getattr__(name: str) -> Any:
    """Resolve application exports lazily."""
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = _EXPORTS[name]
    module = import_module(module_name)
    value = getattr(module, attribute)
    globals()[name] = value
    return value
