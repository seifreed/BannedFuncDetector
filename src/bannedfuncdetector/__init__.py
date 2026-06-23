"""Public package surface for BannedFuncDetector.

Keep the import surface stable without eagerly importing the full runtime stack.
"""

from ._lazy import lazy_exports

__all__ = [
    "main",
    "analyze_binary",
    "analyze_directory",
    "create_application_wiring",
    "create_binary_analyzer",
    "create_config_from_file",
    "create_config_from_dict",
    "BannedFunction",
    "AnalysisResult",
]

_EXPORTS: dict[str, tuple[str, str]] = {
    "main": ("bannedfuncdetector.bannedfunc", "main"),
    "analyze_binary": (
        "bannedfuncdetector.application.binary_analyzer",
        "analyze_binary",
    ),
    "analyze_directory": (
        "bannedfuncdetector.application.directory_scanner",
        "analyze_directory",
    ),
    "create_application_wiring": (
        "bannedfuncdetector.factories",
        "create_application_wiring",
    ),
    "create_binary_analyzer": (
        "bannedfuncdetector.factories",
        "create_binary_analyzer",
    ),
    "create_config_from_file": (
        "bannedfuncdetector.factories",
        "create_config_from_file",
    ),
    "create_config_from_dict": (
        "bannedfuncdetector.factories",
        "create_config_from_dict",
    ),
    "BannedFunction": ("bannedfuncdetector.domain.entities", "BannedFunction"),
    "AnalysisResult": ("bannedfuncdetector.domain.entities", "AnalysisResult"),
}


__getattr__ = lazy_exports(__name__, _EXPORTS, globals())
