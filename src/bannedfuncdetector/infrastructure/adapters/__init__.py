"""External adapter exports."""

from importlib import import_module
from typing import Any

__all__ = [
    "DetectionResultDTO",
    "FunctionInfoDTO",
    "R2Client",
    "check_r2ai_server_available",
]

_EXPORTS: dict[str, tuple[str, str]] = {
    "DetectionResultDTO": (
        "bannedfuncdetector.infrastructure.adapters.dtos",
        "DetectionResultDTO",
    ),
    "FunctionInfoDTO": (
        "bannedfuncdetector.infrastructure.adapters.dtos",
        "FunctionInfoDTO",
    ),
    "R2Client": ("bannedfuncdetector.infrastructure.adapters.r2_client", "R2Client"),
    "check_r2ai_server_available": (
        "bannedfuncdetector.infrastructure.adapters.r2ai_server",
        "check_r2ai_server_available",
    ),
}


def __getattr__(name: str) -> Any:
    """Resolve adapter exports lazily."""
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = _EXPORTS[name]
    module = import_module(module_name)
    value = getattr(module, attribute)
    globals()[name] = value
    return value
