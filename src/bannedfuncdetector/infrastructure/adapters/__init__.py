"""External adapter exports."""

from ..._lazy import lazy_exports

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


__getattr__ = lazy_exports(__name__, _EXPORTS, globals())
