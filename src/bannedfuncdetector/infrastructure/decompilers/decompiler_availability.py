"""Availability configuration and checks for decompiler backends."""

from __future__ import annotations

import logging
from typing import Any, cast

import requests

from bannedfuncdetector.infrastructure.adapters.r2_client import R2Client

from .decompiler_types import DecompilerType

logger = logging.getLogger(__name__)


def _is_http_ok(response: Any) -> bool:
    """Return ``True`` when the response object reports HTTP 200."""
    try:
        status_code = cast(int, response.status_code)
        return status_code == 200
    except (AttributeError, TypeError):
        return False


DECOMPILER_CONFIG: dict[str, dict[str, Any]] = {
    "r2ghidra": {"check_cmd": "Lc", "expected": "r2ghidra"},
    "r2dec": {"check_cmd": "Lc", "expected": ["pdd", "r2dec"]},
    "default": {"always_available": True},
    "decai": {"check_service": True, "url": "http://localhost:11434"},
    "r2ai": {
        "not_decompiler": True,
        "message": "r2ai is not a decompiler, it's an AI assistant. Please use a decompiler like r2ghidra or r2dec",
    },
}

DECAI_PREFERRED_MODELS = [
    "qwen2:5b-coder",
    "codellama:7b",
    "llama3",
    "mistral",
    "phi",
]


def check_decompiler_plugin_available(
    decompiler_type: str | DecompilerType,
) -> bool:
    """Unified function to check if a decompiler plugin is available."""
    if isinstance(decompiler_type, DecompilerType):
        decompiler_type = decompiler_type.value

    config = DECOMPILER_CONFIG.get(decompiler_type)
    if config is None:
        return False
    if config.get("not_decompiler"):
        return False
    if config.get("always_available"):
        return True
    if config.get("check_service"):
        return _check_decai_service_available(config["url"])
    if "check_cmd" in config:
        return _check_r2_plugin_available(config["check_cmd"], config["expected"])
    return False


def _check_r2_plugin_available(check_cmd: str, expected: str | list[str]) -> bool:
    """Check if a radare2 plugin is available."""
    try:
        with R2Client.open("-") as r2:
            result = r2.cmd(check_cmd)
        if isinstance(expected, list):
            return any(exp in result for exp in expected)
        return expected in result
    except (RuntimeError, ValueError, OSError, IOError) as exc:
        logger.error(f"Error checking r2 plugin: {exc}")
        return False
    except (AttributeError, TypeError) as exc:
        logger.error(f"Data error checking r2 plugin: {exc}")
        return False


def _check_decai_service_available(url: str) -> bool:
    """Check if decai plugin and Ollama service are available."""
    try:
        with R2Client.open("-") as r2:
            result = r2.cmd("decai -h")

        is_plugin_available = (
            "Usage: decai" in result and "Unknown command" not in result
        )
        if not is_plugin_available:
            return False

        response = requests.get(f"{url}/api/tags", timeout=1)
        return _is_http_ok(response)
    except requests.RequestException:
        logger.warning("decai plugin is available but cannot connect to Ollama")
        return False
    except (RuntimeError, ValueError, OSError, IOError) as exc:
        logger.error(f"Error checking decai availability: {exc}")
        return False


__all__ = [
    "DECAI_PREFERRED_MODELS",
    "DECOMPILER_CONFIG",
    "check_decompiler_plugin_available",
]
