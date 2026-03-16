"""Validation helpers for configuration payloads."""

from __future__ import annotations

import logging
from typing import Any

from ..domain.result import Err, Ok, Result

logger = logging.getLogger(__name__)

VALID_DECOMPILER_TYPES = ["default", "r2ghidra", "r2dec", "r2ai", "decai", "r2ai-server"]
VALID_OUTPUT_FORMATS = ["json", "text", "html"]


def validate_config(config: dict[str, Any]) -> bool:
    """Validate that configuration has required top-level keys."""
    required_keys = ["decompiler", "output", "analysis"]
    is_valid = all(key in config for key in required_keys)
    if not is_valid:
        missing = [k for k in required_keys if k not in config]
        logger.warning(f"Configuration missing required keys: {missing}")
    return is_valid


def validate_banned_functions(functions: list[Any]) -> Result[list[str], str]:
    """Validate a list of banned function definitions."""
    if not isinstance(functions, list):
        return Err("Banned functions must be a list")

    validated: list[str] = []
    for func in functions:
        if isinstance(func, str):
            validated.append(func)
        elif isinstance(func, dict) and "name" in func:
            validated.append(func["name"])
        else:
            return Err(f"Invalid banned function entry: {func}")
    return Ok(validated)


def validate_decompiler_settings(settings: dict[str, Any]) -> Result[dict[str, Any], str]:
    """Validate decompiler configuration settings."""
    if not isinstance(settings, dict):
        return Err("Decompiler settings must be a dictionary")
    if "type" not in settings:
        return Err("Decompiler settings missing 'type' field")
    if settings["type"] not in VALID_DECOMPILER_TYPES:
        return Err(f"Invalid decompiler type '{settings['type']}'. Must be one of: {VALID_DECOMPILER_TYPES}")
    if "options" not in settings or not isinstance(settings["options"], dict):
        return Err("Decompiler settings missing 'options' dictionary")
    return Ok(settings)


def validate_output_settings(settings: dict[str, Any]) -> Result[dict[str, Any], str]:
    """Validate output configuration settings."""
    if not isinstance(settings, dict):
        return Err("Output settings must be a dictionary")
    if "directory" not in settings:
        return Err("Output settings missing 'directory' field")
    if "format" in settings and settings["format"] not in VALID_OUTPUT_FORMATS:
        logger.warning(f"Output format '{settings['format']}' not in: {VALID_OUTPUT_FORMATS}")
    return Ok(settings)


def validate_analysis_settings(settings: dict[str, Any]) -> Result[dict[str, Any], str]:
    """Validate analysis configuration settings."""
    if not isinstance(settings, dict):
        return Err("Analysis settings must be a dictionary")
    if "max_workers" in settings:
        if not isinstance(settings["max_workers"], int) or settings["max_workers"] <= 0:
            return Err("max_workers must be a positive integer")
    if "timeout" in settings:
        if not isinstance(settings["timeout"], (int, float)) or settings["timeout"] <= 0:
            return Err("timeout must be a positive number")
    if "parallel" in settings and not isinstance(settings["parallel"], bool):
        return Err("parallel must be a boolean")
    return Ok(settings)


def validate_full_config(config: dict[str, Any]) -> Result[dict[str, Any], str]:
    """Perform comprehensive validation of a complete configuration."""
    if not validate_config(config):
        return Err("Configuration missing required top-level keys")

    result = validate_decompiler_settings(config["decompiler"])
    if isinstance(result, Err):
        return Err(f"Decompiler validation failed: {result.error}")

    result = validate_output_settings(config["output"])
    if isinstance(result, Err):
        return Err(f"Output validation failed: {result.error}")

    result = validate_analysis_settings(config["analysis"])
    if isinstance(result, Err):
        return Err(f"Analysis validation failed: {result.error}")

    return Ok(config)


__all__ = [
    "VALID_DECOMPILER_TYPES",
    "VALID_OUTPUT_FORMATS",
    "validate_analysis_settings",
    "validate_banned_functions",
    "validate_config",
    "validate_decompiler_settings",
    "validate_full_config",
    "validate_output_settings",
]
