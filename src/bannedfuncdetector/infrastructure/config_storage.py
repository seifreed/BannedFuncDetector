"""Configuration file I/O, merging, and immutable snapshots."""

from __future__ import annotations

import copy
import json
import logging
from collections.abc import KeysView
from pathlib import Path
from typing import Any

from .config_models import DEFAULT_CONFIG
from .config_validation import validate_config, validate_full_config

logger = logging.getLogger(__name__)


def load_config_from_file(path: Path | str) -> dict[str, Any] | None:
    """Load configuration from a JSON file."""
    config_path = Path(path)
    if not config_path.exists():
        logger.debug(f"Configuration file {config_path} does not exist")
        return None

    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            result: dict[str, Any] = json.load(handle)
            return result
    except json.JSONDecodeError as exc:
        logger.error(f"Invalid JSON in {config_path}: {exc}")
        raise
    except OSError as exc:
        logger.error(f"Error reading {config_path}: {exc}")
        return None


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge override dictionary into base dictionary."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class ImmutableConfig:
    """Immutable snapshot-based configuration wrapper."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config: dict[str, Any] = (
            copy.deepcopy(config) if config is not None else copy.deepcopy(DEFAULT_CONFIG)
        )

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value, returning copies for mutable types."""
        value = self._config.get(key, default)
        if isinstance(value, (dict, list)):
            return copy.deepcopy(value)
        return value

    def get_output_dir(self) -> str:
        """Get the configured output directory path."""
        output = self.get("output", {})
        if isinstance(output, dict):
            directory = output.get("directory", "output")
            return str(directory) if directory is not None else "output"
        return "output"

    def __getitem__(self, key: str) -> Any:
        value = self._config[key]
        if isinstance(value, (dict, list)):
            return copy.deepcopy(value)
        return value

    def __contains__(self, key: str) -> bool:
        return key in self._config

    def keys(self) -> KeysView[str]:
        """Return configuration keys."""
        return self._config.keys()

    def items(self) -> list[tuple[str, Any]]:
        """Return configuration items, copying mutable values."""
        return [
            (k, copy.deepcopy(v) if isinstance(v, (dict, list)) else v)
            for k, v in self._config.items()
        ]

    def to_dict(self) -> dict[str, Any]:
        """Return a deep copy of the entire configuration."""
        return copy.deepcopy(self._config)

    def reload(self, config_file: str = "config.json") -> None:
        """Reload configuration from file."""
        try:
            user_config = load_config_from_file(config_file)
            if user_config is None:
                logger.warning(f"Configuration file {config_file} not found.")
                return
            if not validate_config(user_config):
                logger.warning(f"Configuration file {config_file} missing required keys, merging with defaults.")

            # Reject configs where dict keys are overridden with non-dict values
            for key in ("decompiler", "output", "analysis"):
                if key in user_config and not isinstance(user_config[key], dict):
                    logger.error(f"Configuration key '{key}' must be a dict, got {type(user_config[key]).__name__}. Keeping current config.")
                    return

            merged = deep_merge(DEFAULT_CONFIG, user_config)

            # Run deep validation on the merged config
            from ..domain.result import Err as _Err
            validation_result = validate_full_config(merged)
            if isinstance(validation_result, _Err):
                logger.warning(f"Configuration validation: {validation_result.error}. Keeping current config.")
                return

            self._config = merged
            logger.info(f"Configuration reloaded from {config_file}")
        except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError) as exc:
            logger.error(f"Error reloading configuration: {exc}")

    def _update_internal(self, new_config: dict[str, Any]) -> None:
        """Internal method to update configuration."""
        self._config = copy.deepcopy(new_config)


def load_config(config_file: str = "config.json") -> dict[str, Any]:
    """Load configuration from a JSON file and return a merged snapshot."""
    try:
        user_config = load_config_from_file(config_file)
        if user_config is None:
            logger.warning(f"Configuration file {config_file} not found.")
            return copy.deepcopy(DEFAULT_CONFIG)

        if not validate_config(user_config):
            logger.warning(f"Configuration file {config_file} missing required keys, merging with defaults.")

        # Reject configs where dict keys are overridden with non-dict values
        for key in ("decompiler", "output", "analysis"):
            if key in user_config and not isinstance(user_config[key], dict):
                logger.error(f"Configuration key '{key}' must be a dict, got {type(user_config[key]).__name__}. Using defaults.")
                return copy.deepcopy(DEFAULT_CONFIG)

        merged = deep_merge(DEFAULT_CONFIG, user_config)

        # Run deep validation on the merged config
        from ..domain.result import Err as _Err
        validation_result = validate_full_config(merged)
        if isinstance(validation_result, _Err):
            logger.warning(f"Configuration validation: {validation_result.error}. Using defaults.")
            return copy.deepcopy(DEFAULT_CONFIG)

        logger.info(f"Configuration loaded from {config_file}")
        return merged
    except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError) as exc:
        logger.error(f"Error loading configuration: {exc}")
        return copy.deepcopy(DEFAULT_CONFIG)


__all__ = [
    "ImmutableConfig",
    "deep_merge",
    "load_config",
    "load_config_from_file",
]
