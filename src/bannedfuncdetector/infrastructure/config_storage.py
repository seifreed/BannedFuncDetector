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


def _log_config_event(
    level: int,
    operation: str,
    event_name: str,
    outcome: str,
    message: str,
    **fields: Any,
) -> None:
    logger.log(
        level,
        message,
        extra={
            "operation": operation,
            "event_name": event_name,
            "outcome": outcome,
            **fields,
        },
    )


def _log_config_exception(
    operation: str,
    exc: Exception,
) -> None:
    _log_config_event(
        logging.ERROR,
        operation,
        "configuration_load_failed",
        "error",
        "Configuration operation failed",
        error_type=type(exc).__name__,
        error_code=getattr(exc, "errno", None),
        error_line=getattr(exc, "lineno", None),
        error_column=getattr(exc, "colno", None),
    )


def load_config_from_file(path: Path | str) -> dict[str, Any] | None:
    """Load configuration from a JSON file."""
    config_path = Path(path)
    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            result: dict[str, Any] = json.load(handle)
            return result
    except FileNotFoundError:
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
            copy.deepcopy(config)
            if config is not None
            else copy.deepcopy(DEFAULT_CONFIG)
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
                _log_config_event(
                    logging.WARNING,
                    "config_reload",
                    "configuration_not_found",
                    "unchanged",
                    "Configuration file not found; keeping current configuration",
                )
                return
            if not isinstance(user_config, dict):
                _log_config_event(
                    logging.ERROR,
                    "config_reload",
                    "configuration_invalid_root",
                    "unchanged",
                    "Configuration root must be a JSON object; keeping current configuration",
                    error_type=type(user_config).__name__,
                )
                return
            if not validate_config(user_config):
                _log_config_event(
                    logging.WARNING,
                    "config_reload",
                    "configuration_missing_required_keys",
                    "degraded",
                    "Configuration is missing required sections; merging defaults",
                    missing_keys=[
                        key
                        for key in ("decompiler", "output", "analysis")
                        if key not in user_config
                    ],
                )

            # Reject configs where dict keys are overridden with non-dict values
            for key in ("decompiler", "output", "analysis"):
                if key in user_config and not isinstance(user_config[key], dict):
                    _log_config_event(
                        logging.ERROR,
                        "config_reload",
                        "configuration_invalid_section",
                        "unchanged",
                        "Configuration section must be an object; keeping current configuration",
                        error_type=type(user_config[key]).__name__,
                        config_section=key,
                    )
                    return

            merged = deep_merge(DEFAULT_CONFIG, user_config)

            # Run deep validation on the merged config
            from ..domain.result import Err as _Err

            validation_result = validate_full_config(merged)
            if isinstance(validation_result, _Err):
                _log_config_event(
                    logging.WARNING,
                    "config_reload",
                    "configuration_validation_failed",
                    "unchanged",
                    "Configuration validation failed; keeping current configuration",
                    error_category="configuration",
                )
                return

            self._config = merged
            _log_config_event(
                logging.INFO,
                "config_reload",
                "configuration_reloaded",
                "success",
                "Configuration reloaded",
            )
        except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError) as exc:
            _log_config_exception("config_reload", exc)

    def _update_internal(self, new_config: dict[str, Any]) -> None:
        """Internal method to update configuration."""
        self._config = copy.deepcopy(new_config)


def load_config(config_file: str = "config.json") -> dict[str, Any]:
    """Load configuration from a JSON file and return a merged snapshot."""
    try:
        user_config = load_config_from_file(config_file)
        if user_config is None:
            _log_config_event(
                logging.WARNING,
                "config_load",
                "configuration_not_found",
                "defaulted",
                "Configuration file not found; using defaults",
            )
            return copy.deepcopy(DEFAULT_CONFIG)

        if not isinstance(user_config, dict):
            _log_config_event(
                logging.ERROR,
                "config_load",
                "configuration_invalid_root",
                "defaulted",
                "Configuration root must be a JSON object; using defaults",
                error_type=type(user_config).__name__,
            )
            return copy.deepcopy(DEFAULT_CONFIG)

        if not validate_config(user_config):
            _log_config_event(
                logging.WARNING,
                "config_load",
                "configuration_missing_required_keys",
                "degraded",
                "Configuration is missing required sections; merging defaults",
                missing_keys=[
                    key
                    for key in ("decompiler", "output", "analysis")
                    if key not in user_config
                ],
            )

        # Reject configs where dict keys are overridden with non-dict values
        for key in ("decompiler", "output", "analysis"):
            if key in user_config and not isinstance(user_config[key], dict):
                _log_config_event(
                    logging.ERROR,
                    "config_load",
                    "configuration_invalid_section",
                    "defaulted",
                    "Configuration section must be an object; using defaults",
                    error_type=type(user_config[key]).__name__,
                    config_section=key,
                )
                return copy.deepcopy(DEFAULT_CONFIG)

        merged = deep_merge(DEFAULT_CONFIG, user_config)

        # Run deep validation on the merged config
        from ..domain.result import Err as _Err

        validation_result = validate_full_config(merged)
        if isinstance(validation_result, _Err):
            _log_config_event(
                logging.WARNING,
                "config_load",
                "configuration_validation_failed",
                "defaulted",
                "Configuration validation failed; using defaults",
                error_category="configuration",
            )
            return copy.deepcopy(DEFAULT_CONFIG)

        _log_config_event(
            logging.INFO,
            "config_load",
            "configuration_loaded",
            "success",
            "Configuration loaded",
        )
        return merged
    except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError) as exc:
        _log_config_exception("config_load", exc)
        return copy.deepcopy(DEFAULT_CONFIG)


__all__ = [
    "ImmutableConfig",
    "deep_merge",
    "load_config",
    "load_config_from_file",
]
