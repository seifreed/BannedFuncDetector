#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Configuration Repository

Provides configuration management with type-safe defaults and file loading.

Author: Marc Rivero | @seifreed
License: GNU General Public License v3 (GPLv3)
"""
import copy
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING
from collections.abc import KeysView

from ..constants import DEFAULT_MAX_WORKERS, DEFAULT_OUTPUT_DIR
from ..domain.result import Result, Ok, Err

if TYPE_CHECKING:
    from ..domain.protocols import IConfigRepository

logger = logging.getLogger(__name__)


# =============================================================================
# VALIDATION CONSTANTS
# =============================================================================

VALID_DECOMPILER_TYPES = ["default", "r2ghidra", "r2dec", "r2ai", "decai", "r2ai-server"]
VALID_OUTPUT_FORMATS = ["json", "text", "html"]


# =============================================================================
# TYPE DEFINITIONS
# =============================================================================


@dataclass(frozen=True)
class DecompilerOption:
    """Configuration for a single decompiler."""

    enabled: bool = True
    command: str = ""
    description: str = ""
    # Error handling
    ignore_unknown_branches: bool = True
    clean_error_messages: bool = True
    fallback_to_asm: bool = True
    # AI options
    model: str = ""
    api: str = ""
    prompt: str = ""
    host: str = ""
    port: int = 0
    server_url: str = ""
    temperature: float = 0.7
    context: int = 8192
    max_tokens: int = 4096
    system_prompt: str = ""


# Default decompiler options
DEFAULT_DECOMPILER_OPTIONS: dict[str, DecompilerOption] = {
    "default": DecompilerOption(
        enabled=True,
        command="pdc",
        description="Default radare2 decompiler",
    ),
    "r2ghidra": DecompilerOption(
        enabled=True,
        command="pdg",
        description="r2ghidra decompiler",
    ),
    "r2dec": DecompilerOption(
        enabled=True,
        command="pdd",
        description="r2dec decompiler",
    ),
    "r2ai": DecompilerOption(
        enabled=True,
        command="pdai",
        description="AI-based decompiler (r2ai)",
        model="hhao/qwen2.5-coder-tools:32b",
        system_prompt=(
            "You are a reverse engineering assistant focused on decompiling "
            "assembly code into clean, human-readable C code."
        ),
    ),
    "decai": DecompilerOption(
        enabled=True,
        command="decai -d",
        description="AI-based decompiler (decai)",
        api="ollama",
        model="qwen2:5b-coder",
        prompt=(
            "Rewrite this function and respond ONLY with code, NO explanations, "
            "NO markdown, Change 'goto' into if/else/for/while, Simplify as much "
            "as possible, use better variable names, take function arguments and "
            "strings from comments like 'string:'"
        ),
        host="http://localhost",
        port=11434,
    ),
    "r2ai-server": DecompilerOption(
        enabled=True,
        command="pdai",
        description="AI-based decompiler (r2ai-server)",
        server_url="http://localhost:8080",
        model="mistral-7b-instruct-v0.2.Q2_K",
        system_prompt=(
            "You are a reverse engineering assistant focused on decompiling "
            "assembly code into clean, human-readable C code."
        ),
    ),
}


@dataclass(frozen=True)
class AppConfig:
    """Application configuration with typed defaults.

    Consolidates all configuration sections into a single dataclass.
    Replaces: DecompilerConfig, OutputConfig, AnalysisConfig.
    """

    # Decompiler settings
    decompiler_type: str = "default"
    decompiler_options: dict[str, DecompilerOption] = field(
        default_factory=lambda: dict(DEFAULT_DECOMPILER_OPTIONS)
    )
    ignore_unknown_branches: bool = True
    clean_error_messages: bool = True
    fallback_to_asm: bool = True
    max_retries: int = 3
    error_threshold: float = 0.1
    use_alternative_decompiler: bool = True

    # Output settings
    output_directory: str = DEFAULT_OUTPUT_DIR
    output_format: str = "json"
    open_results: bool = False
    verbose: bool = False

    # Analysis settings
    parallel: bool = True
    max_workers: int = DEFAULT_MAX_WORKERS
    timeout: int = 600
    worker_limit: int | None = None

    # Root-level settings
    skip_small_functions: bool = True
    small_function_threshold: int = 10
    r2pipe_threads: int = 10

    def to_dict(self) -> dict[str, Any]:
        """Convert to nested dictionary for backward compatibility."""
        decompiler_options_dict: dict[str, Any] = {}
        for name, opt in self.decompiler_options.items():
            opt_dict: dict[str, Any] = {"enabled": opt.enabled}
            if opt.command:
                opt_dict["command"] = opt.command
            if opt.description:
                opt_dict["description"] = opt.description
            if opt.model:
                opt_dict["model"] = opt.model
            if opt.api:
                opt_dict["api"] = opt.api
            if opt.prompt:
                opt_dict["prompt"] = opt.prompt
            if opt.host:
                opt_dict["host"] = opt.host
            if opt.port:
                opt_dict["port"] = opt.port
            if opt.server_url:
                opt_dict["server_url"] = opt.server_url
            decompiler_options_dict[name] = opt_dict

        decompiler_options_dict["ignore_unknown_branches"] = self.ignore_unknown_branches
        decompiler_options_dict["max_retries"] = self.max_retries
        decompiler_options_dict["fallback_to_asm"] = self.fallback_to_asm
        decompiler_options_dict["error_threshold"] = self.error_threshold
        decompiler_options_dict["clean_error_messages"] = self.clean_error_messages
        decompiler_options_dict["use_alternative_decompiler"] = self.use_alternative_decompiler

        return {
            "decompiler": {
                "type": self.decompiler_type,
                "options": decompiler_options_dict,
            },
            "output": {
                "directory": self.output_directory,
                "format": self.output_format,
                "open_results": self.open_results,
                "verbose": self.verbose,
            },
            "analysis": {
                "parallel": self.parallel,
                "max_workers": self.max_workers,
                "timeout": self.timeout,
                "worker_limit": self.worker_limit,
            },
            "max_workers": self.max_workers,
            "skip_small_functions": self.skip_small_functions,
            "small_function_threshold": self.small_function_threshold,
            "r2pipe_threads": self.r2pipe_threads,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppConfig":
        """Create AppConfig from a dictionary."""
        decompiler_data = data.get("decompiler", {})
        options_data = decompiler_data.get("options", {})
        output_data = data.get("output", {})
        analysis_data = data.get("analysis", {})

        decompiler_options = {}
        for name, default_opt in DEFAULT_DECOMPILER_OPTIONS.items():
            opt_data = options_data.get(name, {})
            error_handling = opt_data.get("error_handling", {})
            advanced = opt_data.get("advanced_options", {})

            decompiler_options[name] = DecompilerOption(
                enabled=opt_data.get("enabled", default_opt.enabled),
                command=opt_data.get("command", default_opt.command),
                description=opt_data.get("description", default_opt.description),
                ignore_unknown_branches=error_handling.get(
                    "ignore_unknown_branches", default_opt.ignore_unknown_branches
                ),
                clean_error_messages=error_handling.get(
                    "clean_error_messages", default_opt.clean_error_messages
                ),
                fallback_to_asm=error_handling.get(
                    "fallback_to_asm", default_opt.fallback_to_asm
                ),
                model=opt_data.get("model", default_opt.model),
                api=opt_data.get("api", default_opt.api),
                prompt=opt_data.get("prompt", default_opt.prompt),
                host=opt_data.get("host", default_opt.host),
                port=opt_data.get("port", default_opt.port),
                server_url=opt_data.get("server_url", default_opt.server_url),
                temperature=advanced.get("temperature", default_opt.temperature),
                context=advanced.get("context", default_opt.context),
                max_tokens=advanced.get("max_tokens", default_opt.max_tokens),
                system_prompt=advanced.get("system_prompt", default_opt.system_prompt),
            )

        return cls(
            decompiler_type=decompiler_data.get("type", "default"),
            decompiler_options=decompiler_options,
            ignore_unknown_branches=options_data.get("ignore_unknown_branches", True),
            clean_error_messages=options_data.get("clean_error_messages", True),
            fallback_to_asm=options_data.get("fallback_to_asm", True),
            max_retries=options_data.get("max_retries", 3),
            error_threshold=options_data.get("error_threshold", 0.1),
            use_alternative_decompiler=options_data.get("use_alternative_decompiler", True),
            output_directory=output_data.get("directory", DEFAULT_OUTPUT_DIR),
            output_format=output_data.get("format", "json"),
            open_results=output_data.get("open_results", False),
            verbose=output_data.get("verbose", False),
            parallel=analysis_data.get("parallel", True),
            max_workers=analysis_data.get("max_workers", DEFAULT_MAX_WORKERS),
            timeout=analysis_data.get("timeout", 600),
            worker_limit=analysis_data.get("worker_limit"),
            skip_small_functions=data.get("skip_small_functions", True),
            small_function_threshold=data.get("small_function_threshold", 10),
            r2pipe_threads=data.get("r2pipe_threads", 10),
        )


# Default configuration
DEFAULT_APP_CONFIG = AppConfig()
DEFAULT_CONFIG: dict[str, Any] = DEFAULT_APP_CONFIG.to_dict()


# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================


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

    validated = []
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
        logger.warning(f"Decompiler type '{settings['type']}' not in: {VALID_DECOMPILER_TYPES}")
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


# =============================================================================
# FILE I/O
# =============================================================================


def load_config_from_file(path: Path | str) -> dict[str, Any] | None:
    """Load configuration from a JSON file."""
    config_path = Path(path)
    if not config_path.exists():
        logger.debug(f"Configuration file {config_path} does not exist")
        return None

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            result: dict[str, Any] = json.load(f)
            return result
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {config_path}: {e}")
        raise
    except OSError as e:
        logger.error(f"Error reading {config_path}: {e}")
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


# =============================================================================
# IMMUTABLE CONFIG (IConfigRepository Implementation)
# =============================================================================


class ImmutableConfig:
    """Immutable configuration wrapper with singleton pattern.

    Provides dict-like access to configuration values.
    """

    _instance: "ImmutableConfig | None" = None
    _config: dict[str, Any] = {}
    _initialized: bool = False

    def __new__(cls) -> "ImmutableConfig":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not ImmutableConfig._initialized:
            ImmutableConfig._config = copy.deepcopy(DEFAULT_CONFIG)
            ImmutableConfig._initialized = True

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value (returns copy for mutable types)."""
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
        """Return configuration items (copies of values)."""
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
                logger.warning(f"Configuration file {config_file} missing required keys.")
            ImmutableConfig._config = deep_merge(DEFAULT_CONFIG, user_config)
            logger.info(f"Configuration reloaded from {config_file}")
        except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError) as e:
            logger.error(f"Error reloading configuration: {e}")

    def _update_internal(self, new_config: dict[str, Any]) -> None:
        """Internal method to update configuration."""
        ImmutableConfig._config = copy.deepcopy(new_config)


# Global singleton instance (deprecated - use dependency injection instead)
CONFIG = ImmutableConfig()


def get_default_config() -> "IConfigRepository":
    """Get the default global configuration instance.

    .. deprecated::
        This function returns the global singleton. For new code, prefer
        creating configuration via :func:`factories.create_config_from_file`
        or :func:`factories.create_config_from_dict` and passing it explicitly.

    Returns:
        IConfigRepository: The global configuration singleton.
    """
    return CONFIG


def load_config(config_file: str = "config.json") -> dict[str, Any]:
    """Load configuration from a JSON file and update the global singleton."""
    try:
        user_config = load_config_from_file(config_file)
        if user_config is None:
            logger.warning(f"Configuration file {config_file} not found.")
            return CONFIG.to_dict()

        if not validate_config(user_config):
            logger.warning(f"Configuration file {config_file} missing required keys.")

        merged = deep_merge(DEFAULT_CONFIG, user_config)
        CONFIG._update_internal(merged)
        logger.info(f"Configuration loaded from {config_file}")
        return CONFIG.to_dict()
    except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError) as e:
        logger.error(f"Error loading configuration: {e}")
        return CONFIG.to_dict()


__all__ = [
    # Type definitions
    "DecompilerOption",
    "AppConfig",
    # Default values
    "DEFAULT_DECOMPILER_OPTIONS",
    "DEFAULT_APP_CONFIG",
    "DEFAULT_CONFIG",
    # Validation constants
    "VALID_DECOMPILER_TYPES",
    "VALID_OUTPUT_FORMATS",
    # Validation functions
    "validate_config",
    "validate_banned_functions",
    "validate_decompiler_settings",
    "validate_output_settings",
    "validate_analysis_settings",
    "validate_full_config",
    # Immutable Config
    "ImmutableConfig",
    "CONFIG",
    "get_default_config",
    # File I/O
    "load_config_from_file",
    "deep_merge",
    "load_config",
]
