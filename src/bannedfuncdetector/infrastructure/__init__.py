"""Infrastructure layer public surface."""

from importlib import import_module
from typing import Any

__all__ = [
    "handle_errors",
    "handle_errors_sync",
    "ErrorCategory",
    "EXCEPTION_GROUPS",
    "check_python_version",
    "check_requirements",
    "validate_binary_file",
    "ImmutableConfig",
    "DecompilerOption",
    "AppConfig",
    "load_config_from_file",
    "load_config",
    "deep_merge",
    "DEFAULT_CONFIG",
    "DEFAULT_DECOMPILER_OPTIONS",
    "DEFAULT_APP_CONFIG",
    "VALID_DECOMPILER_TYPES",
    "VALID_OUTPUT_FORMATS",
    "validate_config",
    "validate_banned_functions",
    "validate_decompiler_settings",
    "validate_output_settings",
    "validate_analysis_settings",
    "validate_full_config",
]

_EXPORTS: dict[str, tuple[str, str]] = {
    "handle_errors": (
        "bannedfuncdetector.infrastructure.error_handling",
        "handle_errors",
    ),
    "handle_errors_sync": (
        "bannedfuncdetector.infrastructure.error_handling",
        "handle_errors_sync",
    ),
    "ErrorCategory": ("bannedfuncdetector.domain.error_types", "ErrorCategory"),
    "EXCEPTION_GROUPS": (
        "bannedfuncdetector.infrastructure.error_handling",
        "EXCEPTION_GROUPS",
    ),
    "check_python_version": (
        "bannedfuncdetector.infrastructure.validators",
        "check_python_version",
    ),
    "check_requirements": (
        "bannedfuncdetector.infrastructure.validators",
        "check_requirements",
    ),
    "validate_binary_file": (
        "bannedfuncdetector.infrastructure.validators",
        "validate_binary_file",
    ),
    "ImmutableConfig": (
        "bannedfuncdetector.infrastructure.config_repository",
        "ImmutableConfig",
    ),
    "DecompilerOption": (
        "bannedfuncdetector.infrastructure.config_repository",
        "DecompilerOption",
    ),
    "AppConfig": ("bannedfuncdetector.infrastructure.config_repository", "AppConfig"),
    "load_config_from_file": (
        "bannedfuncdetector.infrastructure.config_repository",
        "load_config_from_file",
    ),
    "load_config": (
        "bannedfuncdetector.infrastructure.config_repository",
        "load_config",
    ),
    "deep_merge": ("bannedfuncdetector.infrastructure.config_repository", "deep_merge"),
    "DEFAULT_CONFIG": (
        "bannedfuncdetector.infrastructure.config_repository",
        "DEFAULT_CONFIG",
    ),
    "DEFAULT_DECOMPILER_OPTIONS": (
        "bannedfuncdetector.infrastructure.config_repository",
        "DEFAULT_DECOMPILER_OPTIONS",
    ),
    "DEFAULT_APP_CONFIG": (
        "bannedfuncdetector.infrastructure.config_repository",
        "DEFAULT_APP_CONFIG",
    ),
    "VALID_DECOMPILER_TYPES": (
        "bannedfuncdetector.infrastructure.config_repository",
        "VALID_DECOMPILER_TYPES",
    ),
    "VALID_OUTPUT_FORMATS": (
        "bannedfuncdetector.infrastructure.config_repository",
        "VALID_OUTPUT_FORMATS",
    ),
    "validate_config": (
        "bannedfuncdetector.infrastructure.config_repository",
        "validate_config",
    ),
    "validate_banned_functions": (
        "bannedfuncdetector.infrastructure.config_repository",
        "validate_banned_functions",
    ),
    "validate_decompiler_settings": (
        "bannedfuncdetector.infrastructure.config_repository",
        "validate_decompiler_settings",
    ),
    "validate_output_settings": (
        "bannedfuncdetector.infrastructure.config_repository",
        "validate_output_settings",
    ),
    "validate_analysis_settings": (
        "bannedfuncdetector.infrastructure.config_repository",
        "validate_analysis_settings",
    ),
    "validate_full_config": (
        "bannedfuncdetector.infrastructure.config_repository",
        "validate_full_config",
    ),
}


def __getattr__(name: str) -> Any:
    """Resolve infrastructure exports lazily."""
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = _EXPORTS[name]
    module = import_module(module_name)
    value = getattr(module, attribute)
    globals()[name] = value
    return value
