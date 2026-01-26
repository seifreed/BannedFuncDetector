"""Infrastructure layer - External adapters and tool integrations."""

from .error_handling import (
    handle_errors,
    handle_errors_sync,
    ErrorCategory,
    EXCEPTION_GROUPS,
)
from .validators import (
    check_python_version,
    check_requirements,
    validate_binary_file,
)
from .config_repository import (
    # Configuration classes
    ImmutableConfig,
    DecompilerOption,
    AppConfig,
    # Configuration instances
    CONFIG,
    get_default_config,
    # Configuration loading
    load_config_from_file,
    load_config,
    # Utilities
    deep_merge,
    # Default configurations
    DEFAULT_CONFIG,
    DEFAULT_DECOMPILER_OPTIONS,
    DEFAULT_APP_CONFIG,
    # Validation constants
    VALID_DECOMPILER_TYPES,
    VALID_OUTPUT_FORMATS,
    # Validation functions
    validate_config,
    validate_banned_functions,
    validate_decompiler_settings,
    validate_output_settings,
    validate_analysis_settings,
    validate_full_config,
)

__all__ = [
    # Error handling
    'handle_errors',
    'handle_errors_sync',
    'ErrorCategory',
    'EXCEPTION_GROUPS',
    # Validators
    'check_python_version',
    'check_requirements',
    'validate_binary_file',
    # Configuration classes
    'ImmutableConfig',
    'DecompilerOption',
    'AppConfig',
    # Configuration instances
    'CONFIG',
    'get_default_config',
    # Configuration loading
    'load_config_from_file',
    'load_config',
    # Utilities
    'deep_merge',
    # Default configurations
    'DEFAULT_CONFIG',
    'DEFAULT_DECOMPILER_OPTIONS',
    'DEFAULT_APP_CONFIG',
    # Validation constants
    'VALID_DECOMPILER_TYPES',
    'VALID_OUTPUT_FORMATS',
    # Validation functions
    'validate_config',
    'validate_banned_functions',
    'validate_decompiler_settings',
    'validate_output_settings',
    'validate_analysis_settings',
    'validate_full_config',
]
