"""Runtime and configuration factory helpers."""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable

from .application.analysis_runtime import (
    AnalysisRuntime,
    BinaryRuntimeServices,
    DirectoryRuntimeServices,
)
from .infrastructure.config_storage import ImmutableConfig as DictConfig
from .domain.protocols import (
    IConfigRepository,
    IDecompilerOrchestrator,
    IR2Client,
)
from .infrastructure.adapters.r2_client import R2Client
from .domain.result import Result

logger = logging.getLogger(__name__)

DEFAULT_R2_FLAGS: list[str] = ["-2"]


def create_r2_client(
    file_path: str,
    flags: list[str] | None = None,
) -> IR2Client:
    """Create an R2 client bound to a binary path."""
    effective_flags = flags if flags is not None else DEFAULT_R2_FLAGS
    logger.debug(f"Creating R2Client for {file_path} with flags {effective_flags}")
    return R2Client.open(file_path, flags=effective_flags)


def create_config_from_file(config_path: str | None = None) -> IConfigRepository:
    """Create a configuration repository from JSON file contents."""
    from .infrastructure.config_repository import ImmutableConfig, load_config

    loaded = load_config(config_path) if config_path else load_config()
    return ImmutableConfig(loaded)


def create_config_from_dict(config_dict: dict) -> IConfigRepository:
    """Create an isolated config repository from a dictionary.

    Raises:
        ValueError: If the merged configuration fails validation.
    """
    from .domain.result import Err
    from .infrastructure.config_repository import DEFAULT_CONFIG, deep_merge
    from .infrastructure.config_validation import validate_full_config

    merged = deep_merge(DEFAULT_CONFIG, config_dict)
    validation = validate_full_config(merged)
    if isinstance(validation, Err):
        raise ValueError(f"Invalid configuration: {validation.error}")
    return DictConfig(merged)


def _resolve_anal_timeout(config: IConfigRepository) -> int:
    """Read the r2 analysis-time budget from ``config["analysis"]["timeout"]``.

    Falls back to ``DECOMPILER_TIMEOUT`` when the section or value is missing or
    invalid. The value caps r2's ``aaa`` so larger budgets recover more
    functions on big binaries; it is honored via :func:`_default_binary_opener`.
    """
    from .constants import DECOMPILER_TIMEOUT

    analysis = config.get("analysis", {})
    if isinstance(analysis, dict):
        timeout = analysis.get("timeout")
        if (
            isinstance(timeout, (int, float))
            and not isinstance(timeout, bool)
            and timeout > 0
        ):
            return int(timeout)
    return DECOMPILER_TIMEOUT


def _default_binary_opener(
    binary_path: str,
    verbose: bool,
    r2_factory: Callable,
    *,
    anal_timeout: int | None = None,
) -> IR2Client:
    """Top-level picklable adapter for open_binary_with_r2.

    ``anal_timeout`` is bound by the factories (via ``functools.partial``) from
    config; ``None`` keeps r2_session's built-in default for direct callers.
    """
    from .infrastructure.adapters.r2_session import open_binary_with_r2
    from .constants import DECOMPILER_TIMEOUT

    return open_binary_with_r2(
        binary_path,
        verbose,
        r2_factory=r2_factory,
        anal_timeout=anal_timeout if anal_timeout is not None else DECOMPILER_TIMEOUT,
    )


def _default_r2_closer(r2: IR2Client) -> Result[None, str]:
    """Top-level picklable adapter for close_r2_client."""
    from .infrastructure.adapters.r2_session import close_r2_client

    return close_r2_client(r2)


def _default_file_finder(directory: str, file_type: str = "any") -> list[str]:
    """Top-level picklable adapter for find_executable_files."""
    from .infrastructure.file_detection import find_executable_files

    return find_executable_files(directory, file_type=file_type)


def _default_orchestrator_factory(
    config: IConfigRepository,
) -> IDecompilerOrchestrator:
    """Top-level adapter that rebuilds the decompiler orchestrator.

    Parallel directory analysis serializes the worker job (including this
    factory) to send it to a ProcessPoolExecutor, so it must be a top-level
    function rather than a closure/lambda, which cannot be serialized.
    """
    from .infrastructure.decompilers.orchestrator import (
        create_decompiler_orchestrator,
    )

    return create_decompiler_orchestrator(
        config,
        config_factory=create_config_from_dict,
    )


def create_application_wiring(config_path: str | None = None) -> AnalysisRuntime:
    """Build the explicit wiring used by outer-layer entry points."""
    from .infrastructure.decompilers.orchestrator import create_decompiler_orchestrator

    config = create_config_from_file(config_path)
    return AnalysisRuntime(
        config=config,
        binary=BinaryRuntimeServices(
            binary_opener=functools.partial(
                _default_binary_opener, anal_timeout=_resolve_anal_timeout(config)
            ),
            r2_closer=_default_r2_closer,
        ),
        directory=DirectoryRuntimeServices(
            file_finder=_default_file_finder,
        ),
        config_factory=create_config_from_dict,
        r2_factory=create_r2_client,
        decompiler_orchestrator=create_decompiler_orchestrator(
            config,
            config_factory=create_config_from_dict,
        ),
        orchestrator_factory=_default_orchestrator_factory,
    )


__all__ = [
    "DEFAULT_R2_FLAGS",
    "DictConfig",
    "create_application_wiring",
    "create_config_from_dict",
    "create_config_from_file",
    "create_r2_client",
]
