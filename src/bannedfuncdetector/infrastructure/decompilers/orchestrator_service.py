"""High-level orchestration service and factory."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from bannedfuncdetector.domain import BannedFunction, FunctionDescriptor
from bannedfuncdetector.domain.protocols import IConfigRepository, IR2Client
from bannedfuncdetector.domain.result import Result
from bannedfuncdetector.domain.types import DecompilationResultType

from .availability import check_decompiler_available
from .orchestrator_dispatch import decompile_function
from .orchestrator_progress import _log_final_summary
from .orchestrator_runtime import (
    _get_function_filtering_config,
    _iterate_and_decompile_functions,
    _log_decompilation_progress,
)
from .selector import select_decompiler


def decompile_with_selected_decompiler(
    r2: IR2Client,
    functions: list[FunctionDescriptor],
    verbose: bool = True,
    decompiler_type: str | None = None,
    *,
    config: IConfigRepository,
    decompile_function_impl: Callable[..., DecompilationResultType] = decompile_function,
) -> list[BannedFunction]:
    """Use the selected decompiler to scan all candidate functions."""
    decompiler_type_str = select_decompiler(
        requested=decompiler_type, force=False, verbose=verbose, config=config
    )
    if not functions:
        if verbose:
            logging.getLogger(__name__).warning("No functions found to decompile")
        return []

    _log_decompilation_progress(functions, decompiler_type_str, verbose)
    threshold, skip = _get_function_filtering_config(config)
    detected, success_count, error_count = _iterate_and_decompile_functions(
        r2,
        functions,
        decompiler_type_str,
        verbose,
        threshold,
        skip,
        config,
        decompile_function_impl,
    )
    _log_final_summary(len(functions), success_count, error_count, len(detected), verbose)
    return detected


class DecompilerOrchestrator:
    """Protocol-compliant orchestration facade."""

    def __init__(
        self,
        config: IConfigRepository,
        *,
        config_factory: "Callable[[dict], IConfigRepository] | None" = None,
    ) -> None:
        self._config = config
        self._config_factory = config_factory

    def decompile_function(
        self,
        r2: IR2Client,
        function_name: str,
        decompiler_type: str | None = None,
        **options: Any,
    ) -> "Result[str, str]":
        if options and self._config_factory is not None:
            # Merge caller options into a config overlay so they reach the cascade
            config_dict = self._config.to_dict()
            decompiler_opts = config_dict.get("decompiler", {}).get("options", {})
            decompiler_opts.update(options)
            config_dict.setdefault("decompiler", {})["options"] = decompiler_opts
            merged_config = self._config_factory(config_dict)
            return decompile_function(r2, function_name, decompiler_type, config=merged_config)
        return decompile_function(r2, function_name, decompiler_type, config=self._config)

    def select_decompiler(
        self,
        requested: str | None = None,
        force: bool = False,
    ) -> str:
        return select_decompiler(
            requested=requested, force=force, verbose=False, config=self._config
        )

    def check_decompiler_available(self, decompiler_type: str) -> bool:
        return check_decompiler_available(decompiler_type)


def create_decompiler_orchestrator(
    config: IConfigRepository,
    *,
    config_factory: "Callable[[dict], IConfigRepository] | None" = None,
) -> DecompilerOrchestrator:
    """Create a new orchestrator instance."""
    return DecompilerOrchestrator(config, config_factory=config_factory)


__all__ = [
    "DecompilerOrchestrator",
    "create_decompiler_orchestrator",
    "decompile_with_selected_decompiler",
]
