"""Construction helpers for analyzer instances."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from .domain.protocols import IConfigRepository, IR2Client
from .runtime_factories import create_r2_client

if TYPE_CHECKING:
    from .application.binary_analyzer import R2BinaryAnalyzer


def create_binary_analyzer(
    config: IConfigRepository,
    decompiler_type: str = "default",
    verbose: bool = False,
    r2_factory: Callable[[str], IR2Client] | None = None,
) -> "R2BinaryAnalyzer":
    """Construct an analyzer with explicit dependencies."""
    from .application.binary_analyzer import R2BinaryAnalyzer

    from .application.analysis_runtime import BinaryRuntimeServices
    from .runtime_factories import _default_binary_opener, _default_r2_closer

    effective_factory = r2_factory if r2_factory is not None else create_r2_client
    return R2BinaryAnalyzer(
        decompiler_type=decompiler_type,
        verbose=verbose,
        r2_factory=effective_factory,
        config=config,
        binary_services=BinaryRuntimeServices(
            binary_opener=_default_binary_opener,
            r2_closer=_default_r2_closer,
        ),
    )


__all__ = ["create_binary_analyzer"]
