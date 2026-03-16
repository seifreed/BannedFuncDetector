"""Dispatch helpers for decompiler orchestration."""

from __future__ import annotations

import logging

from bannedfuncdetector.domain.protocols import IConfigRepository, IR2Client
from bannedfuncdetector.domain.result import err
from bannedfuncdetector.domain.types import DecompilationResultType

from .base_decompiler import DecompilationError, DecompilerType
from .cascade import _decompile_with_instance
from .selector import resolve_to_decompiler_type

logger = logging.getLogger(__name__)


def decompile_function(
    r2: IR2Client,
    function_name: str,
    decompiler_type: str | DecompilerType | None = None,
    *,
    config: IConfigRepository,
) -> DecompilationResultType:
    """Decompile one function using the resolved decompiler backend."""
    try:
        decompiler_type_enum = resolve_to_decompiler_type(decompiler_type, config)
        decompiler_options = config["decompiler"].get("options", {})
        return _decompile_with_instance(r2, function_name, decompiler_type_enum, decompiler_options)
    except (KeyError, AttributeError, TypeError) as exc:
        return err(f"Configuration error decompiling {function_name}: {str(exc)}")
    except (RuntimeError, ValueError) as exc:
        logger.error(f"Runtime error decompiling {function_name}: {exc}")
        return err(f"Runtime error decompiling {function_name}: {str(exc)}")
    except DecompilationError as exc:
        logger.error(f"Decompilation error for {function_name}: {exc}")
        return err(f"Decompilation error: {str(exc)}")


__all__ = ["decompile_function"]
