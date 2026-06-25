"""Bootstrap helpers for CLI entry points."""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable


def configure_logging(verbose: bool = False) -> None:
    """Configure process-wide logging for CLI execution.

    ``verbose`` lowers the level to DEBUG so the ``logger.debug`` diagnostics
    (symlink following, r2 client flags, file discovery, …) become visible;
    otherwise they are unreachable since the level defaults to INFO.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )
    if verbose:
        # basicConfig is a no-op if handlers already exist (e.g. a worker that
        # configured at INFO first), so force the level explicitly.
        logging.getLogger().setLevel(logging.DEBUG)


def validate_requirements(
    skip_requirements: bool,
    *,
    check_requirements: Callable[[bool], bool],
    logger: logging.Logger,
) -> None:
    """Validate environment requirements before running analysis."""
    if skip_requirements:
        return

    logger.info("Checking system requirements...")
    if not check_requirements(False):
        logger.error("Not all system requirements are met.")
        sys.exit(1)
    logger.info("Requirements check completed.")


__all__ = [
    "configure_logging",
    "validate_requirements",
]
