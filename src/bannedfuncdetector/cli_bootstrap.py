#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bootstrap helpers for CLI entry points."""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable


def configure_logging() -> None:
    """Configure process-wide logging for CLI execution."""
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
    )


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
