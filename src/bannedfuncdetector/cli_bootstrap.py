"""CLI bootstrap helpers with stable re-exports for logging configuration."""

from __future__ import annotations

import logging
import sys
import time
from collections.abc import Callable

from .infrastructure.logging_config import (
    configure_logging,
    configure_worker_logging,
    ensure_request_id,
    log_context,
    new_log_context,
    new_request_id,
    operation_context,
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

    with operation_context("requirements_check"):
        started = time.perf_counter()
        logger.info("Checking system requirements...")
        if not check_requirements(False):
            logger.error(
                "Not all system requirements are met.",
                extra={
                    "event_name": "requirements_check_failed",
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                    "outcome": "error",
                    "error_code": 1,
                },
            )
            sys.exit(1)
        logger.info(
            "Requirements check completed.",
            extra={
                "event_name": "requirements_check_completed",
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "outcome": "success",
            },
        )


__all__ = [
    "configure_logging",
    "configure_worker_logging",
    "ensure_request_id",
    "log_context",
    "new_log_context",
    "new_request_id",
    "operation_context",
    "validate_requirements",
]
