"""R2 session lifecycle helpers for infrastructure-backed binary analysis.

This module contains best-effort mitigation for transient r2/r2pipe startup
failures. It does not guarantee that every transport-layer fault can be
classified correctly because r2pipe may wrap backend failures inconsistently.
The retry policy therefore stays in infrastructure and should be treated as an
operational guardrail, not as a correctness guarantee.
"""

from __future__ import annotations

import errno
import logging
import time
from collections.abc import Callable

from bannedfuncdetector.analyzer_exceptions import TransientR2Error
from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.domain.result import Result, err, ok

logger = logging.getLogger(__name__)

_OPEN_RETRY_ATTEMPTS = 2
_OPEN_RETRY_DELAY_SECONDS = 0.05


def close_r2_client(r2: IR2Client) -> Result[None, str]:
    try:
        r2.quit()
        return ok(None)
    except (
        RuntimeError,
        OSError,
        IOError,
        AttributeError,
        TypeError,
        ValueError,
    ) as exc:
        message = f"Error closing r2 client {hex(id(r2))} ({type(r2).__name__}): {exc}"
        logger.warning(message)
        return err(message)


def is_transient_r2_setup_error(exc: Exception) -> bool:
    if isinstance(exc, TransientR2Error):
        return True
    if isinstance(exc, BrokenPipeError):
        return True
    if isinstance(exc, OSError):
        if getattr(exc, "errno", None) in {
            errno.EPIPE,
            errno.ECONNRESET,
            errno.ETIMEDOUT,
            errno.EINTR,
        }:
            return True
    return False


def open_binary_with_r2(
    binary_path: str,
    verbose: bool = False,
    *,
    r2_factory: Callable[[str], IR2Client],
) -> IR2Client:
    last_error: Exception | None = None
    if verbose:
        logger.info(f"Opening {binary_path} with r2pipe...")

    r2: IR2Client | None = None
    for attempt in range(1, _OPEN_RETRY_ATTEMPTS + 1):
        try:
            r2 = r2_factory(binary_path)
            if verbose:
                logger.info("Analyzing the binary...")
            r2.cmd("aaa")
            return r2
        except (
            TransientR2Error,
            BrokenPipeError,
            OSError,
            IOError,
            RuntimeError,
        ) as exc:
            last_error = exc
            if r2 is not None:
                close_r2_client(r2)
                r2 = None
            if attempt == _OPEN_RETRY_ATTEMPTS or not is_transient_r2_setup_error(exc):
                raise
            logger.warning(
                "Transient r2 setup failure for %s on attempt %s/%s: %s",
                binary_path,
                attempt,
                _OPEN_RETRY_ATTEMPTS,
                exc,
            )
            time.sleep(_OPEN_RETRY_DELAY_SECONDS)
    raise RuntimeError(f"Failed to open binary with r2: {binary_path}") from last_error


__all__ = [
    "close_r2_client",
    "is_transient_r2_setup_error",
    "open_binary_with_r2",
]
