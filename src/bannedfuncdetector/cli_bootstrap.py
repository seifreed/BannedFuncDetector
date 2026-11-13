"""Bootstrap helpers for CLI entry points."""

from __future__ import annotations

import logging
import json
import os
import re
import sys
import contextvars
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timezone
from collections.abc import Iterator


_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "bannedfuncdetector_request_id", default=None
)


def ensure_request_id() -> str:
    request_id = _request_id.get()
    if request_id is None:
        request_id = uuid.uuid4().hex
        _request_id.set(request_id)
    return request_id


def new_request_id() -> str:
    request_id = uuid.uuid4().hex
    _request_id.set(request_id)
    return request_id


@contextmanager
def log_context(request_id: str | None) -> Iterator[None]:
    token = _request_id.set(request_id)
    try:
        yield
    finally:
        _request_id.reset(token)


_SENSITIVE_VALUE = re.compile(
    r"(?i)(\b(?:password|passwd|(?:access|refresh|id)?[_-]?token|"
    r"api[_-]?key|client[_-]?secret|secret|session(?:id)?|private[_-]?key)"
    r"\b\s*[=:]\s*[\"']?|"
    r"\bauthorization\s*:\s*(?:bearer\s+|basic\s+)?|"
    r"\b(?:bearer|basic)\s+)[^\s,;]+"
)


def _safe_message(value: str) -> str:
    redacted = _SENSITIVE_VALUE.sub(r"\1[REDACTED]", value)
    return "".join(
        character
        if character >= " " and character != "\x7f"
        else f"\\x{ord(character):02x}"
        for character in redacted
    )


class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "service": "bannedfuncdetector",
            "component": record.name,
            "message": _safe_message(record.getMessage()),
        }
        request_id = _request_id.get()
        if request_id is not None:
            event["request_id"] = request_id
        for field in (
            "operation",
            "event_name",
            "duration_ms",
            "outcome",
            "error_type",
        ):
            value = getattr(record, field, None)
            if value is not None:
                event[field] = value
        if record.exc_info:
            event["stack_trace"] = _safe_message(self.formatException(record.exc_info))
        return json.dumps(event, ensure_ascii=True)


class _TextLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = f"[{record.levelname}] {_safe_message(record.getMessage())}"
        if record.exc_info:
            message += "\n" + _safe_message(self.formatException(record.exc_info))
        return message


def configure_logging(verbose: bool = False) -> None:
    """Configure process-wide logging for CLI execution.

    ``verbose`` lowers the level to DEBUG so the ``logger.debug`` diagnostics
    (symlink following, r2 client flags, file discovery, …) become visible;
    otherwise they are unreachable since the level defaults to INFO.
    """
    configured_level = os.getenv(
        "BFD_LOG_LEVEL", "DEBUG" if verbose else "INFO"
    ).upper()
    level = getattr(logging, configured_level, logging.INFO)
    log_format = os.getenv("BFD_LOG_FORMAT", "text").lower()
    formatter = _JsonLogFormatter() if log_format == "json" else _TextLogFormatter()
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)


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
    "ensure_request_id",
    "log_context",
    "new_request_id",
    "validate_requirements",
]
