"""Bootstrap helpers for CLI entry points."""

from __future__ import annotations

import logging
import json
import logging.handlers
import os
import re
import sys
import contextvars
import copy
import threading
import uuid
from types import TracebackType
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timezone
from collections.abc import Iterator
from typing import Any


_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "bannedfuncdetector_request_id", default=None
)
_logging_configuration_lock = threading.Lock()
_MAX_LOG_MESSAGE_CHARS = 16_384


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
def new_log_context() -> Iterator[str]:
    request_id = uuid.uuid4().hex
    token = _request_id.set(request_id)
    try:
        yield request_id
    finally:
        _request_id.reset(token)


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
    r"\b(?:authorization|set-cookie|cookie)\s*:\s*"
    r"(?:bearer\s+|basic\s+)?|"
    r"\b(?:bearer|basic)\s+)[^\s,;]+"
)
_URL_WITH_PRIVATE_PARTS = re.compile(
    r"(?i)\b(https?://)(?:[^/@\s]+@)?([^/?#\s]+)(?:[/?#][^\s]*)?"
)


def _safe_message(value: str) -> str:
    truncated = len(value) > _MAX_LOG_MESSAGE_CHARS
    value = value[:_MAX_LOG_MESSAGE_CHARS]
    redacted = _SENSITIVE_VALUE.sub(r"\1[REDACTED]", value)
    redacted = _URL_WITH_PRIVATE_PARTS.sub(r"\1\2", redacted)
    escaped = "".join(
        character if character.isprintable() else _escape_character(character)
        for character in redacted
    )
    if truncated or len(escaped) > _MAX_LOG_MESSAGE_CHARS:
        marker = "[truncated]"
        return escaped[: _MAX_LOG_MESSAGE_CHARS - len(marker)] + marker
    return escaped


def _escape_character(character: str) -> str:
    codepoint = ord(character)
    return f"\\x{codepoint:02x}" if codepoint <= 0xFF else ascii(character)[1:-1]


def _safe_record_message(record: logging.LogRecord) -> str:
    try:
        return _safe_message(record.getMessage())
    except Exception as exc:
        return f"[log message formatting failed: {type(exc).__name__}]"


def _safe_exception_text(
    exc_info: tuple[type[BaseException], BaseException, TracebackType | None]
    | tuple[None, None, None],
) -> str:
    try:
        return _safe_message(logging.Formatter().formatException(exc_info))
    except Exception as exc:
        return f"[exception formatting failed: {type(exc).__name__}]"


class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "service": "bannedfuncdetector",
            "component": record.name,
            "message": _safe_record_message(record),
        }
        environment = os.getenv("BFD_ENVIRONMENT")
        if environment:
            event["environment"] = _safe_message(environment)
        request_id = getattr(record, "request_id", None) or _request_id.get()
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
        stack_trace = getattr(record, "stack_trace", None)
        if record.exc_info:
            stack_trace = _safe_exception_text(record.exc_info)
        if stack_trace:
            event["stack_trace"] = _safe_message(stack_trace)
        return json.dumps(event, ensure_ascii=True)


class _TextLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = f"[{record.levelname}] {_safe_record_message(record)}"
        if record.exc_info:
            message += "\n" + _safe_exception_text(record.exc_info)
        elif getattr(record, "stack_trace", None):
            message += "\n" + _safe_message(getattr(record, "stack_trace"))
        return message


class _RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        request_id = _request_id.get()
        if request_id is not None:
            record.request_id = request_id
        return True


class _SanitizingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _safe_record_message(record)
        record.args = ()
        if record.exc_info:
            if record.exc_info[0] is not None and not hasattr(record, "error_type"):
                record.error_type = record.exc_info[0].__name__
            record.exc_text = _safe_exception_text(record.exc_info)
        stack_trace = getattr(record, "stack_trace", None)
        if stack_trace:
            record.stack_trace = _safe_message(stack_trace)
        return True


class _ContextQueueHandler(logging.handlers.QueueHandler):
    def prepare(self, record: logging.LogRecord) -> logging.LogRecord:
        prepared = copy.copy(record)
        if record.exc_info:
            prepared.stack_trace = _safe_exception_text(record.exc_info)
        prepared.message = _safe_record_message(record)
        prepared.msg = prepared.message
        prepared.args = None
        prepared.exc_info = None
        prepared.exc_text = None
        return prepared


def configure_logging(verbose: bool = False) -> None:
    """Configure process-wide logging for CLI execution.

    ``verbose`` lowers the level to DEBUG so the ``logger.debug`` diagnostics
    (symlink following, r2 client flags, file discovery, …) become visible;
    otherwise they are unreachable since the level defaults to INFO.
    """
    level = _configured_level(verbose)
    log_format = os.getenv("BFD_LOG_FORMAT", "text").lower()
    formatter = _JsonLogFormatter() if log_format == "json" else _TextLogFormatter()
    root_logger = logging.getLogger()
    with _logging_configuration_lock:
        root_logger.setLevel(level)
        if not root_logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            root_logger.addHandler(handler)
        for configured_handler in root_logger.handlers:
            if not any(
                isinstance(item, _RequestContextFilter)
                for item in configured_handler.filters
            ):
                configured_handler.addFilter(_RequestContextFilter())
            if not any(
                isinstance(item, _SanitizingFilter)
                for item in configured_handler.filters
            ):
                configured_handler.addFilter(_SanitizingFilter())


def configure_worker_logging(verbose: bool, log_queue: Any) -> None:
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(_configured_level(verbose))
    handler = _ContextQueueHandler(log_queue)
    handler.addFilter(_RequestContextFilter())
    handler.addFilter(_SanitizingFilter())
    root_logger.addHandler(handler)


def _configured_level(verbose: bool) -> int:
    configured_name = os.getenv(
        "BFD_LOG_LEVEL", "DEBUG" if verbose else "INFO"
    ).upper()
    configured_value = logging.getLevelName(configured_name)
    return configured_value if isinstance(configured_value, int) else logging.INFO


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
    "configure_worker_logging",
    "ensure_request_id",
    "log_context",
    "new_log_context",
    "new_request_id",
    "validate_requirements",
]
