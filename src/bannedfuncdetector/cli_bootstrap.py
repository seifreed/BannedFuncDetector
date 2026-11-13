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
import time
import uuid
from queue import Full
from types import TracebackType
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timezone
from collections.abc import Iterator
from typing import Any

from concurrent_log_handler import ConcurrentRotatingFileHandler


_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "bannedfuncdetector_request_id", default=None
)
_operation: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "bannedfuncdetector_operation", default=None
)
_logging_configuration_lock = threading.Lock()
_MAX_LOG_MESSAGE_CHARS = 16_384
_LOG_FILE_MAX_BYTES = 10 * 1024 * 1024
_LOG_FILE_BACKUP_COUNT = 5


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


@contextmanager
def operation_context(operation: str) -> Iterator[None]:
    token = _operation.set(operation)
    try:
        yield
    finally:
        _operation.reset(token)


_SENSITIVE_NAMES = (
    r"password|passwd|(?:access|refresh|id)?[_-]?token|api[_-]?key|"
    r"client[_-]?secret|secret|session(?:id)?|private[_-]?key|"
    r"authorization|set-cookie|cookie"
)
_SENSITIVE_VALUE = re.compile(
    rf"(?i)(\b(?:{_SENSITIVE_NAMES})\b[\"']?\s*[=:]\s*|"
    rf"--(?:{_SENSITIVE_NAMES})\s+)(?!\[REDACTED\])"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)|"
    r"(\bauthorization\s*:\s*)(?!\[REDACTED\])(?:bearer\s+|basic\s+)?"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)|"
    r"(\b(?:bearer|basic)\s+)(?!\[REDACTED\])[^\s,;]+"
)
_COOKIE_HEADER = re.compile(
    r"(?i)(\b(?:set-cookie|cookie)\s*:\s*)"
    r"(?:(?!\\x0a|\\x0d)[^\r\n])*"
)
_URL_WITH_PRIVATE_PARTS = re.compile(
    r"(?i)\b(https?://)(?:[^/@\s]+@)?([^/?#\s]+)(?:[/?#][^\s]*)?"
)


def _safe_message(value: str) -> str:
    truncated = len(value) > _MAX_LOG_MESSAGE_CHARS
    value = value[:_MAX_LOG_MESSAGE_CHARS]
    redacted = _COOKIE_HEADER.sub(r"\1[REDACTED]", value)
    redacted = _SENSITIVE_VALUE.sub(
        lambda match: f"{match.group(1) or match.group(2) or match.group(3)}[REDACTED]",
        redacted,
    )
    redacted = _URL_WITH_PRIVATE_PARTS.sub(r"\1\2", redacted)
    home_directory = os.path.expanduser("~")
    if home_directory != "~":
        redacted = redacted.replace(home_directory, "~")
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
            event["request_id"] = _safe_message(str(request_id))
        for field in (
            "operation",
            "event_name",
            "duration_ms",
            "outcome",
            "error_type",
            "error_code",
            "error_line",
            "error_column",
            "error_category",
            "error_phase",
            "dropped_count",
        ):
            value = getattr(record, field, None)
            if value is not None:
                event[field] = _safe_message(value) if isinstance(value, str) else value
        stack_trace = getattr(record, "stack_trace", None)
        if record.exc_info:
            stack_trace = _safe_exception_text(record.exc_info)
        if stack_trace:
            event["stack_trace"] = _safe_message(stack_trace)
        return json.dumps(event, ensure_ascii=True)


class _TextLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, timezone.utc).isoformat()
        timestamp = timestamp.replace("+00:00", "Z")
        fields = [timestamp, record.levelname, _safe_message(record.name)]
        request_id = getattr(record, "request_id", None) or _request_id.get()
        if request_id is not None:
            fields.append(f"request_id={_safe_message(str(request_id))}")
        operation = getattr(record, "operation", None) or _operation.get()
        if operation is not None:
            fields.append(f"operation={_safe_message(str(operation))}")
        message = " ".join(fields) + f" {_safe_record_message(record)}"
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
        if getattr(record, "operation", None) is None:
            operation = _operation.get()
            if operation is not None:
                record.operation = operation
        return True


class _SanitizingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _safe_record_message(record)
        if record.exc_info:
            if record.exc_info[0] is not None and not hasattr(record, "error_type"):
                record.error_type = record.exc_info[0].__name__
            record.exc_text = _safe_exception_text(record.exc_info)
        elif record.levelno >= logging.ERROR and not hasattr(record, "error_type"):
            args = record.args
            candidates = (
                args.values()
                if isinstance(args, dict)
                else args
                if isinstance(args, tuple)
                else (args,)
            )
            error = next(
                (value for value in candidates if isinstance(value, BaseException)),
                None,
            )
            if error is not None:
                record.error_type = type(error).__name__
        record.args = ()
        stack_trace = getattr(record, "stack_trace", None)
        if stack_trace:
            record.stack_trace = _safe_message(stack_trace)
        return True


class _ContextQueueHandler(logging.handlers.QueueHandler):
    def __init__(self, log_queue: Any) -> None:
        super().__init__(log_queue)
        formatter = (
            _JsonLogFormatter()
            if os.getenv("BFD_LOG_FORMAT", "text").lower() == "json"
            else _TextLogFormatter()
        )
        self._overflow_handler = logging.StreamHandler(sys.stderr)
        self._overflow_handler.setFormatter(formatter)
        self._queue_saturated = False
        self._dropped_records = 0

    def enqueue(self, record: logging.LogRecord) -> None:
        try:
            self.queue.put_nowait(record)
        except Full:
            if not self._queue_saturated:
                self._queue_saturated = True
                self._emit_overflow_event(
                    "Worker log queue saturated; low-severity records may be dropped",
                    "worker_log_queue_saturated",
                )
            if record.levelno >= logging.ERROR:
                self._overflow_handler.handle(record)
            else:
                self._dropped_records += 1
            return

        if self._queue_saturated:
            dropped_records = self._dropped_records
            self._queue_saturated = False
            self._dropped_records = 0
            self._emit_overflow_event(
                f"Worker log queue recovered after dropping {dropped_records} records",
                "worker_log_queue_recovered",
                dropped_count=dropped_records,
            )

    def _emit_overflow_event(
        self,
        message: str,
        event_name: str,
        *,
        dropped_count: int | None = None,
    ) -> None:
        record = logging.LogRecord(
            "bannedfuncdetector.cli_bootstrap",
            logging.WARNING,
            "",
            0,
            message,
            (),
            None,
        )
        record.event_name = event_name
        record.outcome = "degraded"
        if dropped_count is not None:
            record.dropped_count = dropped_count
        request_id = _request_id.get()
        if request_id is not None:
            record.request_id = request_id
        operation = _operation.get()
        if operation is not None:
            record.operation = operation
        self._overflow_handler.handle(record)

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
    destination_error = None
    with _logging_configuration_lock:
        root_logger.setLevel(level)
        if not root_logger.handlers:
            handler, destination_error = _configured_handler(formatter)
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
    if destination_error is not None:
        logger = logging.getLogger(__name__)
        logger.warning(
            "Configured log destination failed; using stderr: %s",
            destination_error,
            exc_info=(
                type(destination_error),
                destination_error,
                destination_error.__traceback__,
            )
            if destination_error.__traceback__
            else None,
            extra={
                "error_type": type(destination_error).__name__,
                "event_name": "logging_destination_fallback",
            },
        )


def _configured_handler(
    formatter: logging.Formatter,
) -> tuple[logging.Handler, OSError | ValueError | None]:
    destination = os.getenv("BFD_LOG_DESTINATION", "stderr")
    error: OSError | ValueError | None = None
    if destination == "stdout":
        handler: logging.Handler = logging.StreamHandler(sys.stdout)
    elif destination == "stderr":
        handler = logging.StreamHandler(sys.stderr)
    elif destination.startswith("file:") and destination[5:]:
        try:
            file_path = destination[5:]
            file_descriptor = os.open(
                file_path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600 if os.name == "posix" else 0o666,
            )
            try:
                if os.name == "posix":
                    os.fchmod(file_descriptor, 0o600)
            finally:
                os.close(file_descriptor)
            handler = ConcurrentRotatingFileHandler(
                file_path,
                maxBytes=_LOG_FILE_MAX_BYTES,
                backupCount=_LOG_FILE_BACKUP_COUNT,
                encoding="utf-8",
                chmod=0o600 if os.name == "posix" else None,
            )
        except OSError as exc:
            handler = logging.StreamHandler(sys.stderr)
            error = exc
    else:
        handler = logging.StreamHandler(sys.stderr)
        error = ValueError("Unsupported BFD_LOG_DESTINATION")
    handler.setFormatter(formatter)
    return handler, error


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
