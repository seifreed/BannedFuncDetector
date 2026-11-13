"""Logging configuration and output safety."""

from __future__ import annotations

import logging
import json
import logging.handlers
import math
import os
import re
import sys
import copy
import threading
from queue import Full
from types import TracebackType
from datetime import datetime, timezone
from typing import Any

from bannedfuncdetector.observability import (
    current_operation,
    current_request_id,
    ensure_request_id,
    log_context,
    new_log_context,
    new_request_id,
    operation_context,
    safe_exception_fields,
    safe_stack_trace,
)
from concurrent_log_handler import ConcurrentRotatingFileHandler


_logging_configuration_lock = threading.Lock()
_MAX_LOG_MESSAGE_CHARS = 16_384
_LOG_FILE_MAX_BYTES = 10 * 1024 * 1024
_LOG_FILE_BACKUP_COUNT = 5


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
_SENSITIVE_FIELD_NAME = re.compile(rf"(?i)^(?:{_SENSITIVE_NAMES})$")
_COOKIE_HEADER = re.compile(
    r"(?i)(\b(?:set-cookie|cookie)\s*:\s*)"
    r"(?:(?!\\x0a|\\x0d)[^\r\n])*"
)
_URL_WITH_PRIVATE_PARTS = re.compile(
    r"(?i)\b(https?://)(?:[^/@\s]+@)?([^/?#\s]+)(?:[/?#][^\s]*)?"
)
_STANDARD_LOG_RECORD_FIELDS = frozenset(logging.makeLogRecord({}).__dict__) | {
    "asctime",
    "message",
}
_MAX_LOG_FIELD_ITEMS = 32
_MAX_LOG_FIELD_DEPTH = 3


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


def _safe_field_value(value: Any, remaining_chars: list[int], depth: int = 0) -> Any:
    if isinstance(value, str):
        safe_value = _safe_message(value)
        if len(safe_value) > remaining_chars[0]:
            marker = "[truncated]"
            available = remaining_chars[0]
            safe_value = (
                safe_value[: available - len(marker)] + marker
                if available > len(marker)
                else marker[:available]
            )
        remaining_chars[0] = max(0, remaining_chars[0] - len(safe_value))
        return safe_value
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if value.bit_length() <= 64 else "[number omitted]"
    if isinstance(value, float):
        return value if math.isfinite(value) else "[non-finite number omitted]"
    if isinstance(value, BaseException):
        return type(value).__name__
    if depth >= _MAX_LOG_FIELD_DEPTH:
        return "[nested value omitted]"
    if isinstance(value, dict):
        safe_mapping: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _MAX_LOG_FIELD_ITEMS or remaining_chars[0] <= 0:
                safe_mapping["[truncated]"] = True
                break
            safe_key = _safe_field_value(
                key if isinstance(key, str) else "[non-string key]",
                remaining_chars,
                depth + 1,
            )
            safe_mapping[safe_key] = (
                "[REDACTED]"
                if isinstance(key, str) and _SENSITIVE_FIELD_NAME.fullmatch(key)
                else _safe_field_value(item, remaining_chars, depth + 1)
            )
        return safe_mapping
    if isinstance(value, (list, tuple)):
        safe_items = [
            _safe_field_value(item, remaining_chars, depth + 1)
            for item in value[:_MAX_LOG_FIELD_ITEMS]
        ]
        if len(value) > _MAX_LOG_FIELD_ITEMS or remaining_chars[0] <= 0:
            safe_items.append("[truncated]")
        return tuple(safe_items) if isinstance(value, tuple) else safe_items
    return f"[{type(value).__name__} omitted]"


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
        exception = exc_info[1]
        if exception is None:
            return ""
        return _safe_message(safe_stack_trace(exception))
    except Exception as exc:
        return f"[stack trace formatting failed: {type(exc).__name__}]"


class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "service": "bannedfuncdetector",
            "component": record.name,
            "message": (
                getattr(record, "_bfd_message", None)
                or _safe_record_message(record)
            ),
        }
        environment = os.getenv("BFD_ENVIRONMENT")
        if environment:
            event["environment"] = _safe_message(environment)
        request_id = getattr(record, "request_id", None) or current_request_id()
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
            "config_section",
            "missing_keys",
            "dropped_count",
            "file_count",
            "insecure_count",
            "function_count",
            "total_functions",
            "completed_functions",
            "success_count",
            "error_count",
            "detected_count",
            "worker_count",
            "execution_mode",
            "file_type",
            "decompiler_type",
            "percent_complete",
            "detection_method",
            "file_name",
            "function_name",
            "address",
            "banned_calls",
        ):
            value = getattr(record, field, None)
            if value is not None:
                event[field] = _safe_field_value(value, [_MAX_LOG_MESSAGE_CHARS])
        stack_trace = getattr(record, "stack_trace", None)
        if record.exc_info:
            stack_trace = _safe_exception_text(record.exc_info)
            if record.exc_info[0] is not None:
                event.setdefault("error_type", record.exc_info[0].__name__)
        if stack_trace:
            event["stack_trace"] = _safe_message(stack_trace)
        return json.dumps(event, ensure_ascii=True)


class _TextLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, timezone.utc).isoformat()
        timestamp = timestamp.replace("+00:00", "Z")
        fields = [timestamp, record.levelname, _safe_message(record.name)]
        request_id = getattr(record, "request_id", None) or current_request_id()
        if request_id is not None:
            fields.append(f"request_id={_safe_message(str(request_id))}")
        operation = getattr(record, "operation", None) or current_operation()
        if operation is not None:
            fields.append(f"operation={_safe_message(str(operation))}")
        event_message = getattr(record, "_bfd_message", None)
        if event_message is None:
            event_message = _safe_record_message(record)
        message = " ".join(fields) + f" {event_message}"
        if record.exc_info:
            message += "\n" + _safe_exception_text(record.exc_info)
        elif getattr(record, "stack_trace", None):
            message += "\n" + _safe_message(getattr(record, "stack_trace"))
        return message


class _RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        request_id = current_request_id()
        if request_id is not None:
            record.request_id = request_id
        if getattr(record, "operation", None) is None:
            operation = current_operation()
            if operation is not None:
                record.operation = operation
        return True


class _SanitizingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        safe_message = _safe_record_message(record)
        record.msg = safe_message
        if record.exc_info:
            if record.exc_info[0] is not None and not hasattr(record, "error_type"):
                record.error_type = record.exc_info[0].__name__
            record.exc_text = _safe_exception_text(record.exc_info)
            record.stack_trace = record.exc_text
            record._bfd_message = safe_message
            if record.exc_text:
                record.msg = f"{safe_message}\n{record.exc_text}"
            record.exc_info = None
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
        remaining_chars = [_MAX_LOG_MESSAGE_CHARS]
        for field, value in tuple(record.__dict__.items()):
            if field in {"msg", "args", "exc_info"}:
                continue
            if (
                field not in _STANDARD_LOG_RECORD_FIELDS
                and _SENSITIVE_FIELD_NAME.fullmatch(field)
            ):
                setattr(record, field, "[REDACTED]")
                continue
            if isinstance(value, str):
                setattr(record, field, _safe_message(value))
            elif field not in _STANDARD_LOG_RECORD_FIELDS:
                setattr(record, field, _safe_field_value(value, remaining_chars))
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
            __name__,
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
        request_id = current_request_id()
        if request_id is not None:
            record.request_id = request_id
        operation = current_operation()
        if operation is not None:
            record.operation = operation
        self._overflow_handler.handle(record)

    def prepare(self, record: logging.LogRecord) -> logging.LogRecord:
        prepared = copy.copy(record)
        if record.exc_info:
            prepared.stack_trace = _safe_exception_text(record.exc_info)
        prepared.message = getattr(record, "_bfd_message", None) or _safe_record_message(
            record
        )
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
            "Configured log destination failed; using stderr",
            extra={
                "event_name": "logging_destination_fallback",
                "outcome": "degraded",
                **safe_exception_fields(destination_error),
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


__all__ = [
    "configure_logging",
    "configure_worker_logging",
    "ensure_request_id",
    "log_context",
    "new_log_context",
    "new_request_id",
    "operation_context",
    "safe_exception_fields",
]
