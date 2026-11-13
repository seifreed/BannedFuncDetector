"""Operation and request context shared across application boundaries."""

from __future__ import annotations

import contextvars
import uuid
from collections.abc import Iterator
from contextlib import contextmanager


_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "bannedfuncdetector_request_id", default=None
)
_operation: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "bannedfuncdetector_operation", default=None
)


def current_request_id() -> str | None:
    return _request_id.get()


def current_operation() -> str | None:
    return _operation.get()


def ensure_request_id() -> str:
    request_id = current_request_id()
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


def safe_exception_fields(exc: BaseException) -> dict[str, str | int]:
    """Return diagnostic exception metadata without exposing its message."""
    fields: dict[str, str | int] = {"error_type": type(exc).__name__}
    error_code = getattr(exc, "errno", None)
    if isinstance(error_code, int):
        fields["error_code"] = error_code
    return fields


__all__ = [
    "current_operation",
    "current_request_id",
    "ensure_request_id",
    "log_context",
    "new_log_context",
    "new_request_id",
    "operation_context",
    "safe_exception_fields",
]
