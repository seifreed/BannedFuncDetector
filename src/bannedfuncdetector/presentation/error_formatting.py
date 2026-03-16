from __future__ import annotations


def format_execution_error(error: object) -> str:
    """Render application execution errors for user-facing surfaces.

    ExecutionFailure.__str__() already handles rendering notices,
    and ApplicationExecutionError.__str__() formats category/phase/context.
    """
    return str(error)


__all__ = ["format_execution_error"]
