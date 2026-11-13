# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression: requirement-check subprocesses must time out instead of hanging.

_run_command_async used process.communicate() with no deadline, so a hung
requirement command (e.g. `r2 -v` blocked on I/O) would freeze the CLI during
--check-requirements. It now enforces a timeout and reports a failed command.
"""

from __future__ import annotations

import asyncio

from bannedfuncdetector.infrastructure.validators import _run_command_async


def test_hung_command_times_out_with_failed_result(caplog) -> None:
    # `sleep 5` resolves via PATH and blocks well past the tiny timeout.
    caplog.set_level("ERROR", logger="bannedfuncdetector.infrastructure.validators")
    result = asyncio.run(_run_command_async(["sleep", "5"], timeout=0.3))

    assert result.returncode == 1
    assert result.stderr == "timeout"
    event = next(record for record in caplog.records if record.event_name == "requirement_command_timeout")
    assert event.operation == "requirement_check"
    assert event.outcome == "timeout"
    assert event.error_type == "TimeoutError"
    assert event.duration_ms == 300
    assert "['sleep', '5']" not in caplog.text


def test_fast_command_completes_normally() -> None:
    result = asyncio.run(_run_command_async(["true"], timeout=10))

    assert result.returncode == 0
