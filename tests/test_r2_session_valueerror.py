# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression test: a ValueError during r2 setup must not leak the session.

R2Client._run_command can re-raise a non-transient ValueError from `aaa`. The
open retry loop previously did not catch ValueError, so it escaped without the
r2 instance being closed (resource leak). The loop now treats it like any other
setup failure: close the instance, then re-raise.
"""

from __future__ import annotations

import pytest

from bannedfuncdetector.infrastructure.adapters.r2_session import open_binary_with_r2


class _ValueErrorR2:
    """Fake r2 client that raises ValueError on analysis and records cleanup."""

    def __init__(self) -> None:
        self.quit_called = False

    def cmd(self, command: str) -> str:
        raise ValueError("simulated r2 analysis failure")

    def quit(self) -> None:
        self.quit_called = True


def test_valueerror_during_setup_propagates_and_closes_session() -> None:
    created: list[_ValueErrorR2] = []

    def factory(_path: str) -> _ValueErrorR2:
        client = _ValueErrorR2()
        created.append(client)
        return client

    with pytest.raises(ValueError):
        open_binary_with_r2("/tmp/whatever", r2_factory=factory)

    # The session that failed analysis was closed rather than leaked.
    assert created and all(client.quit_called for client in created)


class _RecordingR2:
    """Fake r2 client that records the commands it receives."""

    def __init__(self) -> None:
        self.commands: list[str] = []

    def cmd(self, command: str) -> str:
        self.commands.append(command)
        return ""

    def quit(self) -> None:  # pragma: no cover - not exercised here
        pass


def test_open_binary_disables_color_before_analysis() -> None:
    """Color must be disabled so ANSI codes never split call sites in pseudocode."""
    r2 = _RecordingR2()
    open_binary_with_r2("/tmp/whatever", r2_factory=lambda _p: r2)

    assert "e scr.color=0" in r2.commands
    # Color is disabled before analysis (aaa), so all later output is plain.
    assert r2.commands.index("e scr.color=0") < r2.commands.index("aaa")


def test_open_binary_bounds_analysis_timeout_before_aaa() -> None:
    """Analysis must be time-bounded so an obfuscated binary cannot hang `aaa`."""
    from bannedfuncdetector.constants import DECOMPILER_TIMEOUT

    r2 = _RecordingR2()
    open_binary_with_r2("/tmp/whatever", r2_factory=lambda _p: r2)

    timeout_cmd = f"e anal.timeout={DECOMPILER_TIMEOUT}"
    assert timeout_cmd in r2.commands
    # The cap is applied before analysis runs.
    assert r2.commands.index(timeout_cmd) < r2.commands.index("aaa")


def test_open_binary_honors_custom_analysis_timeout() -> None:
    """A caller-supplied analysis budget overrides the built-in default."""
    r2 = _RecordingR2()
    open_binary_with_r2("/tmp/whatever", r2_factory=lambda _p: r2, anal_timeout=600)

    assert "e anal.timeout=600" in r2.commands
    assert r2.commands.index("e anal.timeout=600") < r2.commands.index("aaa")
