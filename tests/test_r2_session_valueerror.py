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
