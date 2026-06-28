# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""The r2 analysis-time budget is read from config["analysis"]["timeout"].

Previously the value was validated and stored but never applied; r2's
anal.timeout was hardcoded. These tests pin the wiring so the knob keeps
working and degrades to the built-in default when the config is malformed.
"""

from __future__ import annotations

from bannedfuncdetector.constants import DECOMPILER_TIMEOUT
from bannedfuncdetector.runtime_factories import (
    _default_binary_opener,
    _resolve_anal_timeout,
    create_config_from_dict,
)


class _RecordingR2:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def cmd(self, command: str) -> str:
        self.commands.append(command)
        return ""

    def quit(self) -> None:  # pragma: no cover - not exercised here
        pass


def test_resolve_reads_configured_timeout() -> None:
    config = create_config_from_dict({"analysis": {"timeout": 600}})
    assert _resolve_anal_timeout(config) == 600


def test_resolve_default_config_is_600() -> None:
    # The shipped default for analysis.timeout is 600.
    assert _resolve_anal_timeout(create_config_from_dict({})) == 600


def test_resolve_falls_back_on_invalid_timeout() -> None:
    # A non-positive value is rejected by validation, so build the config object
    # directly to exercise the resolver's own defensive guard.
    class _Cfg:
        def __init__(self, analysis: object) -> None:
            self._analysis = analysis

        def get(self, key: str, default: object = None) -> object:
            return self._analysis if key == "analysis" else default

    assert _resolve_anal_timeout(_Cfg({"timeout": -5})) == DECOMPILER_TIMEOUT
    assert _resolve_anal_timeout(_Cfg({"timeout": True})) == DECOMPILER_TIMEOUT
    assert _resolve_anal_timeout(_Cfg({"timeout": "nope"})) == DECOMPILER_TIMEOUT
    assert _resolve_anal_timeout(_Cfg({})) == DECOMPILER_TIMEOUT
    assert _resolve_anal_timeout(_Cfg("not-a-dict")) == DECOMPILER_TIMEOUT


def test_resolve_accepts_float_timeout() -> None:
    class _Cfg:
        def get(self, key: str, default: object = None) -> object:
            return {"timeout": 45.0} if key == "analysis" else default

    assert _resolve_anal_timeout(_Cfg()) == 45


def test_default_opener_forwards_timeout() -> None:
    r2 = _RecordingR2()
    _default_binary_opener("/tmp/x", False, lambda _p: r2, anal_timeout=600)
    assert "e anal.timeout=600" in r2.commands


def test_default_opener_uses_builtin_default_when_unbound() -> None:
    r2 = _RecordingR2()
    _default_binary_opener("/tmp/x", False, lambda _p: r2)
    assert f"e anal.timeout={DECOMPILER_TIMEOUT}" in r2.commands
