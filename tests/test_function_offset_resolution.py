# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for function offset resolution in decompiler_support.

Covers two bugs the prior tests missed:
  * radare2's `sj` returns a *list* (seek history), so the dict-only fallback
    never resolved an offset when `afij` returned nothing.
  * `offset or addr` discarded a valid address of 0 via truthiness.
"""

from __future__ import annotations

from bannedfuncdetector.infrastructure.decompilers.decompiler_support import (
    _get_function_offset,
)


class _SeekListR2:
    """Fake r2 whose `sj` returns the seek history as a list (real r2 shape)."""

    def __init__(self, sj_value: object) -> None:
        self._sj = sj_value
        self.commands: list[str] = []

    def cmd(self, command: str) -> str:
        self.commands.append(command)
        return ""

    def cmdj(self, command: str) -> object:
        self.commands.append(command)
        return self._sj if command == "sj" else None


def test_offset_zero_is_preserved() -> None:
    """A function whose offset is 0 (base address 0x0) is not discarded."""
    r2 = _SeekListR2(None)
    assert _get_function_offset(r2, "main", {"offset": 0}) == 0


def test_addr_fallback_when_offset_missing() -> None:
    r2 = _SeekListR2(None)
    assert _get_function_offset(r2, "main", {"addr": 0x1000}) == 0x1000


def test_sj_list_current_entry_resolves_offset() -> None:
    """When afij gives nothing, the seek fallback reads the `current` entry."""
    sj = [
        {"offset": 0x400000, "name": "a"},
        {"offset": 0x401120, "name": "main", "current": True},
    ]
    r2 = _SeekListR2(sj)
    assert _get_function_offset(r2, "main", None) == 0x401120
    assert "s main" in r2.commands


def test_sj_list_without_current_uses_last_entry() -> None:
    sj = [{"offset": 0x1}, {"offset": 0x401120}]
    r2 = _SeekListR2(sj)
    assert _get_function_offset(r2, "main", None) == 0x401120


def test_sj_dict_passthrough_still_supported() -> None:
    r2 = _SeekListR2({"offset": 0x401120})
    assert _get_function_offset(r2, "main", None) == 0x401120


def test_sj_empty_list_returns_none() -> None:
    r2 = _SeekListR2([])
    assert _get_function_offset(r2, "main", None) is None


def test_unsafe_name_not_seeked_in_fallback() -> None:
    r2 = _SeekListR2([{"offset": 0x1, "current": True}])
    assert _get_function_offset(r2, "foo;!id", None) is None
    assert r2.commands == []


def test_boolean_offset_is_rejected() -> None:
    """A JSON `true` in the offset field must not be coerced to address 1."""
    r2 = _SeekListR2(None)
    assert _get_function_offset(r2, "main", {"offset": True, "addr": 0x2000}) == 0x2000
