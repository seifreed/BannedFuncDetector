# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression: r2ai-server must be rejected as a decompiler type, not silently
downgraded to 'default'. It is not wired into the decompilation flow, so
accepting it as a type hid a real configuration error."""

from __future__ import annotations

from bannedfuncdetector.domain.result import Err, Ok
from bannedfuncdetector.infrastructure.config_validation import (
    VALID_DECOMPILER_TYPES,
    validate_decompiler_settings,
)


def test_r2ai_server_is_not_a_valid_decompiler_type() -> None:
    assert "r2ai-server" not in VALID_DECOMPILER_TYPES

    result = validate_decompiler_settings({"type": "r2ai-server", "options": {}})

    assert isinstance(result, Err)
    assert "r2ai-server" in result.error


def test_supported_decompiler_types_still_validate() -> None:
    for decompiler_type in ("default", "r2ghidra", "r2dec", "decai"):
        result = validate_decompiler_settings(
            {"type": decompiler_type, "options": {}}
        )
        assert isinstance(result, Ok), decompiler_type
