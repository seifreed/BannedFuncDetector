# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression: is_valid_result must accept valid code that references error
handling, and reject only actual decompiler/AI failure messages. Previously a
bare "error" substring check discarded any function calling strerror /
GetLastError / using a `goto error;` label, forcing decai to fall back."""

from __future__ import annotations

import pytest

from bannedfuncdetector.infrastructure.decompilers.decompiler_support import (
    is_valid_result,
)

VALID_CODE_WITH_ERROR_WORDS = [
    "int handle_error(int code) { char *error_msg = strerror(code); return code; }",
    "void f() { int err = GetLastError(); if (err) goto error; error: return; }",
    "int g(void) { return error_code == 0 ? 1 : 0; /* check error state */ }",
]

FAILURE_MESSAGES = [
    "ERROR: cannot decompile function at 0x1000",
    "Cannot decompile: no function found here at all really",
    "Unknown command 'pdg'. Try the help with '?' for more info",
    "RCmd.Use() the decai plugin is not available in this build",
]


@pytest.mark.parametrize("code", VALID_CODE_WITH_ERROR_WORDS)
def test_valid_code_with_error_identifiers_is_accepted(code: str) -> None:
    assert is_valid_result(code) is True


@pytest.mark.parametrize("code", FAILURE_MESSAGES)
def test_failure_messages_are_rejected(code: str) -> None:
    assert is_valid_result(code) is False


def test_empty_and_short_are_invalid() -> None:
    assert is_valid_result(None) is False
    assert is_valid_result("") is False
    assert is_valid_result("int x;") is False
