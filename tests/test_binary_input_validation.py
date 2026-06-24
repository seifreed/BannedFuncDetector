# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression: a non-regular file (FIFO/socket/device) must be rejected before
radare2 opens it. _validate_binary_input only checked os.path.exists, so a FIFO
(which "exists" but blocks forever on open/read) hung the whole single-file
analysis. It now requires a regular file."""

from __future__ import annotations

import os

import pytest

from bannedfuncdetector.analyzer_exceptions import BinaryNotFoundError
from bannedfuncdetector.application.binary_analyzer.runtime import (
    _validate_binary_input,
)


def test_fifo_is_rejected_not_opened(tmp_path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)

    with pytest.raises(BinaryNotFoundError, match="not a regular file"):
        _validate_binary_input(str(fifo))


def test_directory_is_rejected() -> None:
    with pytest.raises(BinaryNotFoundError, match="not a regular file"):
        _validate_binary_input(os.path.dirname(__file__))


def test_missing_path_still_rejected() -> None:
    with pytest.raises(BinaryNotFoundError, match="does not exist"):
        _validate_binary_input("/no/such/path/at/all")


def test_regular_file_accepted(tmp_path) -> None:
    f = tmp_path / "real.bin"
    f.write_bytes(b"\x7fELF")
    _validate_binary_input(str(f))  # must not raise
