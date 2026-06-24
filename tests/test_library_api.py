# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Tests for the public convenience library API documented in the README.

`from bannedfuncdetector.bannedfunc import analyze_file, analyze_directory`
must work with simple keyword arguments — previously the README documented
these but only the low-level request-object API existed (ImportError /
TypeError for the documented calls)."""

from __future__ import annotations

import os

from bannedfuncdetector.bannedfunc import analyze_file, analyze_directory
from bannedfuncdetector.domain.result import Ok, Err


def test_analyze_file_returns_ok_outcome(compiled_binary, tmp_path):
    result = analyze_file(
        str(compiled_binary),
        decompiler_type="default",
        output_dir=str(tmp_path / "out"),
        skip_analysis=True,
    )
    assert isinstance(result, Ok)
    outcome = result.unwrap()
    assert outcome.report.file_name == os.path.basename(str(compiled_binary))


def test_analyze_file_missing_returns_err(tmp_path):
    result = analyze_file(
        str(tmp_path / "nope.bin"), output_dir=str(tmp_path / "out")
    )
    assert isinstance(result, Err)


def test_analyze_directory_returns_ok_summary(compiled_binary, tmp_path):
    bins = tmp_path / "bins"
    bins.mkdir()
    os.link(compiled_binary, bins / "sample.bin")

    result = analyze_directory(
        str(bins),
        output_dir=str(tmp_path / "out"),
        skip_analysis=True,
    )
    assert isinstance(result, Ok)
    assert result.unwrap().summary.total_files == 1


def test_analyze_directory_empty_returns_err(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    result = analyze_directory(str(empty), output_dir=str(tmp_path / "out"))
    assert isinstance(result, Err)
