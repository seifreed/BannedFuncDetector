# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for directory result reporting and error normalization.

Three bugs the prior tests missed, all on the directory (multi-file) path:
  * the "Total files analyzed" line counted only files that produced a result,
    not every file found (failed binaries were dropped from the count);
  * normalize_directory_result discarded operational_notices from failures;
  * normalize_directory_result flattened every error category to
    "Analysis error", losing the original (I/O, Runtime, ...).
"""

from __future__ import annotations

import logging

from bannedfuncdetector.application.analysis_error import (
    BinaryExecutionError,
    ExecutionFailure,
)
from bannedfuncdetector.application.analysis_outcome import (
    AnalysisResult,
    DirectoryAnalysisOutcome,
    DirectoryAnalysisSummary,
    OperationalNotice,
)
from bannedfuncdetector.application.internal.directory_results import (
    normalize_directory_result,
)
from bannedfuncdetector.domain.result import Err, err, ok
from bannedfuncdetector.presentation.reporting import display_final_results


def _result(name: str) -> AnalysisResult:
    return AnalysisResult(
        file_name=name,
        file_path=f"/bin/{name}",
        total_functions=1,
        detected_functions=(),
        analysis_date="2026-01-01",
    )


def test_total_files_counts_every_file_found_not_just_analyzed(caplog) -> None:
    # 10 files found, only 3 produced a result (7 failed to open).
    summary = DirectoryAnalysisSummary(
        directory="/bin",
        analyzed_results=tuple(_result(f"f{i}") for i in range(3)),
        total_files=10,
    )
    outcome = DirectoryAnalysisOutcome(summary=summary)

    with caplog.at_level(logging.INFO):
        display_final_results(outcome)

    assert "Total files analyzed: 10" in caplog.text
    assert "Total files analyzed: 3" not in caplog.text


def test_normalize_preserves_category_phase_and_notices() -> None:
    notice = OperationalNotice(message="cleanup failed", file_path="/bin/x")
    failure = ExecutionFailure(
        error=BinaryExecutionError(
            category="I/O error",
            context="/bin/x",
            message="cannot read binary",
            phase="open",
        ),
        operational_notices=(notice,),
    )

    normalized = normalize_directory_result("/bin/x", err(failure))

    assert isinstance(normalized, Err)
    new_failure = normalized.error
    assert new_failure.error.category == "I/O error"   # not flattened
    assert new_failure.error.phase == "open"
    assert new_failure.error.message == "cannot read binary"
    assert new_failure.operational_notices == (notice,)  # not dropped


def test_normalize_passes_through_ok() -> None:
    outcome = DirectoryAnalysisOutcome(
        summary=DirectoryAnalysisSummary(
            directory="/bin", analyzed_results=(), total_files=0
        )
    )
    # Ok values are returned unchanged.
    assert normalize_directory_result("/bin/x", ok(outcome)) == ok(outcome)
