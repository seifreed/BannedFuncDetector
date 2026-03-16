import logging

from bannedfuncdetector.application.analysis_outcome import BinaryAnalysisOutcome
from bannedfuncdetector.domain import AnalysisResult, BannedFunction
from bannedfuncdetector.presentation.reporting import display_final_results


def test_display_final_results_supports_current_analysis_contract(caplog):
    report = AnalysisResult(
        file_name="sample.bin",
        file_path="/tmp/sample.bin",
        total_functions=2,
        detected_functions=(
            BannedFunction(
                name="main",
                address=0x1000,
                size=0,
                banned_calls=("strcpy",),
                detection_method="decompilation",
            ),
        ),
        analysis_date="2026-03-11T00:00:00",
    )

    with caplog.at_level(logging.INFO):
        display_final_results(BinaryAnalysisOutcome(report=report))

    assert "Total files analyzed: 1" in caplog.text
    assert "Insecure functions found: 1" in caplog.text
    assert "main at 0x1000" in caplog.text
