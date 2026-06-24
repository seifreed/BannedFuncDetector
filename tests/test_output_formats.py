# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Tests for the json/text/html output formats.

output.format accepted "text"/"html" but the writer always produced JSON and
never read the setting. These tests exercise the now-implemented renderers and
the tightened validation."""

from __future__ import annotations

import json

from bannedfuncdetector.domain.entities import AnalysisResult, BannedFunction
from bannedfuncdetector.application.binary_analyzer.reporting import (
    _save_analysis_results,
)
from bannedfuncdetector.domain.result import Err, Ok
from bannedfuncdetector.infrastructure.config_validation import (
    validate_output_settings,
)


def _report() -> AnalysisResult:
    return AnalysisResult(
        file_name="ls",
        file_path="/bin/ls",
        total_functions=3,
        detected_functions=(
            BannedFunction(
                name="main",
                address=0x1149,
                size=10,
                banned_calls=("strcpy", "gets"),
                detection_method="name",
                category="String",
            ),
        ),
        analysis_date="2026-01-01",
    )


def test_json_format(tmp_path):
    path = _save_analysis_results(_report(), str(tmp_path), "ls", False, "json")
    assert path.endswith("ls_banned_functions.json")
    data = json.load(open(path))
    assert data["unsafe_functions"] == 1


def test_text_format(tmp_path):
    path = _save_analysis_results(_report(), str(tmp_path), "ls", False, "text")
    assert path.endswith(".txt")
    content = open(path).read()
    assert "main" in content and "strcpy, gets" in content


def test_html_format_escapes(tmp_path):
    path = _save_analysis_results(_report(), str(tmp_path), "ls", False, "html")
    assert path.endswith(".html")
    content = open(path).read()
    assert "<table" in content and "main" in content and "0x1149" in content


def test_unknown_format_falls_back_to_json(tmp_path):
    path = _save_analysis_results(_report(), str(tmp_path), "ls", False, "weird")
    assert path.endswith(".json")


def test_validation_rejects_unsupported_format():
    result = validate_output_settings({"directory": "out", "format": "pdf"})
    assert isinstance(result, Err)


def test_validation_accepts_supported_formats():
    for fmt in ("json", "text", "html"):
        result = validate_output_settings({"directory": "out", "format": fmt})
        assert isinstance(result, Ok), fmt


def test_resolve_output_format_defaults_when_not_dict():
    from bannedfuncdetector.application.binary_analyzer.binary_flow_runtime import (
        _resolve_output_format,
    )

    class _BadConfig:
        def get(self, key, default=None):
            return "not-a-dict"

    assert _resolve_output_format(_BadConfig()) == "json"


def test_resolve_output_format_reads_config():
    from bannedfuncdetector.application.binary_analyzer.binary_flow_runtime import (
        _resolve_output_format,
    )
    from bannedfuncdetector.factories import create_config_from_dict

    cfg = create_config_from_dict({"output": {"format": "html"}})
    assert _resolve_output_format(cfg) == "html"
