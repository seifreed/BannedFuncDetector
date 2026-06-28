# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Directory parallelism reads its worker count from analysis.max_workers.

The top-level ``max_workers`` duplicate was removed; ``analysis.max_workers``
is now the single source, falling back to DEFAULT_MAX_WORKERS when absent.
"""

from __future__ import annotations

from bannedfuncdetector.application.internal.directory_execution import (
    _config_max_workers,
)
from bannedfuncdetector.constants import DEFAULT_MAX_WORKERS
from bannedfuncdetector.factories import create_config_from_dict


def test_reads_analysis_max_workers() -> None:
    config = create_config_from_dict({"analysis": {"max_workers": 7}})
    assert _config_max_workers(config) == 7


def test_empty_config_uses_model_default() -> None:
    # An empty dict merges onto DEFAULT_CONFIG, whose analysis.max_workers is
    # the model default (config.json's value only applies when loaded from file).
    config = create_config_from_dict({})
    assert _config_max_workers(config) == DEFAULT_MAX_WORKERS


class _Cfg:
    def __init__(self, analysis: object) -> None:
        self._analysis = analysis

    def get(self, key: str, default: object = None) -> object:
        return self._analysis if key == "analysis" else default


def test_falls_back_when_section_missing_or_invalid() -> None:
    assert _config_max_workers(_Cfg("not-a-dict")) == DEFAULT_MAX_WORKERS
    assert _config_max_workers(_Cfg({})) == DEFAULT_MAX_WORKERS
    assert _config_max_workers(_Cfg({"max_workers": 0})) == DEFAULT_MAX_WORKERS
    assert _config_max_workers(_Cfg({"max_workers": True})) == DEFAULT_MAX_WORKERS
    assert _config_max_workers(_Cfg({"max_workers": "lots"})) == DEFAULT_MAX_WORKERS
