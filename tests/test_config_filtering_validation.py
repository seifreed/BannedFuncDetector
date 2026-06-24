# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression: a non-int small_function_threshold must be rejected at config
validation, not crash mid-analysis. is_small_function compares the threshold
with integer function sizes, so a string threshold raised
`'<' not supported between 'int' and 'str'` during real analysis."""

from __future__ import annotations

import pytest

from bannedfuncdetector.domain.result import Err, Ok
from bannedfuncdetector.infrastructure.config_validation import (
    validate_function_filtering,
)
from bannedfuncdetector.factories import create_config_from_dict


def _full(**overrides):
    base = {
        "decompiler": {"type": "default", "options": {}},
        "output": {"directory": "out"},
        "analysis": {},
    }
    base.update(overrides)
    return base


def test_string_threshold_is_rejected() -> None:
    result = validate_function_filtering(_full(small_function_threshold="ten"))
    assert isinstance(result, Err)
    assert "small_function_threshold" in result.error


def test_negative_threshold_is_rejected() -> None:
    result = validate_function_filtering(_full(small_function_threshold=-1))
    assert isinstance(result, Err)


def test_bool_threshold_is_rejected() -> None:
    result = validate_function_filtering(_full(small_function_threshold=True))
    assert isinstance(result, Err)


def test_non_bool_skip_is_rejected() -> None:
    result = validate_function_filtering(_full(skip_small_functions="yes"))
    assert isinstance(result, Err)
    assert "skip_small_functions" in result.error


def test_valid_filtering_settings_pass() -> None:
    result = validate_function_filtering(
        _full(small_function_threshold=10, skip_small_functions=False)
    )
    assert isinstance(result, Ok)


def test_create_config_from_dict_rejects_bad_threshold() -> None:
    with pytest.raises(ValueError, match="small_function_threshold"):
        create_config_from_dict({"small_function_threshold": "ten"})
