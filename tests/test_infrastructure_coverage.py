#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Tests for 100% coverage of:
  - bannedfuncdetector.infrastructure.config_validation
  - bannedfuncdetector.infrastructure.config_storage
  - bannedfuncdetector.infrastructure.error_handling
  - bannedfuncdetector.infrastructure.adapters.dtos

All tests use real function calls, real data structures, and real file I/O.
No mocks, no monkeypatch, no unittest.mock, no @patch, no pragma comments.
"""

import json
import logging
import sys

import pytest

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from bannedfuncdetector.infrastructure.config_validation import (
    VALID_DECOMPILER_TYPES,
    VALID_OUTPUT_FORMATS,
    validate_banned_functions,
    validate_config,
    validate_decompiler_settings,
    validate_full_config,
    validate_output_settings,
    validate_analysis_settings,
)
from bannedfuncdetector.infrastructure.config_storage import (
    ImmutableConfig,
    deep_merge,
    load_config,
    load_config_from_file,
)
from bannedfuncdetector.infrastructure.error_handling import (
    EXCEPTION_GROUPS,
    handle_errors,
    handle_errors_sync,
)
from bannedfuncdetector.infrastructure.adapters.dtos import (
    DetectionResultDTO,
    FunctionInfoDTO,
)
from bannedfuncdetector.domain.result import Ok, Err, ok
from bannedfuncdetector.domain.error_types import ErrorCategory
from bannedfuncdetector.analyzer_exceptions import AnalysisError

# ===========================================================================
# Helpers — minimal valid config dict that passes validate_full_config
# ===========================================================================


def _minimal_valid_config() -> dict:
    """Return the smallest dict that passes validate_full_config."""
    return {
        "decompiler": {"type": "default", "options": {}},
        "output": {"directory": "/tmp/output"},
        "analysis": {},
    }


# ===========================================================================
# config_validation — validate_banned_functions
# ===========================================================================


class TestValidateBannedFunctions:
    """Validate banned-function list entries."""

    def test_empty_list_returns_ok_with_empty_result(self):
        result = validate_banned_functions([])
        assert isinstance(result, Ok)
        assert result.value == []

    def test_list_of_strings_returns_all_names(self):
        functions = ["strcpy", "gets", "sprintf"]
        result = validate_banned_functions(functions)
        assert isinstance(result, Ok)
        assert result.value == functions

    def test_list_of_dicts_with_name_key_returns_names(self):
        functions = [{"name": "strcpy"}, {"name": "gets"}]
        result = validate_banned_functions(functions)
        assert isinstance(result, Ok)
        assert result.value == ["strcpy", "gets"]

    def test_mixed_strings_and_dicts_returns_names_in_order(self):
        functions = ["strcpy", {"name": "gets"}, "sprintf"]
        result = validate_banned_functions(functions)
        assert isinstance(result, Ok)
        assert result.value == ["strcpy", "gets", "sprintf"]

    def test_not_a_list_returns_err(self):
        result = validate_banned_functions("strcpy")
        assert isinstance(result, Err)
        assert "list" in result.error.lower()

    def test_dict_without_name_key_returns_err(self):
        result = validate_banned_functions([{"function": "strcpy"}])
        assert isinstance(result, Err)
        assert "Invalid banned function entry" in result.error

    def test_integer_entry_returns_err(self):
        result = validate_banned_functions([42])
        assert isinstance(result, Err)
        assert "Invalid banned function entry" in result.error

    def test_none_as_input_returns_err(self):
        result = validate_banned_functions(None)
        assert isinstance(result, Err)

    def test_dict_input_returns_err(self):
        result = validate_banned_functions({"strcpy": True})
        assert isinstance(result, Err)


# ===========================================================================
# config_validation — validate_decompiler_settings
# ===========================================================================


class TestValidateDecompilerSettings:
    """Validate decompiler section of configuration."""

    def test_valid_default_type_returns_ok(self):
        settings = {"type": "default", "options": {}}
        result = validate_decompiler_settings(settings)
        assert isinstance(result, Ok)
        assert result.value == settings

    def test_every_valid_decompiler_type_passes(self):
        for dtype in VALID_DECOMPILER_TYPES:
            settings = {"type": dtype, "options": {}}
            result = validate_decompiler_settings(settings)
            assert isinstance(result, Ok), f"Expected Ok for type '{dtype}'"

    def test_non_dict_input_returns_err(self):
        result = validate_decompiler_settings("default")
        assert isinstance(result, Err)
        assert "dictionary" in result.error.lower()

    def test_missing_type_field_returns_err(self):
        result = validate_decompiler_settings({"options": {}})
        assert isinstance(result, Err)
        assert "'type'" in result.error

    def test_invalid_type_value_returns_err(self):
        result = validate_decompiler_settings({"type": "unknown_tool", "options": {}})
        assert isinstance(result, Err)
        assert "Invalid decompiler type" in result.error

    def test_missing_options_returns_err(self):
        result = validate_decompiler_settings({"type": "default"})
        assert isinstance(result, Err)
        assert "'options'" in result.error

    def test_options_not_dict_returns_err(self):
        result = validate_decompiler_settings({"type": "default", "options": "none"})
        assert isinstance(result, Err)
        assert "'options'" in result.error

    def test_options_with_nested_content_passes(self):
        settings = {"type": "r2ghidra", "options": {"enabled": True, "command": "pdg"}}
        result = validate_decompiler_settings(settings)
        assert isinstance(result, Ok)


# ===========================================================================
# config_validation — validate_output_settings
# ===========================================================================


class TestValidateOutputSettings:
    """Validate output section of configuration."""

    def test_valid_settings_with_directory_passes(self):
        settings = {"directory": "/tmp/output"}
        result = validate_output_settings(settings)
        assert isinstance(result, Ok)
        assert result.value == settings

    def test_non_dict_input_returns_err(self):
        result = validate_output_settings("/tmp/output")
        assert isinstance(result, Err)
        assert "dictionary" in result.error.lower()

    def test_missing_directory_returns_err(self):
        result = validate_output_settings({"format": "json"})
        assert isinstance(result, Err)
        assert "'directory'" in result.error

    def test_valid_format_values_pass_without_warning(self, caplog):
        for fmt in VALID_OUTPUT_FORMATS:
            settings = {"directory": "/tmp/out", "format": fmt}
            result = validate_output_settings(settings)
            assert isinstance(result, Ok)

    def test_invalid_format_still_returns_ok_but_logs_warning(self, caplog):
        settings = {"directory": "/tmp/out", "format": "xml"}
        with caplog.at_level(
            logging.WARNING,
            logger="bannedfuncdetector.infrastructure.config_validation",
        ):
            result = validate_output_settings(settings)
        assert isinstance(result, Ok)
        assert any("xml" in record.message for record in caplog.records)

    def test_no_format_key_returns_ok(self):
        settings = {"directory": "/tmp/out", "verbose": True}
        result = validate_output_settings(settings)
        assert isinstance(result, Ok)


# ===========================================================================
# config_validation — validate_analysis_settings
# ===========================================================================


class TestValidateAnalysisSettings:
    """Validate analysis section of configuration."""

    def test_empty_dict_passes(self):
        result = validate_analysis_settings({})
        assert isinstance(result, Ok)

    def test_valid_max_workers_passes(self):
        result = validate_analysis_settings({"max_workers": 4})
        assert isinstance(result, Ok)

    def test_zero_max_workers_returns_err(self):
        result = validate_analysis_settings({"max_workers": 0})
        assert isinstance(result, Err)
        assert "max_workers" in result.error

    def test_negative_max_workers_returns_err(self):
        result = validate_analysis_settings({"max_workers": -1})
        assert isinstance(result, Err)

    def test_non_integer_max_workers_returns_err(self):
        result = validate_analysis_settings({"max_workers": "four"})
        assert isinstance(result, Err)

    def test_valid_timeout_int_passes(self):
        result = validate_analysis_settings({"timeout": 600})
        assert isinstance(result, Ok)

    def test_valid_timeout_float_passes(self):
        result = validate_analysis_settings({"timeout": 30.5})
        assert isinstance(result, Ok)

    def test_zero_timeout_returns_err(self):
        result = validate_analysis_settings({"timeout": 0})
        assert isinstance(result, Err)
        assert "timeout" in result.error

    def test_negative_timeout_returns_err(self):
        result = validate_analysis_settings({"timeout": -10})
        assert isinstance(result, Err)

    def test_string_timeout_returns_err(self):
        result = validate_analysis_settings({"timeout": "fast"})
        assert isinstance(result, Err)

    def test_bool_parallel_true_passes(self):
        result = validate_analysis_settings({"parallel": True})
        assert isinstance(result, Ok)

    def test_bool_parallel_false_passes(self):
        result = validate_analysis_settings({"parallel": False})
        assert isinstance(result, Ok)

    def test_non_bool_parallel_returns_err(self):
        result = validate_analysis_settings({"parallel": 1})
        assert isinstance(result, Err)
        assert "parallel" in result.error

    def test_non_dict_input_returns_err(self):
        result = validate_analysis_settings("parallel")
        assert isinstance(result, Err)
        assert "dictionary" in result.error.lower()

    def test_all_valid_fields_together_pass(self):
        result = validate_analysis_settings(
            {"max_workers": 8, "timeout": 120, "parallel": True}
        )
        assert isinstance(result, Ok)


# ===========================================================================
# config_validation — validate_full_config
# ===========================================================================


class TestValidateFullConfig:
    """End-to-end full-config validation."""

    def test_minimal_valid_config_passes(self):
        config = _minimal_valid_config()
        result = validate_full_config(config)
        assert isinstance(result, Ok)

    def test_missing_top_level_key_returns_err(self):
        config = {"decompiler": {"type": "default", "options": {}}}
        result = validate_full_config(config)
        assert isinstance(result, Err)
        assert "required" in result.error.lower()

    def test_invalid_decompiler_section_returns_err(self):
        config = _minimal_valid_config()
        config["decompiler"] = {"type": "invalid_tool", "options": {}}
        result = validate_full_config(config)
        assert isinstance(result, Err)
        assert "Decompiler" in result.error

    def test_invalid_output_section_returns_err(self):
        config = _minimal_valid_config()
        config["output"] = {}  # missing 'directory'
        result = validate_full_config(config)
        assert isinstance(result, Err)
        assert "Output" in result.error

    def test_invalid_analysis_section_returns_err(self):
        config = _minimal_valid_config()
        config["analysis"] = {"max_workers": -5}
        result = validate_full_config(config)
        assert isinstance(result, Err)
        assert "Analysis" in result.error

    def test_full_config_with_all_analysis_fields_passes(self):
        config = _minimal_valid_config()
        config["analysis"] = {"max_workers": 4, "timeout": 300, "parallel": True}
        result = validate_full_config(config)
        assert isinstance(result, Ok)


# ===========================================================================
# config_validation — validate_config (the simple key-presence check)
# ===========================================================================


class TestValidateConfig:
    """Tests for the top-level key-presence guard."""

    def test_all_required_keys_present_returns_true(self):
        config = {"decompiler": {}, "output": {}, "analysis": {}}
        assert validate_config(config) is True

    def test_missing_one_key_returns_false(self, caplog):
        config = {"decompiler": {}, "output": {}}
        with caplog.at_level(
            logging.WARNING,
            logger="bannedfuncdetector.infrastructure.config_validation",
        ):
            result = validate_config(config)
        assert result is False
        assert any("analysis" in record.message for record in caplog.records)

    def test_empty_dict_returns_false(self):
        assert validate_config({}) is False


# ===========================================================================
# config_storage — deep_merge
# ===========================================================================


class TestDeepMerge:
    """Tests for recursive dictionary merging."""

    def test_non_overlapping_keys_are_combined(self):
        base = {"a": 1}
        override = {"b": 2}
        merged = deep_merge(base, override)
        assert merged == {"a": 1, "b": 2}

    def test_scalar_override_replaces_base_value(self):
        base = {"x": 1}
        override = {"x": 99}
        merged = deep_merge(base, override)
        assert merged["x"] == 99

    def test_nested_dicts_are_merged_recursively(self):
        base = {"nested": {"a": 1, "b": 2}}
        override = {"nested": {"b": 20, "c": 3}}
        merged = deep_merge(base, override)
        assert merged["nested"] == {"a": 1, "b": 20, "c": 3}

    def test_base_dict_is_not_mutated(self):
        base = {"a": {"x": 1}}
        override = {"a": {"y": 2}}
        original_base = {"a": {"x": 1}}
        deep_merge(base, override)
        assert base == original_base

    def test_override_dict_is_not_mutated(self):
        base = {"a": 1}
        override = {"b": {"nested": True}}
        original_override = {"b": {"nested": True}}
        deep_merge(base, override)
        assert override == original_override

    def test_override_with_empty_dict_returns_copy_of_base(self):
        base = {"a": 1, "b": {"x": 10}}
        merged = deep_merge(base, {})
        assert merged == base
        assert merged is not base

    def test_base_empty_override_becomes_result(self):
        override = {"new": "value"}
        merged = deep_merge({}, override)
        assert merged == override

    def test_three_level_nested_merge(self):
        base = {"l1": {"l2": {"l3": "original"}}}
        override = {"l1": {"l2": {"l3": "updated", "l3_extra": True}}}
        merged = deep_merge(base, override)
        assert merged["l1"]["l2"]["l3"] == "updated"
        assert merged["l1"]["l2"]["l3_extra"] is True

    def test_non_dict_override_replaces_dict_base_value(self):
        base = {"key": {"nested": True}}
        override = {"key": "scalar"}
        merged = deep_merge(base, override)
        assert merged["key"] == "scalar"


# ===========================================================================
# config_storage — load_config_from_file
# ===========================================================================


class TestLoadConfigFromFile:
    """Tests for load_config_from_file (file read + JSON parse, no merging)."""

    def test_missing_file_returns_none(self, tmp_path):
        missing = tmp_path / "missing.json"
        result = load_config_from_file(str(missing))
        assert result is None

    def test_valid_json_returns_dict(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({"a": 1, "b": 2}))
        result = load_config_from_file(str(cfg_path))
        assert result == {"a": 1, "b": 2}

    def test_invalid_json_returns_none(self, tmp_path):
        cfg_path = tmp_path / "bad.json"
        cfg_path.write_text("{ invalid json")
        result = load_config_from_file(str(cfg_path))
        assert result is None

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Windows file permissions work differently",
    )
    def test_returns_none_when_file_exists_but_is_unreadable(self, tmp_path):
        # Create a file that exists on disk but has no read permission,
        # triggering the OSError branch (lines 32-34).
        import os

        cfg_path = tmp_path / "no_read.json"
        cfg_path.write_text(json.dumps({"x": 1}))
        original_mode = cfg_path.stat().st_mode
        try:
            os.chmod(str(cfg_path), 0o000)
            result = load_config_from_file(str(cfg_path))
            assert result is None
        finally:
            # Restore permissions so tmp_path cleanup succeeds.
            os.chmod(str(cfg_path), original_mode)


# ===========================================================================
# config_storage — load_config  (the merging + validation wrapper)
# ===========================================================================


class TestLoadConfig:
    """Tests for the full load_config path including merging and validation."""

    def test_returns_default_config_when_file_missing(self, tmp_path):
        missing = tmp_path / "missing.json"
        result = load_config(str(missing))
        assert isinstance(result, dict)
        assert "decompiler" in result
        assert "output" in result
        assert "analysis" in result

    def test_valid_user_config_is_merged_with_defaults(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        user_config = {
            "decompiler": {"type": "r2ghidra", "options": {}},
            "output": {"directory": "/custom/output"},
            "analysis": {"max_workers": 2},
        }
        cfg_path.write_text(json.dumps(user_config))
        result = load_config(str(cfg_path))
        assert result["decompiler"]["type"] == "r2ghidra"
        assert result["output"]["directory"] == "/custom/output"
        assert result["analysis"]["max_workers"] == 2

    def test_partial_config_missing_required_keys_still_merges_with_defaults(
        self, tmp_path
    ):
        # Only has 'decompiler', missing 'output' and 'analysis'
        cfg_path = tmp_path / "config.json"
        user_config = {
            "decompiler": {"type": "default", "options": {}},
            "extra_key": "extra_val",
        }
        cfg_path.write_text(json.dumps(user_config))
        result = load_config(str(cfg_path))
        # Should still return a valid merged result (defaults fill the gaps)
        assert isinstance(result, dict)
        assert "decompiler" in result

    def test_returns_defaults_when_json_is_invalid(self, tmp_path):
        cfg_path = tmp_path / "bad.json"
        cfg_path.write_text("{not valid json}")
        result = load_config(str(cfg_path))
        assert isinstance(result, dict)
        assert "decompiler" in result

    def test_returns_defaults_when_decompiler_key_is_not_dict(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        bad_config = {
            "decompiler": "not_a_dict",
            "output": {"directory": "/tmp"},
            "analysis": {},
        }
        cfg_path.write_text(json.dumps(bad_config))
        result = load_config(str(cfg_path))
        # Rejected because 'decompiler' must be a dict; returns defaults
        assert isinstance(result, dict)
        assert isinstance(result["decompiler"], dict)

    def test_returns_defaults_when_output_key_is_not_dict(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        bad_config = {
            "decompiler": {"type": "default", "options": {}},
            "output": "string_not_dict",
            "analysis": {},
        }
        cfg_path.write_text(json.dumps(bad_config))
        result = load_config(str(cfg_path))
        assert isinstance(result["output"], dict)

    def test_returns_defaults_when_analysis_key_is_not_dict(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        bad_config = {
            "decompiler": {"type": "default", "options": {}},
            "output": {"directory": "/tmp"},
            "analysis": 42,
        }
        cfg_path.write_text(json.dumps(bad_config))
        result = load_config(str(cfg_path))
        assert isinstance(result["analysis"], dict)

    def test_returns_defaults_when_merged_config_fails_full_validation(self, tmp_path):
        # Provide a config that passes the type-check guard but fails validate_full_config
        # — give an invalid decompiler type so the merged config is rejected
        cfg_path = tmp_path / "config.json"
        bad_config = {
            "decompiler": {"type": "invalid_decompiler", "options": {}},
            "output": {"directory": "/tmp"},
            "analysis": {},
        }
        cfg_path.write_text(json.dumps(bad_config))
        result = load_config(str(cfg_path))
        # validate_full_config rejects it → falls back to DEFAULT_CONFIG
        assert isinstance(result, dict)
        assert "decompiler" in result

    def test_deep_nested_user_values_override_defaults(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        user_config = {
            "decompiler": {
                "type": "default",
                "options": {
                    "default": {"enabled": False},
                },
            },
            "output": {"directory": "out"},
            "analysis": {},
        }
        cfg_path.write_text(json.dumps(user_config))
        result = load_config(str(cfg_path))
        assert result["decompiler"]["options"]["default"]["enabled"] is False


# ===========================================================================
# config_storage — ImmutableConfig
# ===========================================================================


class TestImmutableConfig:
    """Tests for the snapshot-based immutable config wrapper."""

    def test_default_construction_uses_default_config(self):
        cfg = ImmutableConfig()
        assert "decompiler" in cfg
        assert "output" in cfg

    def test_explicit_dict_is_stored_independently(self):
        data = {
            "decompiler": {"type": "r2dec", "options": {}},
            "output": {"directory": "out"},
            "analysis": {},
        }
        cfg = ImmutableConfig(data)
        assert cfg.get("decompiler")["type"] == "r2dec"

    def test_get_returns_deep_copy_for_dicts(self):
        data = {"nested": {"a": 1}}
        cfg = ImmutableConfig(data)
        copy1 = cfg.get("nested")
        copy1["a"] = 999
        assert cfg.get("nested")["a"] == 1

    def test_get_returns_default_when_key_missing(self):
        cfg = ImmutableConfig({"x": 1})
        assert cfg.get("missing_key", "fallback") == "fallback"

    def test_getitem_returns_value(self):
        cfg = ImmutableConfig({"score": 42})
        assert cfg["score"] == 42

    def test_getitem_returns_deep_copy_for_list(self):
        cfg = ImmutableConfig({"items": [1, 2, 3]})
        items = cfg["items"]
        items.append(99)
        assert cfg["items"] == [1, 2, 3]

    def test_contains_returns_true_for_existing_key(self):
        cfg = ImmutableConfig({"flag": True})
        assert "flag" in cfg

    def test_contains_returns_false_for_missing_key(self):
        cfg = ImmutableConfig({"flag": True})
        assert "missing" not in cfg

    def test_keys_returns_config_keys(self):
        cfg = ImmutableConfig({"a": 1, "b": 2})
        assert set(cfg.keys()) == {"a", "b"}

    def test_items_returns_all_key_value_pairs(self):
        cfg = ImmutableConfig({"x": 10, "y": 20})
        items = dict(cfg.items())
        assert items["x"] == 10
        assert items["y"] == 20

    def test_items_returns_deep_copy_of_dict_values(self):
        cfg = ImmutableConfig({"nested": {"inner": 1}})
        items = dict(cfg.items())
        items["nested"]["inner"] = 999
        assert cfg.get("nested")["inner"] == 1

    def test_to_dict_returns_full_deep_copy(self):
        cfg = ImmutableConfig({"a": {"b": 1}})
        d = cfg.to_dict()
        d["a"]["b"] = 999
        assert cfg.get("a")["b"] == 1

    def test_get_output_dir_from_output_section(self):
        cfg = ImmutableConfig(
            {
                "output": {"directory": "/results"},
                "decompiler": {"type": "default", "options": {}},
                "analysis": {},
            }
        )
        assert cfg.get_output_dir() == "/results"

    def test_get_output_dir_returns_default_when_output_missing(self):
        cfg = ImmutableConfig({"other": "value"})
        assert cfg.get_output_dir() == "output"

    def test_get_output_dir_returns_default_when_directory_key_missing(self):
        cfg = ImmutableConfig({"output": {}})
        assert cfg.get_output_dir() == "output"

    def test_get_output_dir_returns_default_when_output_is_not_dict(self):
        cfg = ImmutableConfig({"output": "string_value"})
        assert cfg.get_output_dir() == "output"

    def test_reload_updates_config_from_valid_file(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        new_config = {
            "decompiler": {"type": "r2ghidra", "options": {}},
            "output": {"directory": "/new/output"},
            "analysis": {},
        }
        cfg_path.write_text(json.dumps(new_config))
        cfg = ImmutableConfig()
        cfg.reload(str(cfg_path))
        assert cfg.get("decompiler")["type"] == "r2ghidra"

    def test_reload_keeps_current_config_when_file_missing(self, tmp_path):
        missing = tmp_path / "nonexistent.json"
        cfg = ImmutableConfig()
        original_decompiler = cfg.get("decompiler")
        cfg.reload(str(missing))
        assert cfg.get("decompiler") == original_decompiler

    def test_reload_keeps_current_config_when_decompiler_not_dict(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        bad = {
            "decompiler": "not_a_dict",
            "output": {"directory": "/tmp"},
            "analysis": {},
        }
        cfg_path.write_text(json.dumps(bad))
        cfg = ImmutableConfig()
        original = cfg.get("decompiler")
        cfg.reload(str(cfg_path))
        # Guard rejects it → config unchanged
        assert cfg.get("decompiler") == original

    def test_reload_keeps_current_config_when_output_not_dict(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        bad = {
            "decompiler": {"type": "default", "options": {}},
            "output": 123,
            "analysis": {},
        }
        cfg_path.write_text(json.dumps(bad))
        cfg = ImmutableConfig()
        original_output = cfg.get("output")
        cfg.reload(str(cfg_path))
        assert cfg.get("output") == original_output

    def test_reload_keeps_current_config_when_analysis_not_dict(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        bad = {
            "decompiler": {"type": "default", "options": {}},
            "output": {"directory": "/tmp"},
            "analysis": "not_a_dict",
        }
        cfg_path.write_text(json.dumps(bad))
        cfg = ImmutableConfig()
        original_analysis = cfg.get("analysis")
        cfg.reload(str(cfg_path))
        assert cfg.get("analysis") == original_analysis

    def test_reload_keeps_current_config_when_validation_fails(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        # Invalid decompiler type will pass the dict-guard but fail validate_full_config
        bad = {
            "decompiler": {"type": "totally_invalid", "options": {}},
            "output": {"directory": "/tmp"},
            "analysis": {},
        }
        cfg_path.write_text(json.dumps(bad))
        cfg = ImmutableConfig()
        original_type = cfg.get("decompiler")["type"]
        cfg.reload(str(cfg_path))
        assert cfg.get("decompiler")["type"] == original_type

    def test_reload_keeps_current_config_for_invalid_json(self, tmp_path):
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text("{invalid json")
        cfg = ImmutableConfig()
        original = cfg.get("decompiler")
        cfg.reload(str(cfg_path))
        # JSONDecodeError is caught, config unchanged
        assert cfg.get("decompiler") == original

    def test_reload_handles_missing_required_keys_by_logging_warning(
        self, tmp_path, caplog
    ):
        # Config without 'output' and 'analysis' keys — validate_config returns False
        # but reload still merges with defaults; validate_full_config then decides
        cfg_path = tmp_path / "config.json"
        partial = {"decompiler": {"type": "default", "options": {}}}
        cfg_path.write_text(json.dumps(partial))
        cfg = ImmutableConfig()
        with caplog.at_level(logging.WARNING):
            cfg.reload(str(cfg_path))
        # After merging, defaults fill in the gaps → validation should succeed
        # (no hard failure, the merged config is valid)
        assert isinstance(cfg.get("decompiler"), dict)

    def test_update_internal_replaces_config_with_new_dict(self):
        # Directly exercise ImmutableConfig._update_internal (line 127).
        cfg = ImmutableConfig({"old_key": "old_value"})
        new_data = {"new_key": "new_value", "score": 99}
        cfg._update_internal(new_data)
        assert cfg.get("new_key") == "new_value"
        assert cfg.get("score") == 99
        assert cfg.get("old_key") is None

    def test_update_internal_stores_deep_copy_isolating_from_caller(self):
        # Mutating the dict passed to _update_internal must not change the stored config.
        cfg = ImmutableConfig()
        mutable = {"key": "original"}
        cfg._update_internal(mutable)
        mutable["key"] = "mutated"
        assert cfg.get("key") == "original"


# ===========================================================================
# error_handling — ErrorCategory
# ===========================================================================


class TestErrorCategory:
    """Validate that ErrorCategory string enum values are correct."""

    def test_data_category_string_value(self):
        assert ErrorCategory.DATA == "Data error"

    def test_runtime_category_string_value(self):
        assert ErrorCategory.RUNTIME == "Runtime error"

    def test_io_category_string_value(self):
        assert ErrorCategory.IO == "I/O error"

    def test_analysis_category_string_value(self):
        assert ErrorCategory.ANALYSIS == "Analysis error"

    def test_all_categories_are_strings(self):
        for member in ErrorCategory:
            assert isinstance(member, str)


# ===========================================================================
# error_handling — EXCEPTION_GROUPS constant
# ===========================================================================


class TestExceptionGroups:
    """Validate the built-in exception-to-category mapping."""

    def test_data_group_contains_key_error(self):
        assert KeyError in EXCEPTION_GROUPS[ErrorCategory.DATA]

    def test_data_group_contains_attribute_error(self):
        assert AttributeError in EXCEPTION_GROUPS[ErrorCategory.DATA]

    def test_data_group_contains_type_error(self):
        assert TypeError in EXCEPTION_GROUPS[ErrorCategory.DATA]

    def test_runtime_group_contains_runtime_error(self):
        assert RuntimeError in EXCEPTION_GROUPS[ErrorCategory.RUNTIME]

    def test_runtime_group_contains_value_error(self):
        assert ValueError in EXCEPTION_GROUPS[ErrorCategory.RUNTIME]

    def test_io_group_contains_os_error(self):
        assert OSError in EXCEPTION_GROUPS[ErrorCategory.IO]


# ===========================================================================
# error_handling — _format_error_message (exercised via handle_errors)
# ===========================================================================


class TestFormatErrorMessage:
    """The private _format_error_message is reachable only through the decorator."""

    def test_formatted_message_contains_category_operation_and_exception(self):
        @handle_errors("loading data")
        def raise_key_error() -> "Ok[str] | Err[str]":
            raise KeyError("missing_key")

        result = raise_key_error()
        assert isinstance(result, Err)
        # ErrorCategory.DATA == "Data error"
        assert "Data error" in result.error
        assert "loading data" in result.error
        assert "missing_key" in result.error


# ===========================================================================
# error_handling — _log_error (exercised via handle_errors flags)
# ===========================================================================


class TestLogError:
    """_log_error is triggered when the corresponding logging flag is True."""

    def test_data_error_not_logged_by_default(self, caplog):
        @handle_errors("reading config")
        def raise_key_error() -> "Ok[str] | Err[str]":
            raise KeyError("no_key")

        with caplog.at_level(
            logging.ERROR, logger="bannedfuncdetector.infrastructure.error_handling"
        ):
            raise_key_error()
        assert not any("Data error" in r.message for r in caplog.records)

    def test_data_error_logged_when_flag_enabled(self, caplog):
        @handle_errors("reading config", log_data_errors=True)
        def raise_key_error() -> "Ok[str] | Err[str]":
            raise KeyError("no_key")

        with caplog.at_level(
            logging.ERROR, logger="bannedfuncdetector.infrastructure.error_handling"
        ):
            raise_key_error()
        assert any("no_key" in r.message for r in caplog.records)

    def test_runtime_error_logged_by_default(self, caplog):
        @handle_errors("processing")
        def raise_runtime_error() -> "Ok[int] | Err[str]":
            raise RuntimeError("bad state")

        with caplog.at_level(
            logging.ERROR, logger="bannedfuncdetector.infrastructure.error_handling"
        ):
            raise_runtime_error()
        assert any("bad state" in r.message for r in caplog.records)

    def test_runtime_error_not_logged_when_flag_disabled(self, caplog):
        @handle_errors("processing", log_runtime_errors=False)
        def raise_runtime_error() -> "Ok[int] | Err[str]":
            raise RuntimeError("silent failure")

        with caplog.at_level(
            logging.ERROR, logger="bannedfuncdetector.infrastructure.error_handling"
        ):
            raise_runtime_error()
        assert not any("silent failure" in r.message for r in caplog.records)

    def test_io_error_logged_by_default(self, caplog):
        @handle_errors("reading file")
        def raise_os_error() -> "Ok[str] | Err[str]":
            raise OSError("disk full")

        with caplog.at_level(
            logging.ERROR, logger="bannedfuncdetector.infrastructure.error_handling"
        ):
            raise_os_error()
        assert any("disk full" in r.message for r in caplog.records)

    def test_io_error_not_logged_when_flag_disabled(self, caplog):
        @handle_errors("reading file", log_io_errors=False)
        def raise_os_error() -> "Ok[str] | Err[str]":
            raise OSError("silent io")

        with caplog.at_level(
            logging.ERROR, logger="bannedfuncdetector.infrastructure.error_handling"
        ):
            raise_os_error()
        assert not any("silent io" in r.message for r in caplog.records)


# ===========================================================================
# error_handling — handle_errors decorator — success and each exception group
# ===========================================================================


class TestHandleErrors:
    """Tests for the @handle_errors decorator covering all exception branches."""

    def test_successful_function_returns_ok_value(self):
        @handle_errors("computing result")
        def compute() -> "Ok[int] | Err[str]":
            return ok(42)

        result = compute()
        assert isinstance(result, Ok)
        assert result.value == 42

    def test_key_error_is_converted_to_err_with_data_category(self):
        @handle_errors("accessing dict")
        def access_missing() -> "Ok[str] | Err[str]":
            d: dict = {}
            return ok(d["nonexistent"])

        result = access_missing()
        assert isinstance(result, Err)
        assert "Data error" in result.error
        assert "accessing dict" in result.error

    def test_attribute_error_is_converted_to_err_with_data_category(self):
        @handle_errors("accessing attribute")
        def access_attr() -> "Ok[str] | Err[str]":
            obj = object()
            return ok(obj.no_such_attr)  # type: ignore[attr-defined]

        result = access_attr()
        assert isinstance(result, Err)
        assert "Data error" in result.error

    def test_type_error_is_converted_to_err_with_data_category(self):
        @handle_errors("concatenating")
        def bad_concat() -> "Ok[str] | Err[str]":
            return ok("string" + 42)  # type: ignore[operator]

        result = bad_concat()
        assert isinstance(result, Err)
        assert "Data error" in result.error

    def test_runtime_error_is_converted_to_err_with_runtime_category(self):
        @handle_errors("processing")
        def raise_runtime() -> "Ok[int] | Err[str]":
            raise RuntimeError("something went wrong")

        result = raise_runtime()
        assert isinstance(result, Err)
        assert "Runtime error" in result.error
        assert "something went wrong" in result.error

    def test_value_error_is_converted_to_err_with_runtime_category(self):
        @handle_errors("parsing")
        def bad_parse() -> "Ok[int] | Err[str]":
            return ok(int("not_a_number"))

        result = bad_parse()
        assert isinstance(result, Err)
        assert "Runtime error" in result.error

    def test_os_error_is_converted_to_err_with_io_category(self):
        @handle_errors("reading file")
        def read_missing() -> "Ok[str] | Err[str]":
            with open("/nonexistent/path/to/file.txt") as f:
                return ok(f.read())

        result = read_missing()
        assert isinstance(result, Err)
        assert "I/O error" in result.error

    def test_io_error_subclass_is_caught_as_io_category(self):
        @handle_errors("io operation")
        def raise_file_not_found() -> "Ok[str] | Err[str]":
            raise FileNotFoundError("gone")

        result = raise_file_not_found()
        assert isinstance(result, Err)
        assert "I/O error" in result.error

    def test_decorator_preserves_function_name(self):
        @handle_errors("test op")
        def my_unique_function_name() -> "Ok[int] | Err[str]":
            return ok(1)

        assert my_unique_function_name.__name__ == "my_unique_function_name"

    def test_decorator_preserves_docstring(self):
        @handle_errors("test op")
        def documented_function() -> "Ok[int] | Err[str]":
            """This is the docstring."""
            return ok(1)

        assert documented_function.__doc__ == "This is the docstring."

    def test_decorator_with_args_and_kwargs(self):
        @handle_errors("computing sum")
        def add(a: int, b: int, multiplier: int = 1) -> "Ok[int] | Err[str]":
            return ok((a + b) * multiplier)

        result = add(3, 4, multiplier=2)
        assert isinstance(result, Ok)
        assert result.value == 14

    def test_decorator_with_include_analysis_errors_catches_analysis_error(self):
        @handle_errors("analyzing function", include_analysis_errors=True)
        def analyze() -> "Ok[str] | Err[str]":
            raise AnalysisError("decompiler failed")

        result = analyze()
        assert isinstance(result, Err)
        assert "Analysis error" in result.error
        assert "analyzing function" in result.error

    def test_decorator_without_include_analysis_errors_does_not_catch_analysis_error(
        self,
    ):
        @handle_errors("analyzing function", include_analysis_errors=False)
        def analyze() -> "Ok[str] | Err[str]":
            raise AnalysisError("decompiler failed")

        with pytest.raises(AnalysisError):
            analyze()

    def test_analysis_error_logged_when_runtime_logging_enabled(self, caplog):
        @handle_errors(
            "running analysis", include_analysis_errors=True, log_runtime_errors=True
        )
        def analyze() -> "Ok[str] | Err[str]":
            raise AnalysisError("logged analysis error")

        with caplog.at_level(
            logging.ERROR, logger="bannedfuncdetector.infrastructure.error_handling"
        ):
            analyze()
        assert any("logged analysis error" in r.message for r in caplog.records)

    def test_analysis_error_not_logged_when_runtime_logging_disabled(self, caplog):
        @handle_errors(
            "running analysis", include_analysis_errors=True, log_runtime_errors=False
        )
        def analyze() -> "Ok[str] | Err[str]":
            raise AnalysisError("silent analysis error")

        with caplog.at_level(
            logging.ERROR, logger="bannedfuncdetector.infrastructure.error_handling"
        ):
            analyze()
        assert not any("silent analysis error" in r.message for r in caplog.records)


# ===========================================================================
# error_handling — handle_errors_sync decorator
# ===========================================================================


class TestHandleErrorsSync:
    """Tests for the @handle_errors_sync decorator."""

    def test_successful_function_returns_its_value(self):
        @handle_errors_sync("checking flag")
        def always_true() -> bool:
            return True

        assert always_true() is True

    def test_exception_returns_false_by_default(self):
        @handle_errors_sync("checking plugin")
        def raise_runtime() -> bool:
            raise RuntimeError("plugin missing")

        assert raise_runtime() is False

    def test_exception_returns_custom_default_value(self):
        @handle_errors_sync("checking plugin", default_value=False)
        def raise_key_error() -> bool:
            raise KeyError("missing")

        assert raise_key_error() is False

    def test_exception_is_reraised_when_reraise_true(self):
        @handle_errors_sync("checking", reraise=True)
        def raise_value_error() -> bool:
            raise ValueError("must reraise")

        with pytest.raises(ValueError, match="must reraise"):
            raise_value_error()

    def test_exception_is_logged_by_default(self, caplog):
        @handle_errors_sync("checking availability")
        def raise_os_error() -> bool:
            raise OSError("disk problem")

        with caplog.at_level(
            logging.ERROR, logger="bannedfuncdetector.infrastructure.error_handling"
        ):
            raise_os_error()
        assert any("disk problem" in r.message for r in caplog.records)

    def test_exception_not_logged_when_log_errors_false(self, caplog):
        @handle_errors_sync("quiet op", log_errors=False)
        def raise_runtime() -> bool:
            raise RuntimeError("silent")

        with caplog.at_level(
            logging.ERROR, logger="bannedfuncdetector.infrastructure.error_handling"
        ):
            raise_runtime()
        assert not any("silent" in r.message for r in caplog.records)

    def test_catches_key_error(self):
        @handle_errors_sync("dict access")
        def bad_access() -> bool:
            d: dict = {}
            return bool(d["missing"])

        assert bad_access() is False

    def test_catches_attribute_error(self):
        @handle_errors_sync("attr access")
        def bad_attr() -> bool:
            return bool(object().no_attr)  # type: ignore[attr-defined]

        assert bad_attr() is False

    def test_catches_type_error(self):
        @handle_errors_sync("type op")
        def bad_type() -> bool:
            return bool("a" + 1)  # type: ignore[operator]

        assert bad_type() is False

    def test_catches_value_error(self):
        @handle_errors_sync("parse op")
        def bad_parse() -> bool:
            return bool(int("nope"))

        assert bad_parse() is False

    def test_catches_io_error(self):
        @handle_errors_sync("file op")
        def bad_io() -> bool:
            with open("/nonexistent/path.txt") as f:
                return bool(f.read())

        assert bad_io() is False

    def test_preserves_function_name(self):
        @handle_errors_sync("some op")
        def my_sync_func() -> bool:
            return True

        assert my_sync_func.__name__ == "my_sync_func"

    def test_decorator_with_none_default_value_returns_false_on_exception(self):
        # When default_value is None (the parameter default), the wrapper
        # returns False (the `default_value if default_value is not None else False` branch)
        @handle_errors_sync("none default", default_value=None)
        def raise_runtime() -> bool:
            raise RuntimeError("trigger default")

        result = raise_runtime()
        assert result is False


# ===========================================================================
# adapters.dtos — DetectionResultDTO and FunctionInfoDTO
# ===========================================================================


class TestDetectionResultDTO:
    """Instantiate and access every field of DetectionResultDTO."""

    def test_empty_detection_result_dto_is_valid(self):
        dto: DetectionResultDTO = {}
        assert isinstance(dto, dict)

    def test_full_detection_result_dto_with_all_fields(self):
        dto: DetectionResultDTO = {
            "name": "main",
            "address": 0x1000,
            "banned_functions": ["strcpy", "gets"],
            "detection_method": "import_table",
            "match_type": "exact",
            "decompiler": "r2ghidra",
            "size": 256,
            "type": "function",
            "string": "strcpy",
        }
        assert dto["name"] == "main"
        assert dto["address"] == 0x1000
        assert dto["banned_functions"] == ["strcpy", "gets"]
        assert dto["detection_method"] == "import_table"
        assert dto["match_type"] == "exact"
        assert dto["decompiler"] == "r2ghidra"
        assert dto["size"] == 256
        assert dto["type"] == "function"
        assert dto["string"] == "strcpy"

    def test_detection_result_dto_with_address_as_string(self):
        dto: DetectionResultDTO = {
            "name": "sym.func",
            "address": "0x401000",
        }
        assert dto["address"] == "0x401000"

    def test_detection_result_dto_with_subset_of_fields(self):
        dto: DetectionResultDTO = {
            "name": "helper",
            "banned_functions": ["sprintf"],
        }
        assert dto["name"] == "helper"
        assert "size" not in dto

    def test_detection_result_dto_banned_functions_is_a_list(self):
        dto: DetectionResultDTO = {
            "name": "vulnerable",
            "banned_functions": ["strcpy", "strcat", "gets"],
        }
        assert len(dto["banned_functions"]) == 3
        assert "gets" in dto["banned_functions"]

    def test_detection_result_dto_is_serializable_to_json(self):
        dto: DetectionResultDTO = {
            "name": "func",
            "address": 0x2000,
            "banned_functions": ["gets"],
            "detection_method": "decompiled_code",
        }
        serialized = json.dumps(dto)
        loaded = json.loads(serialized)
        assert loaded["name"] == "func"
        assert loaded["banned_functions"] == ["gets"]


class TestFunctionInfoDTO:
    """Instantiate and access every field of FunctionInfoDTO."""

    def test_empty_function_info_dto_is_valid(self):
        dto: FunctionInfoDTO = {}
        assert isinstance(dto, dict)

    def test_full_function_info_dto_with_all_fields(self):
        dto: FunctionInfoDTO = {
            "name": "fcn.00401000",
            "offset": 0x401000,
            "size": 128,
        }
        assert dto["name"] == "fcn.00401000"
        assert dto["offset"] == 0x401000
        assert dto["size"] == 128

    def test_function_info_dto_with_only_name(self):
        dto: FunctionInfoDTO = {"name": "main"}
        assert dto["name"] == "main"
        assert "offset" not in dto
        assert "size" not in dto

    def test_function_info_dto_with_only_offset_and_size(self):
        dto: FunctionInfoDTO = {"offset": 0x100, "size": 64}
        assert dto["offset"] == 0x100
        assert dto["size"] == 64

    def test_function_info_dto_offset_zero_is_valid(self):
        dto: FunctionInfoDTO = {"name": "entry", "offset": 0, "size": 8}
        assert dto["offset"] == 0

    def test_function_info_dto_is_serializable_to_json(self):
        dto: FunctionInfoDTO = {"name": "main", "offset": 0x1000, "size": 100}
        serialized = json.dumps(dto)
        loaded = json.loads(serialized)
        assert loaded["name"] == "main"
        assert loaded["offset"] == 0x1000
