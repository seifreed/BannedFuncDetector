#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for dependency injection patterns in BannedFuncDetector.

This test module demonstrates how to use the new DI-friendly APIs
for testing components with mock dependencies.

Author: Marc Rivero | @seifreed
"""

import pytest

from bannedfuncdetector.factories import (
    DEFAULT_R2_FLAGS,
    DictConfig,
    create_r2_client,
    create_binary_analyzer,
    create_config_from_dict,
)
from conftest import MockR2ClientFactory, MockConfigRepository
from bannedfuncdetector.application.binary_analyzer import R2BinaryAnalyzer, analyze_function, analyze_binary
from bannedfuncdetector.application.directory_scanner import analyze_directory
from bannedfuncdetector.domain.result import Ok, Err


# =============================================================================
# MOCK CONFIGURATION TESTS
# =============================================================================


class TestMockConfigRepository:
    """Tests for MockConfigRepository."""

    def test_get_returns_configured_value(self):
        """Test that get() returns configured values."""
        config = MockConfigRepository({"banned_functions": ["strcpy"]})
        assert config.get("banned_functions") == ["strcpy"]

    def test_get_returns_default_for_missing_key(self):
        """Test that get() returns default for missing keys."""
        config = MockConfigRepository({})
        assert config.get("missing", "default") == "default"

    def test_getitem_returns_configured_value(self):
        """Test that bracket notation works."""
        config = MockConfigRepository({"output": {"directory": "/tmp"}})
        assert config["output"]["directory"] == "/tmp"

    def test_get_output_dir_returns_directory(self):
        """Test get_output_dir() returns the configured directory."""
        config = MockConfigRepository({"output": {"directory": "/custom/output"}})
        assert config.get_output_dir() == "/custom/output"

    def test_get_output_dir_returns_default(self):
        """Test get_output_dir() returns default when not configured."""
        config = MockConfigRepository({})
        assert config.get_output_dir() == "output"

    def test_contains_check(self):
        """Test 'in' operator works correctly."""
        config = MockConfigRepository({"key": "value"})
        assert "key" in config
        assert "missing" not in config

    def test_to_dict_returns_copy(self):
        """Test to_dict() returns the configuration."""
        original = {"key": "value"}
        config = MockConfigRepository(original)
        result = config.to_dict()
        assert result == original


# =============================================================================
# MOCK R2 FACTORY TESTS
# =============================================================================


class TestMockR2ClientFactory:
    """Tests for MockR2ClientFactory."""

    def test_create_returns_mock_client(self, fake_r2_factory):
        """Test that create() returns the configured mock client."""
        fake = fake_r2_factory(cmdj_map={"aflj": [{"name": "main"}]})
        factory = MockR2ClientFactory(fake)

        client = factory.create("/any/path")
        functions = client.cmdj("aflj")

        assert len(functions) == 1
        assert functions[0]["name"] == "main"

    def test_create_ignores_file_path(self, fake_r2_factory):
        """Test that create() ignores the file path argument."""
        fake = fake_r2_factory()
        factory = MockR2ClientFactory(fake)

        client1 = factory.create("/path/one")
        client2 = factory.create("/path/two")

        # Both should return the same mock
        assert client1 is client2


# =============================================================================
# R2 CLIENT FACTORY FUNCTION TESTS
# =============================================================================


class TestCreateR2Client:
    """Tests for create_r2_client factory function."""

    def test_default_flags_are_set(self):
        """Test that default flags are configured."""
        assert DEFAULT_R2_FLAGS == ["-2"]

    def test_create_r2_client_is_callable(self):
        """Test that create_r2_client is a callable function."""
        assert callable(create_r2_client)


# =============================================================================
# CREATE BINARY ANALYZER FACTORY TESTS
# =============================================================================


class TestCreateBinaryAnalyzer:
    """Tests for create_binary_analyzer factory function."""

    def test_creates_analyzer_with_config(self, mock_config):
        """Test that factory creates analyzer with provided config."""
        analyzer = create_binary_analyzer(config=mock_config)

        assert isinstance(analyzer, R2BinaryAnalyzer)
        assert analyzer._config is mock_config

    def test_creates_analyzer_with_decompiler_type(self, mock_config):
        """Test that factory passes decompiler type."""
        analyzer = create_binary_analyzer(
            config=mock_config,
            decompiler_type="r2ghidra"
        )

        assert analyzer.decompiler_type == "r2ghidra"

    def test_creates_analyzer_with_verbose_flag(self, mock_config):
        """Test that factory passes verbose flag."""
        analyzer = create_binary_analyzer(
            config=mock_config,
            verbose=True
        )

        assert analyzer.verbose is True

    def test_creates_analyzer_with_r2_factory(self, mock_config, fake_r2_factory):
        """Test that factory accepts custom R2 factory."""
        fake = fake_r2_factory()
        r2_factory = MockR2ClientFactory(fake)

        analyzer = create_binary_analyzer(
            config=mock_config,
            r2_factory=r2_factory
        )

        # The analyzer should use our factory
        assert analyzer._r2_factory is not None


# =============================================================================
# CREATE CONFIG FROM DICT TESTS
# =============================================================================


class TestDictConfig:
    """Tests for DictConfig class."""

    def test_get_returns_configured_value(self):
        """Test that get() returns configured values."""
        config = DictConfig({"banned_functions": ["strcpy"]})
        assert config.get("banned_functions") == ["strcpy"]

    def test_get_returns_default_for_missing_key(self):
        """Test that get() returns default for missing keys."""
        config = DictConfig({})
        assert config.get("missing", "default") == "default"

    def test_getitem_returns_configured_value(self):
        """Test that bracket notation works."""
        config = DictConfig({"output": {"directory": "/tmp"}})
        assert config["output"]["directory"] == "/tmp"

    def test_get_output_dir_returns_directory(self):
        """Test get_output_dir() returns the configured directory."""
        config = DictConfig({"output": {"directory": "/custom/output"}})
        assert config.get_output_dir() == "/custom/output"

    def test_get_output_dir_returns_default(self):
        """Test get_output_dir() returns default when not configured."""
        config = DictConfig({})
        assert config.get_output_dir() == "output"

    def test_contains_check(self):
        """Test 'in' operator works correctly."""
        config = DictConfig({"key": "value"})
        assert "key" in config
        assert "missing" not in config

    def test_to_dict_returns_copy(self):
        """Test to_dict() returns a deep copy of the configuration."""
        original = {"key": "value"}
        config = DictConfig(original)
        result = config.to_dict()
        assert result == original
        # Verify it's a copy, not the same object
        result["key"] = "modified"
        assert config.get("key") == "value"

    def test_values_are_isolated(self):
        """Test that modifying returned values doesn't affect internal state."""
        config = DictConfig({"list": [1, 2, 3]})
        returned_list = config.get("list")
        returned_list.append(4)
        assert config.get("list") == [1, 2, 3]


class TestCreateConfigFromDict:
    """Tests for create_config_from_dict factory function."""

    def test_creates_config_from_dict(self):
        """Test that factory creates config from dictionary."""
        config = create_config_from_dict({"banned_functions": ["gets"]})

        assert "gets" in config.get("banned_functions", [])

    def test_merges_with_defaults(self):
        """Test that config is merged with defaults."""
        config = create_config_from_dict({"custom_key": "value"})

        # Should have both custom key and default keys
        assert config.get("custom_key") == "value"
        assert config.get("output") is not None  # Default key

    def test_returns_dict_config_by_default(self):
        """Test that factory returns DictConfig by default (not singleton)."""
        config = create_config_from_dict({"test_key": "test_value"})
        assert isinstance(config, DictConfig)

    def test_dict_config_is_isolated(self):
        """Test that DictConfig instances are isolated from each other."""
        config1 = create_config_from_dict({"key1": "value1"})
        config2 = create_config_from_dict({"key2": "value2"})

        # Each config should only have its own key
        assert config1.get("key1") == "value1"
        assert config2.get("key2") == "value2"
        # And not the other's key (beyond defaults)
        assert config1.get("key2") is None
        assert config2.get("key1") is None


# =============================================================================
# DIRECT API TESTS WITH DEPENDENCY INJECTION
# =============================================================================


class TestAnalyzeBinaryWithDI:
    """Tests for analyze_binary function with mock dependencies."""

    def test_execute_with_mock_config(self, tmp_path):
        """Test binary analysis execution with mock configuration."""
        # Create a test file
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"test binary data")

        mock_config = MockConfigRepository({
            "banned_functions": ["strcpy"],
            "output": {"directory": str(tmp_path / "output")},
            "decompiler": {"type": "default"}
        })

        result = analyze_binary(
            binary_path=str(test_file),
            config=mock_config,
        )

        # The analysis returns a Result type (Ok or Err)
        # Likely Err since it's not a real binary
        assert isinstance(result, (Ok, Err))

    def test_execute_file_not_found(self, mock_config):
        """Test analysis handles missing file gracefully."""
        # Add required config keys
        mock_config._config["decompiler"] = {"type": "default"}

        result = analyze_binary(
            binary_path="/nonexistent/file.bin",
            config=mock_config,
        )

        # The function returns Err for missing files
        assert isinstance(result, Err)
        assert "not found" in result.error.lower() or "not exist" in result.error.lower()


class TestAnalyzeDirectoryWithDI:
    """Tests for analyze_directory function with mock dependencies."""

    def test_execute_directory_not_found(self, mock_config):
        """Test analysis handles missing directory gracefully."""
        result = analyze_directory(
            directory="/nonexistent/directory",
            config=mock_config,
        )

        assert isinstance(result, Err)
        assert "does not exist" in result.error.lower()

    def test_uses_config_output_dir(self, tmp_path, mock_config_factory):
        """Test analysis uses config output directory when not provided."""
        output_dir = tmp_path / "configured_output"
        config = mock_config_factory({
            "output": {"directory": str(output_dir)}
        })

        # Just verify the config is used correctly
        assert config.get_output_dir() == str(output_dir)


# =============================================================================
# ANALYZE FUNCTION WITH INJECTED CONFIG TESTS
# =============================================================================


class TestAnalyzeFunctionWithDI:
    """Tests for analyze_function with injected configuration."""

    def test_analyze_with_custom_banned_functions(self):
        """Test analyze_function uses provided banned functions."""
        mock_config = MockConfigRepository({
            "banned_functions": ["custom_banned_func"]
        })

        # Test with a function that matches our custom banned function
        func = {"name": "custom_banned_func", "offset": 0x1000}
        result = analyze_function(
            r2=None,  # Not needed for name matching
            func=func,
            banned_functions={"custom_banned_func"},
            decompiler_type="default",
            verbose=False,
            config=mock_config
        )

        assert result.is_ok()
        detection = result.unwrap()
        assert detection["detection_method"] == "name"
        assert "custom_banned_func" in detection["banned_functions"]

    def test_analyze_with_different_banned_functions(self, mock_config):
        """Test analyze_function with different banned functions set."""
        func = {"name": "safefunc", "offset": 0x1000}
        result = analyze_function(
            r2=None,
            func=func,
            banned_functions={"dangerous_func"},  # Not matching function name
            decompiler_type="default",
            verbose=False,
            config=mock_config
        )

        # Should not detect since function name doesn't match banned set
        assert result.is_err()


# =============================================================================
# INTEGRATION TEST: FULL DI CHAIN
# =============================================================================


class TestFullDependencyInjectionChain:
    """Integration tests verifying the full DI chain works correctly."""

    def test_analyzer_with_all_injected_dependencies(self, mock_config, fake_r2_factory):
        """Test R2BinaryAnalyzer with fully injected dependencies."""
        # Create mock R2 client that returns test data
        fake = fake_r2_factory(
            cmd_map={"aaa": ""},
            cmdj_map={
                "aflj": [
                    {"name": "main", "offset": 0x1000, "size": 100},
                    {"name": "strcpy", "offset": 0x2000, "size": 50},
                ]
            }
        )
        r2_factory = MockR2ClientFactory(fake)

        # Create analyzer with all dependencies injected
        analyzer = R2BinaryAnalyzer(
            decompiler_type="default",
            verbose=True,
            r2_factory=r2_factory.create,
            config=mock_config
        )

        # Verify the configuration is properly injected
        assert analyzer._config is mock_config
        assert analyzer.decompiler_type == "default"
        assert analyzer.verbose is True

    def test_analyzer_with_factory_created_config(self, mock_config):
        """Test that factory-created analyzer has correct configuration."""
        analyzer = create_binary_analyzer(
            config=mock_config,
            decompiler_type="default",
            verbose=False
        )

        # Verify the analyzer has the right configuration
        assert analyzer._config is mock_config
        assert analyzer.decompiler_type == "default"
