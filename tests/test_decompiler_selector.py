#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Decompiler Selector Tests

Copyright (c) 2026 Marc Rivero Lopez
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Author: Marc Rivero | @seifreed
"""

import pytest
from bannedfuncdetector.infrastructure.decompilers.availability import (
    check_decompiler_available,
    get_available_decompiler,
)
from bannedfuncdetector.infrastructure.decompilers.selector import (
    select_decompiler,
)
from bannedfuncdetector.infrastructure.decompilers.base_decompiler import DecompilerType
from bannedfuncdetector.infrastructure.config_repository import CONFIG, get_default_config


class TestCheckDecompilerAvailable:
    """Test suite for check_decompiler_available function."""

    def test_check_decompiler_available_default_always_true(self):
        """Test that default decompiler is always available."""
        result = check_decompiler_available(DecompilerType.DEFAULT)

        assert result is True

    def test_check_decompiler_available_default_string(self):
        """Test default decompiler availability with string."""
        result = check_decompiler_available("default")

        assert result is True

    def test_check_decompiler_available_unknown_returns_false(self):
        """Test that unknown decompiler returns False."""
        result = check_decompiler_available("unknown_decompiler", print_message=False)

        assert result is False

    def test_check_decompiler_available_r2ai_returns_false(self):
        """Test that r2ai (not a decompiler) returns False."""
        result = check_decompiler_available("r2ai", print_message=False)

        assert result is False

    def test_check_decompiler_available_r2ghidra(self):
        """Test r2ghidra availability check."""
        result = check_decompiler_available("r2ghidra", print_message=False)

        # Result depends on system configuration
        assert isinstance(result, bool)

    def test_check_decompiler_available_r2dec(self):
        """Test r2dec availability check."""
        result = check_decompiler_available("r2dec", print_message=False)

        assert isinstance(result, bool)

    def test_check_decompiler_available_decai(self):
        """Test decai availability check."""
        result = check_decompiler_available("decai", print_message=False)

        assert isinstance(result, bool)

    def test_check_decompiler_available_with_enum_type(self):
        """Test availability check with DecompilerType enum."""
        result = check_decompiler_available(DecompilerType.R2GHIDRA, print_message=False)

        assert isinstance(result, bool)

    def test_check_decompiler_available_with_print_message(self):
        """Test availability check with logging enabled."""
        # Should not raise, just log
        result = check_decompiler_available(DecompilerType.DEFAULT, print_message=True)

        assert result is True


class TestGetAvailableDecompiler:
    """Test suite for get_available_decompiler function."""

    def test_get_available_decompiler_default_preference(self):
        """Test getting available decompiler with default preference."""
        result = get_available_decompiler()

        # Should return a valid decompiler name
        assert isinstance(result, str)
        assert result in ["r2ghidra", "r2dec", "default", "decai"]

    def test_get_available_decompiler_r2ghidra_preferred(self):
        """Test getting available decompiler preferring r2ghidra."""
        result = get_available_decompiler(DecompilerType.R2GHIDRA)

        assert isinstance(result, str)
        assert result in ["r2ghidra", "r2dec", "default"]

    def test_get_available_decompiler_string_preferred(self):
        """Test getting available decompiler with string preference."""
        result = get_available_decompiler("r2dec")

        assert isinstance(result, str)
        assert result in ["r2ghidra", "r2dec", "default"]

    def test_get_available_decompiler_r2ai_ignored(self):
        """Test that r2ai preference is ignored (not a decompiler)."""
        result = get_available_decompiler("r2ai")

        # Should fall back to available alternatives
        assert isinstance(result, str)
        assert result in ["r2ghidra", "r2dec", "default"]

    def test_get_available_decompiler_unknown_type(self):
        """Test getting available decompiler with unknown type."""
        result = get_available_decompiler("unknown")

        # Should still find an available decompiler
        assert isinstance(result, str)
        assert result in ["r2ghidra", "r2dec", "default", "unknown"]


class TestSelectDecompiler:
    """Test suite for select_decompiler function."""

    def test_select_decompiler_default_from_config(self):
        """Test selection using config default."""
        result = select_decompiler()

        assert isinstance(result, str)
        assert result in ["r2ghidra", "r2dec", "default", "decai"]

    def test_select_decompiler_force_mode(self):
        """Test that force mode bypasses availability check."""
        result = select_decompiler("r2ghidra", force=True)

        assert result == "r2ghidra"

    def test_select_decompiler_force_mode_unknown(self):
        """Test force mode with unknown decompiler."""
        result = select_decompiler("unknown", force=True)

        assert result == "unknown"

    def test_select_decompiler_available_requested(self):
        """Test selection when requested decompiler is available."""
        # Default is always available
        result = select_decompiler("default", verbose=False)

        assert result == "default"

    def test_select_decompiler_fallback_to_alternative(self):
        """Test fallback when requested is unavailable."""
        # Try to request something that might not be available
        result = select_decompiler("decai", verbose=False)

        # Should return a valid decompiler (might be decai or fallback)
        assert result in ["decai", "r2ghidra", "r2dec", "default"]

    def test_select_decompiler_with_enum(self):
        """Test selection with DecompilerType enum."""
        result = select_decompiler(DecompilerType.DEFAULT)

        assert result == "default"

    def test_select_decompiler_verbose_mode(self):
        """Test selection with verbose logging."""
        result = select_decompiler("default", verbose=True)

        assert result == "default"

    def test_select_decompiler_r2ai_replaced(self):
        """Test that r2ai is replaced with default."""
        result = select_decompiler("r2ai", verbose=False)

        # r2ai should be replaced with default
        assert result in ["r2ghidra", "r2dec", "default"]

    def test_select_decompiler_none_uses_config(self):
        """Test that None uses config value."""
        result = select_decompiler(None, verbose=False)

        # Should use config default
        assert isinstance(result, str)


class TestDecompilerSelectionIntegration:
    """Integration tests for decompiler selection."""

    def test_select_decompiler_always_returns_valid(self):
        """Test that select_decompiler always returns valid decompiler."""
        test_cases = [
            None,
            "default",
            "r2ghidra",
            "r2dec",
            "decai",
            "unknown",
            "r2ai",
            DecompilerType.DEFAULT,
            DecompilerType.R2GHIDRA,
        ]

        for test_case in test_cases:
            result = select_decompiler(test_case, verbose=False)
            assert isinstance(result, str)
            assert len(result) > 0

    def test_force_mode_accepts_any_value(self):
        """Test that force mode accepts any decompiler value."""
        test_cases = ["unknown", "custom", "anything"]

        for test_case in test_cases:
            result = select_decompiler(test_case, force=True, verbose=False)
            assert result == test_case

    def test_get_available_decompiler_consistency(self):
        """Test that get_available_decompiler returns consistent results."""
        result1 = get_available_decompiler()
        result2 = get_available_decompiler()

        # Should return the same result for repeated calls
        assert result1 == result2
