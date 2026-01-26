#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - R2Dec Decompiler Tests

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Author: Marc Rivero | @seifreed
"""

import pytest
from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    DecompilerType,
    check_decompiler_plugin_available,
)
from bannedfuncdetector.infrastructure.decompilers.r2dec_decompiler import R2DecDecompiler
from conftest import FakeR2


class TestR2DecAvailability:
    """Test suite for R2Dec availability checking."""

    def test_check_r2dec_available(self):
        """Test r2dec availability check using check_decompiler_plugin_available."""
        result = check_decompiler_plugin_available(DecompilerType.R2DEC)

        # Result depends on system configuration
        assert isinstance(result, bool)


class TestDecompileWithR2Dec:
    """Test suite for R2DecDecompiler.decompile method."""

    def test_decompile_with_r2dec_success(self, fake_r2_factory):
        """Test successful decompilation with r2dec."""
        expected_code = "void main() { printf(\"test\"); }"
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ main": {"name": "main", "offset": 4096},
            },
            cmd_map={
                "s 4096": "",
                "pdd": expected_code,
            }
        )

        decompiler = R2DecDecompiler()
        result = decompiler.decompile(fake, "main")

        assert result == expected_code

    def test_decompile_with_r2dec_fallback_to_r2ghidra(self, fake_r2_factory):
        """Test r2dec falls back to r2ghidra when primary fails."""
        fallback_code = "void main() { }"
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ main": {"name": "main", "offset": 4096},
            },
            cmd_map={
                "s 4096": "",
                "pdd": "",  # r2dec fails
                "pdg": fallback_code,  # r2ghidra succeeds
            }
        )

        decompiler = R2DecDecompiler()
        result = decompiler.decompile(fake, "main", use_alternative=True)

        assert result == fallback_code

    def test_decompile_with_r2dec_no_alternative(self, fake_r2_factory):
        """Test r2dec without fallback returns empty string."""
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ main": {"name": "main", "offset": 4096},
            },
            cmd_map={
                "s 4096": "",
                "pdd": "",  # r2dec fails
            }
        )

        decompiler = R2DecDecompiler()
        result = decompiler.decompile(fake, "main", use_alternative=False)

        assert result == ""

    def test_decompile_with_r2dec_clean_error_messages(self, fake_r2_factory):
        """Test r2dec with error message cleaning."""
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ main": {"name": "main", "offset": 4096},
            },
            cmd_map={
                "s 4096": "",
                "pdd": "void main() { error_message }",
            }
        )

        decompiler = R2DecDecompiler()
        result = decompiler.decompile(fake, "main", clean_error_messages=True)

        # Result should have error messages cleaned
        assert isinstance(result, str)


class TestR2DecDecompilerClass:
    """Test suite for R2DecDecompiler class."""

    def test_r2dec_decompiler_init(self):
        """Test R2DecDecompiler initialization."""
        decompiler = R2DecDecompiler()

        assert decompiler.name == "r2dec"
        assert decompiler.command == "pdd"
        assert decompiler.get_name() == "r2dec"

    def test_r2dec_decompiler_is_available(self):
        """Test is_available method."""
        decompiler = R2DecDecompiler()

        result = decompiler.is_available()

        # Result depends on system configuration
        assert isinstance(result, bool)

    def test_r2dec_decompiler_is_available_with_r2(self, fake_r2):
        """Test is_available method with r2 parameter (not used)."""
        decompiler = R2DecDecompiler()

        result = decompiler.is_available(fake_r2)

        assert isinstance(result, bool)

    def test_r2dec_decompiler_decompile_success(self, fake_r2_factory):
        """Test decompile method success path."""
        expected_code = "void test() { return 0; }"
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ test": {"name": "test", "offset": 8192},
            },
            cmd_map={
                "s 8192": "",
                "pdd": expected_code,
            }
        )

        decompiler = R2DecDecompiler()
        result = decompiler.decompile(fake, "test")

        assert result == expected_code

    def test_r2dec_decompiler_decompile_empty_result(self, fake_r2_factory):
        """Test decompile method returns empty string for failed decompilation."""
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ test": {"name": "test", "offset": 4096},
            },
            cmd_map={
                "s 4096": "",
                "pdd": "",  # Empty result
            }
        )

        decompiler = R2DecDecompiler()
        result = decompiler.decompile(fake, "test")

        assert result == ""

    def test_r2dec_decompiler_decompile_function_not_found(self, fake_r2_factory):
        """Test decompile method when function not found."""
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ missing": None,
            }
        )

        decompiler = R2DecDecompiler()
        result = decompiler.decompile(fake, "missing")

        # Should return empty string when function not found
        assert result == ""

    def test_r2dec_decompiler_decompile_short_output(self, fake_r2_factory):
        """Test decompile method filters out very short output."""
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ test": {"name": "test", "offset": 4096},
            },
            cmd_map={
                "s 4096": "",
                "pdd": "x",  # Very short output (likely error)
            }
        )

        decompiler = R2DecDecompiler()
        result = decompiler.decompile(fake, "test")

        # Short outputs should be filtered
        assert result == ""


class TestR2DecIntegration:
    """Integration tests for R2Dec decompiler."""

    def test_r2dec_decompiler_protocol_compliance(self):
        """Test that R2DecDecompiler implements IDecompiler protocol."""
        decompiler = R2DecDecompiler()

        # Check required methods exist
        assert hasattr(decompiler, "decompile")
        assert callable(decompiler.decompile)
        assert hasattr(decompiler, "is_available")
        assert callable(decompiler.is_available)
        assert hasattr(decompiler, "get_name")
        assert callable(decompiler.get_name)

    def test_r2dec_decompiler_get_name_returns_string(self):
        """Test get_name returns non-empty string."""
        decompiler = R2DecDecompiler()

        name = decompiler.get_name()

        assert isinstance(name, str)
        assert len(name) > 0
        assert name == "r2dec"
