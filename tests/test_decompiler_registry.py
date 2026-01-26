#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Decompiler Registry Tests

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Author: Marc Rivero | @seifreed
"""

import pytest
from bannedfuncdetector.infrastructure.decompilers.registry import (
    DECOMPILER_INSTANCES,
    DecompilerInstance,
    create_decompiler,
)
from bannedfuncdetector.infrastructure.decompilers.base_decompiler import DecompilerType
from bannedfuncdetector.infrastructure.decompilers.decai_decompiler import DecAIDecompiler
from bannedfuncdetector.infrastructure.decompilers.default_decompiler import DefaultDecompiler
from bannedfuncdetector.infrastructure.decompilers.r2dec_decompiler import R2DecDecompiler
from bannedfuncdetector.infrastructure.decompilers.r2ghidra_decompiler import R2GhidraDecompiler
from conftest import FakeR2


class TestDecompilerRegistry:
    """Test suite for DECOMPILER_INSTANCES registry."""

    def test_decompiler_instances_contains_all_types(self):
        """Test that registry contains all expected decompiler types."""
        expected_types = [
            DecompilerType.R2GHIDRA.value,
            DecompilerType.R2DEC.value,
            DecompilerType.DECAI.value,
            DecompilerType.DEFAULT.value,
        ]

        for decompiler_type in expected_types:
            assert decompiler_type in DECOMPILER_INSTANCES

    def test_decompiler_instances_r2ghidra_type(self):
        """Test that r2ghidra instance has correct type."""
        instance = DECOMPILER_INSTANCES[DecompilerType.R2GHIDRA.value]

        assert isinstance(instance, R2GhidraDecompiler)
        assert instance.get_name() == "r2ghidra"

    def test_decompiler_instances_r2dec_type(self):
        """Test that r2dec instance has correct type."""
        instance = DECOMPILER_INSTANCES[DecompilerType.R2DEC.value]

        assert isinstance(instance, R2DecDecompiler)
        assert instance.get_name() == "r2dec"

    def test_decompiler_instances_decai_type(self):
        """Test that decai instance has correct type."""
        instance = DECOMPILER_INSTANCES[DecompilerType.DECAI.value]

        assert isinstance(instance, DecAIDecompiler)
        assert instance.get_name() == "decai"

    def test_decompiler_instances_default_type(self):
        """Test that default instance has correct type."""
        instance = DECOMPILER_INSTANCES[DecompilerType.DEFAULT.value]

        assert isinstance(instance, DefaultDecompiler)
        assert instance.get_name() == "default"


class TestCreateDecompiler:
    """Test suite for create_decompiler factory function."""

    def test_create_decompiler_r2ghidra_enum(self):
        """Test creating r2ghidra decompiler with enum."""
        decompiler = create_decompiler(DecompilerType.R2GHIDRA)

        assert isinstance(decompiler, R2GhidraDecompiler)
        assert decompiler.get_name() == "r2ghidra"

    def test_create_decompiler_r2ghidra_string(self):
        """Test creating r2ghidra decompiler with string."""
        decompiler = create_decompiler("r2ghidra")

        assert isinstance(decompiler, R2GhidraDecompiler)
        assert decompiler.get_name() == "r2ghidra"

    def test_create_decompiler_r2dec_enum(self):
        """Test creating r2dec decompiler with enum."""
        decompiler = create_decompiler(DecompilerType.R2DEC)

        assert isinstance(decompiler, R2DecDecompiler)
        assert decompiler.get_name() == "r2dec"

    def test_create_decompiler_r2dec_string(self):
        """Test creating r2dec decompiler with string."""
        decompiler = create_decompiler("r2dec")

        assert isinstance(decompiler, R2DecDecompiler)
        assert decompiler.get_name() == "r2dec"

    def test_create_decompiler_decai_enum(self):
        """Test creating decai decompiler with enum."""
        decompiler = create_decompiler(DecompilerType.DECAI)

        assert isinstance(decompiler, DecAIDecompiler)
        assert decompiler.get_name() == "decai"

    def test_create_decompiler_decai_string(self):
        """Test creating decai decompiler with string."""
        decompiler = create_decompiler("decai")

        assert isinstance(decompiler, DecAIDecompiler)
        assert decompiler.get_name() == "decai"

    def test_create_decompiler_default_enum(self):
        """Test creating default decompiler with enum."""
        decompiler = create_decompiler(DecompilerType.DEFAULT)

        assert isinstance(decompiler, DefaultDecompiler)
        assert decompiler.get_name() == "default"

    def test_create_decompiler_default_string(self):
        """Test creating default decompiler with string."""
        decompiler = create_decompiler("default")

        assert isinstance(decompiler, DefaultDecompiler)
        assert decompiler.get_name() == "default"

    def test_create_decompiler_unknown_string_returns_default(self):
        """Test that unknown decompiler type returns default."""
        decompiler = create_decompiler("unknown_decompiler")

        assert isinstance(decompiler, DefaultDecompiler)
        assert decompiler.get_name() == "default"

    def test_create_decompiler_r2ai_returns_default(self):
        """Test that r2ai type returns default (r2ai is not a decompiler)."""
        decompiler = create_decompiler("r2ai")

        assert isinstance(decompiler, DefaultDecompiler)
        assert decompiler.get_name() == "default"

    def test_create_decompiler_maintains_singleton_instances(self):
        """Test that multiple calls return the same instance from registry."""
        decompiler1 = create_decompiler("r2ghidra")
        decompiler2 = create_decompiler("r2ghidra")

        # Should be the same instance from registry
        assert decompiler1 is decompiler2


class TestDecompilerIntegration:
    """Integration tests for decompiler instances."""

    def test_all_decompilers_have_required_methods(self):
        """Test that all registered decompilers implement required methods."""
        for name, decompiler in DECOMPILER_INSTANCES.items():
            # Each decompiler must have these methods
            assert hasattr(decompiler, "decompile")
            assert callable(decompiler.decompile)
            assert hasattr(decompiler, "is_available")
            assert callable(decompiler.is_available)
            assert hasattr(decompiler, "get_name")
            assert callable(decompiler.get_name)

    def test_all_decompilers_is_available_returns_bool(self):
        """Test that all decompilers' is_available returns boolean."""
        for name, decompiler in DECOMPILER_INSTANCES.items():
            result = decompiler.is_available()
            assert isinstance(result, bool), f"{name} is_available must return bool"

    def test_all_decompilers_get_name_returns_string(self):
        """Test that all decompilers' get_name returns string."""
        for name, decompiler in DECOMPILER_INSTANCES.items():
            result = decompiler.get_name()
            assert isinstance(result, str), f"{name} get_name must return str"
            assert len(result) > 0, f"{name} get_name must return non-empty string"
