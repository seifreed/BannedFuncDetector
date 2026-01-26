#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Analyzers Module Direct Import Tests

Copyright (c) 2026 Marc Rivero Lopez
Licensed under GPLv3. See LICENSE file for details.
This test suite validates direct imports from source modules.

Author: Marc Rivero | @seifreed

Note: The analyzers.py facade module has been removed.
These tests now verify direct imports from source modules.
"""

import pytest
import warnings


class TestAnalyzersPublicAPI:
    """Test suite for analyzers module public API via direct imports."""

    def test_public_exceptions_imported(self):
        """Test that public exceptions are available from source modules."""
        from bannedfuncdetector.analyzer_exceptions import (
            AnalyzerError,
            BinaryNotFoundError,
            DirectoryNotFoundError,
            DecompilerNotAvailableError,
            AnalysisError,
        )

        # All exceptions should be available
        assert AnalyzerError is not None
        assert BinaryNotFoundError is not None
        assert DirectoryNotFoundError is not None
        assert DecompilerNotAvailableError is not None
        assert AnalysisError is not None

    def test_public_functions_imported(self):
        """Test that public functions are available from source modules."""
        from bannedfuncdetector.application.binary_analyzer import (
            analyze_function,
            analyze_binary,
        )
        from bannedfuncdetector.application.directory_scanner import analyze_directory

        # All public functions should be available
        assert analyze_function is not None
        assert callable(analyze_function)
        assert analyze_binary is not None
        assert callable(analyze_binary)
        assert analyze_directory is not None
        assert callable(analyze_directory)

    def test_public_class_imported(self):
        """Test that R2BinaryAnalyzer class is available."""
        from bannedfuncdetector.application.binary_analyzer import R2BinaryAnalyzer

        assert R2BinaryAnalyzer is not None


class TestAnalyzersLazyImportCaching:
    """Test suite for module import functionality."""

    def test_binary_analyzer_imports(self):
        """Test that binary_analyzer functions are importable."""
        from bannedfuncdetector.application.binary_analyzer import _validate_binary_input

        assert callable(_validate_binary_input)

    def test_binary_operations_imports(self):
        """Test that binary_operations functions are importable from binary_analyzer."""
        from bannedfuncdetector.application.binary_analyzer import _open_binary_with_r2

        assert callable(_open_binary_with_r2)


class TestAnalyzersBackwardCompatibility:
    """Test suite for backward compatibility via direct imports."""

    def test_all_internal_functions_available(self):
        """Test that internal functions are available from their modules."""
        from bannedfuncdetector.application.binary_analyzer import _validate_binary_input
        from bannedfuncdetector.application.parallel_analyzer import _resolve_thread_count
        from bannedfuncdetector.application.directory_scanner import _validate_directory

        # All internal functions should be callable from their source modules
        assert callable(_validate_binary_input)
        assert callable(_resolve_thread_count)
        assert callable(_validate_directory)


class TestAnalyzersPublicAPINoWarnings:
    """Test that public API imports don't generate warnings."""

    def test_public_imports_no_warnings(self):
        """Test that importing public API doesn't generate warnings."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            from bannedfuncdetector.analyzer_exceptions import AnalyzerError
            from bannedfuncdetector.application.binary_analyzer import (
                analyze_function,
                analyze_binary,
                R2BinaryAnalyzer,
            )
            from bannedfuncdetector.application.directory_scanner import analyze_directory

            # No deprecation warnings for public API
            deprecation_warnings = [
                warning for warning in w
                if issubclass(warning.category, DeprecationWarning)
            ]
            assert len(deprecation_warnings) == 0
