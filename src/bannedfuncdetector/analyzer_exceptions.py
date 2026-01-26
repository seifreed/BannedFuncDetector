#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Analyzer Exceptions

This module defines custom exceptions for the analyzer components.

Author: Marc Rivero | @seifreed
"""


class AnalyzerError(Exception):
    """Base exception for analyzer-related errors."""


class BinaryNotFoundError(AnalyzerError):
    """Raised when a binary file is not found."""


class DirectoryNotFoundError(AnalyzerError):
    """Raised when a directory is not found."""


class DecompilerNotAvailableError(AnalyzerError):
    """Raised when no decompiler is available for analysis."""


class AnalysisError(AnalyzerError):
    """Raised when an error occurs during binary analysis."""


__all__ = [
    "AnalyzerError",
    "BinaryNotFoundError",
    "DirectoryNotFoundError",
    "DecompilerNotAvailableError",
    "AnalysisError",
]
