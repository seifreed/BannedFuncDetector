#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain entities for BannedFuncDetector.

This module contains the core domain entities that represent the business
concepts in the application. These entities are immutable dataclasses
that encapsulate the domain logic.

Author: Marc Rivero | @seifreed
"""

from dataclasses import dataclass

# Categories considered critical from a security perspective
# These involve memory corruption, code execution, or direct system access
CRITICAL_CATEGORIES: frozenset[str] = frozenset([
    "string_copy",
    "string_concat",
    "string_format",
    "string_input",
    "memory",
    "process",
])

# Risk weights by category (higher = more dangerous)
CATEGORY_RISK_WEIGHTS: dict[str, int] = {
    "string_copy": 8,
    "string_concat": 7,
    "string_format": 9,
    "string_input": 10,
    "memory": 8,
    "process": 9,
    "scanf": 7,
    "path_manipulation": 5,
    "string_token": 4,
    "string_search": 3,
    "number_conversion": 3,
    "file": 4,
    "directory": 3,
    "signal": 5,
    "time": 2,
    "environment": 6,
    "user": 4,
    "network": 6,
    "thread": 3,
    "stdio": 2,
}

# Risk weights by detection method (higher = more reliable detection)
DETECTION_METHOD_WEIGHTS: dict[str, int] = {
    "decompilation": 10,
    "import": 8,
    "name_match": 6,
    "string": 4,
}


@dataclass(frozen=True)
class BannedFunction:
    """Represents a detected banned/insecure function."""
    name: str
    address: int
    size: int
    banned_calls: tuple[str, ...]  # tuple for immutability (frozen dataclass requires hashable fields)
    detection_method: str  # 'name_match', 'import', 'string', 'decompilation'
    category: str | None = None

    @property
    def is_critical(self) -> bool:
        """Check if this function belongs to a critical security category."""
        if self.category is None:
            return False
        return self.category in CRITICAL_CATEGORIES

    @property
    def risk_score(self) -> int:
        """
        Calculate risk score based on category and detection method.

        Returns:
            Risk score from 0-100 (higher = more dangerous).
        """
        category_weight = CATEGORY_RISK_WEIGHTS.get(self.category or "", 5)
        method_weight = DETECTION_METHOD_WEIGHTS.get(self.detection_method, 5)
        # Combine weights: category contributes 70%, detection method 30%
        return min(100, int(category_weight * 7 + method_weight * 3))


@dataclass(frozen=True)
class AnalysisResult:
    """Represents the result of analyzing a binary file."""
    file_name: str
    file_path: str
    total_functions: int
    detected_functions: tuple[BannedFunction, ...]  # tuple of BannedFunction (immutable)
    analysis_date: str
    analyzer: str = "BannedFuncDetector - Author: Marc Rivero | @seifreed"

    @property
    def insecure_count(self) -> int:
        return len(self.detected_functions)

    @property
    def has_issues(self) -> bool:
        return self.insecure_count > 0

    @property
    def critical_count(self) -> int:
        """Count of findings in critical categories."""
        return sum(1 for f in self.detected_functions if f.is_critical)

    @property
    def has_critical_issues(self) -> bool:
        """Check if any findings are in critical categories."""
        return any(f.is_critical for f in self.detected_functions)


__all__ = [
    # Constants
    "CRITICAL_CATEGORIES",
    "CATEGORY_RISK_WEIGHTS",
    "DETECTION_METHOD_WEIGHTS",
    # Domain entities
    "BannedFunction",
    "AnalysisResult",
]
