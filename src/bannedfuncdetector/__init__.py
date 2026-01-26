"""BannedFuncDetector - Detect banned/insecure functions in binary files.

Public API:
    - main: CLI entry point
    - analyze_binary: Direct function for single binary analysis
    - analyze_directory: Direct function for directory batch analysis
    - create_binary_analyzer: Factory for creating analyzers
    - create_config_from_file: Load config from JSON file
    - create_config_from_dict: Create config from dictionary
    - BannedFunction: Domain entity for detected functions
    - AnalysisResult: Domain entity for analysis results
"""

from .bannedfunc import main
from .factories import (
    create_binary_analyzer,
    create_config_from_file,
    create_config_from_dict,
)
from .domain.entities import BannedFunction, AnalysisResult
from .application.binary_analyzer import analyze_binary
from .application.directory_scanner import analyze_directory

__all__ = [
    "main",
    "analyze_binary",
    "analyze_directory",
    "create_binary_analyzer",
    "create_config_from_file",
    "create_config_from_dict",
    "BannedFunction",
    "AnalysisResult",
]
