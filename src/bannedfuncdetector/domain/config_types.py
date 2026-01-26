#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration parameter objects for reducing long function signatures.

This module provides frozen dataclasses that encapsulate groups of related
parameters, replacing long function signatures with cleaner interfaces.

Author: Marc Rivero | @seifreed
"""
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bannedfuncdetector.domain.protocols import IConfigRepository


@dataclass(frozen=True)
class AnalysisOptions:
    """
    Configuration for binary analysis operations.

    This dataclass encapsulates common analysis parameters to reduce
    the number of individual parameters in function signatures.

    Attributes:
        verbose: If True, enables verbose logging output.
        worker_limit: Maximum number of concurrent workers (None for default).
        decompiler_type: Type of decompiler to use (default, r2ghidra, r2dec, decai).
        config: Configuration repository instance for dependency injection.
    """

    verbose: bool = False
    worker_limit: int | None = None
    decompiler_type: str = "default"
    config: "IConfigRepository | None" = None


@dataclass(frozen=True)
class ParallelAnalysisOptions:
    """
    Configuration for parallel analysis operations.

    This dataclass encapsulates parameters specific to parallel processing
    of multiple files or functions.

    Attributes:
        verbose: If True, enables verbose logging output.
        worker_limit: Maximum number of concurrent workers (None for default).
        use_processes: If True, uses ProcessPoolExecutor; otherwise uses threads.
        config: Configuration repository instance for dependency injection.
    """

    verbose: bool = False
    worker_limit: int | None = None
    use_processes: bool = False
    config: "IConfigRepository | None" = None


@dataclass(frozen=True)
class DirectoryAnalysisOptions:
    """
    Configuration for directory scanning and analysis operations.

    This dataclass encapsulates all parameters needed for directory-level
    analysis, combining output settings with analysis options.

    Attributes:
        output_dir: Directory where results should be saved (None to skip).
        decompiler_type: Type of decompiler to use.
        max_workers: Maximum number of parallel workers.
        verbose: If True, enables verbose logging output.
        parallel: If True, uses parallel processing.
        config: Configuration repository instance for dependency injection.
    """

    output_dir: str | None = None
    decompiler_type: str = "default"
    max_workers: int | None = None
    verbose: bool = False
    parallel: bool = True
    config: "IConfigRepository | None" = None


@dataclass(frozen=True)
class BinaryAnalysisOptions:
    """
    Configuration for single binary file analysis.

    This dataclass encapsulates all parameters needed for analyzing
    a single binary file.

    Attributes:
        output_dir: Directory for JSON output (None to skip saving).
        decompiler_type: Type of decompiler to use.
        verbose: If True, enables verbose logging output.
        worker_limit: Maximum number of concurrent workers.
        config: Configuration repository instance for dependency injection.
    """

    output_dir: str | None = None
    decompiler_type: str | None = None
    verbose: bool = False
    worker_limit: int | None = None
    config: "IConfigRepository | None" = None


@dataclass(frozen=True)
class ResolvedAnalysisParams:
    """
    Resolved and validated parameters for binary analysis.

    This dataclass holds the resolved values after parameter validation
    and resolution from either BinaryAnalysisOptions or individual kwargs.

    Attributes:
        output_dir: Directory for JSON output (None to skip saving).
        decompiler_type: Resolved decompiler type (after selection).
        verbose: If True, enables verbose logging output.
        worker_limit: Maximum number of concurrent workers.
        config: Configuration repository instance.
    """

    output_dir: str | None
    decompiler_type: str
    verbose: bool
    worker_limit: int | None
    config: "IConfigRepository"


__all__ = [
    "AnalysisOptions",
    "ParallelAnalysisOptions",
    "DirectoryAnalysisOptions",
    "BinaryAnalysisOptions",
    "ResolvedAnalysisParams",
]
