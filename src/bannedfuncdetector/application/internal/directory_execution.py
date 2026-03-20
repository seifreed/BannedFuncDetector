#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Directory-analysis plan coordinator."""

import os
from collections.abc import Callable

from bannedfuncdetector.application.analysis_outcome import DirectoryAnalysisOutcome
from bannedfuncdetector.domain import AnalysisResult, DirectoryAnalysisSummary
from bannedfuncdetector.application.analysis_outcome import OperationalNotice

from .directory_results import collect_directory_results, persist_directory_summary
from .directory_runners import (
    iter_parallel_directory_results,
    iter_sequential_directory_results,
)
from .execution_plans import DirectoryScanPlan


def execute_directory_plan(
    executable_files: list[str],
    options: DirectoryScanPlan,
    on_result: Callable[[str, AnalysisResult, bool], None],
) -> tuple[list[AnalysisResult], tuple[OperationalNotice, ...]]:
    config = options.runtime.config
    config_factory = options.runtime.config_factory
    if options.parallel and config_factory is None:
        raise ValueError("config_factory is required for directory analysis")

    max_workers = (
        options.max_workers
        if options.max_workers is not None
        else config.get("max_workers", 4)
    )

    if options.parallel:
        result_iter = iter_parallel_directory_results(
            executable_files,
            options,
            max_workers,
        )
    else:
        result_iter = iter_sequential_directory_results(
            executable_files,
            options,
        )

    return collect_directory_results(result_iter, options.verbose, on_result)


def build_directory_summary(
    directory: str,
    executable_files: list[str],
    results: list[AnalysisResult],
) -> DirectoryAnalysisSummary:
    return DirectoryAnalysisSummary(
        directory=directory,
        analyzed_results=tuple(results),
        total_files=len(executable_files),
    )


def run_directory_analysis(
    directory: str,
    executable_files: list[str],
    options: DirectoryScanPlan,
    on_result: Callable[[str, AnalysisResult, bool], None],
) -> DirectoryAnalysisOutcome:
    if options.output_dir:
        os.makedirs(options.output_dir, exist_ok=True)
    results, notices = execute_directory_plan(executable_files, options, on_result)
    summary = build_directory_summary(directory, executable_files, results)
    outcome = DirectoryAnalysisOutcome(summary=summary, operational_notices=notices)
    if options.output_dir:
        persist_directory_summary(options.output_dir, outcome, options.verbose)
    return outcome


__all__ = [
    "build_directory_summary",
    "execute_directory_plan",
    "persist_directory_summary",
    "run_directory_analysis",
]
