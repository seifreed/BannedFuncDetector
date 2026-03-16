#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Internal execution structures and helpers for application use cases."""

from .directory_preparation import (
    discover_executable_files,
    prepare_directory_analysis,
    validate_directory,
)
from .directory_results import (
    collect_directory_results,
    handle_directory_future,
    persist_directory_summary,
)
from .directory_runners import (
    iter_parallel_directory_results,
    iter_sequential_directory_results,
)
from .directory_workers import (
    analyze_binary_job,
    analyze_binary_job_from_worker_payload,
    serialize_config,
)
from .execution_plans import (
    FunctionScanPlan,
    ParallelWorkPlan,
    DirectoryScanPlan,
    BinaryScanPlan,
    DirectoryWorkerJob,
)

__all__ = [
    "discover_executable_files",
    "prepare_directory_analysis",
    "validate_directory",
    "collect_directory_results",
    "handle_directory_future",
    "persist_directory_summary",
    "iter_parallel_directory_results",
    "iter_sequential_directory_results",
    "analyze_binary_job",
    "analyze_binary_job_from_worker_payload",
    "serialize_config",
    "FunctionScanPlan",
    "ParallelWorkPlan",
    "DirectoryScanPlan",
    "BinaryScanPlan",
    "DirectoryWorkerJob",
]
