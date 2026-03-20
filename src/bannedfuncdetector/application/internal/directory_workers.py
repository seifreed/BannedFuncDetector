#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Worker creation and rehydration helpers for directory analysis."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from bannedfuncdetector.application.analysis_outcome import BinaryAnalysisOutcome
from bannedfuncdetector.domain.protocols import (
    IConfigRepository,
    IDecompilerOrchestrator,
    IR2Client,
)
from bannedfuncdetector.application.analysis_error import ExecutionFailure
from bannedfuncdetector.domain.result import Result

from ..analysis_runtime import BinaryRuntimeServices
from ..contracts.analysis import AnalysisRuntime, BinaryAnalysisRequest
from .execution_plans import DirectoryWorkerJob


def analyze_binary_job(
    executable_file: str,
    output_dir: str | None,
    decompiler_type: str,
    verbose: bool,
    config: IConfigRepository,
    r2_factory: Callable[[str], IR2Client],
    binary_services: BinaryRuntimeServices,
    decompiler_orchestrator: IDecompilerOrchestrator | None = None,
    force_decompiler: bool = False,
    skip_banned: bool = False,
    skip_analysis: bool = False,
) -> Result[BinaryAnalysisOutcome, ExecutionFailure]:
    """Analyze a single binary file with explicitly injected dependencies."""
    from ..binary_analyzer import analyze_binary

    return analyze_binary(
        executable_file,
        request=BinaryAnalysisRequest(
            output_dir=output_dir,
            decompiler_type=decompiler_type,
            runtime=AnalysisRuntime(
                config=config,
                r2_factory=r2_factory,
                binary=binary_services,
                decompiler_orchestrator=decompiler_orchestrator,
            ),
            verbose=verbose,
            worker_limit=config.get("worker_limit", 10),
            force_decompiler=force_decompiler,
            skip_banned=skip_banned,
            skip_analysis=skip_analysis,
        ),
    )


def serialize_config(config: IConfigRepository) -> dict[str, Any]:
    """Serialize a config repository into a plain dictionary for worker processes."""
    config_dict = config.to_dict()
    if not isinstance(config_dict, dict):
        raise TypeError("IConfigRepository.to_dict() must return a dictionary.")
    return config_dict


def analyze_binary_job_from_worker_payload(
    job: DirectoryWorkerJob,
) -> Result[BinaryAnalysisOutcome, ExecutionFailure]:
    """Recreate per-process dependencies and execute one directory-analysis job."""
    config = job.config_factory(job.config_dict)
    orchestrator = (
        job.orchestrator_factory(config)
        if job.orchestrator_factory is not None
        else None
    )
    binary_services = BinaryRuntimeServices(
        binary_opener=job.binary_opener,
        r2_closer=job.r2_closer,
    )
    return analyze_binary_job(
        job.executable_file,
        job.output_dir,
        job.decompiler_type,
        job.verbose,
        config,
        job.r2_factory,
        binary_services,
        decompiler_orchestrator=orchestrator,
        force_decompiler=job.force_decompiler,
        skip_banned=job.skip_banned,
        skip_analysis=job.skip_analysis,
    )


__all__ = [
    "analyze_binary_job",
    "analyze_binary_job_from_worker_payload",
    "serialize_config",
]
