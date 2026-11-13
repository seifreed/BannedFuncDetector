# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression test: parallel directory analysis must be serializable.

Parallel mode submits a DirectoryWorkerJob to a ProcessPoolExecutor, which
serializes it with the standard library's object serializer. A previous
regression used a local lambda for `orchestrator_factory`, which cannot be
serialized, so `--parallel` crashed at runtime even though the in-process
tests (which use a fake executor) passed. This test serializes the real
application wiring the way the process pool does.
"""

from __future__ import annotations

import functools
import logging
import pickle

from bannedfuncdetector.factories import create_application_wiring


def _logging_worker(job):
    from bannedfuncdetector.application.analysis_error import (
        BinaryExecutionError,
        ExecutionFailure,
    )
    from bannedfuncdetector.domain.result import err

    worker_logger = logging.getLogger("test.process_worker")
    worker_logger.warning("worker completed %s", job.executable_file)
    try:
        raise RuntimeError("worker diagnostic")
    except RuntimeError:
        worker_logger.exception("worker failed safely")
    return err(
        ExecutionFailure(
            error=BinaryExecutionError(
                category="Test", context=job.executable_file, message="logged"
            )
        )
    )


def test_application_wiring_orchestrator_factory_is_serializable() -> None:
    wiring = create_application_wiring()

    # Round-trips through the same serializer the process pool uses.
    restored = pickle.loads(pickle.dumps(wiring.orchestrator_factory))

    assert restored is wiring.orchestrator_factory


def test_application_wiring_parallel_handoff_fields_serialize() -> None:
    """Every wiring field a worker job carries across processes must serialize."""
    wiring = create_application_wiring()

    for value in (
        wiring.orchestrator_factory,
        wiring.config_factory,
        wiring.r2_factory,
        wiring.binary.r2_closer,
        wiring.directory.file_finder,
    ):
        # Top-level callables pickle by reference; a closure/lambda would raise.
        assert pickle.loads(pickle.dumps(value)) is value

    # binary_opener binds the config-derived anal.timeout via functools.partial,
    # which serializes to an equivalent (not identical) object. It must still
    # survive the round-trip with its function and bound keywords intact.
    opener = wiring.binary.binary_opener
    assert isinstance(opener, functools.partial)
    restored = pickle.loads(pickle.dumps(opener))
    assert restored.func is opener.func
    assert restored.keywords == opener.keywords


def test_default_orchestrator_factory_builds_orchestrator() -> None:
    """The top-level factory rebuilds a working orchestrator from a config."""
    from bannedfuncdetector.domain.protocols import IDecompilerOrchestrator
    from bannedfuncdetector.runtime_factories import (
        _default_orchestrator_factory,
        create_config_from_dict,
    )

    config = create_config_from_dict({})
    orchestrator = _default_orchestrator_factory(config)

    assert isinstance(orchestrator, IDecompilerOrchestrator)


def test_process_workers_forward_logs_to_parent_with_request_context(
    monkeypatch, caplog
) -> None:
    from bannedfuncdetector.application.internal.directory_runners import (
        iter_parallel_directory_results,
    )
    from bannedfuncdetector.application.internal.execution_plans import (
        DirectoryScanPlan,
    )
    import bannedfuncdetector.application.internal.directory_runners as runners

    runtime = create_application_wiring()
    monkeypatch.setattr(runners, "ensure_request_id", lambda: "test-run-id")
    caplog.set_level(logging.WARNING, logger="test.process_worker")
    plan = DirectoryScanPlan(
        runtime=runtime,
        worker_entrypoint=_logging_worker,
    )

    results = list(
        iter_parallel_directory_results(
            ["first.bin", "second.bin"], plan, max_workers=2
        )
    )

    assert len(results) == 2
    worker_logs = [
        record for record in caplog.records if record.name == "test.process_worker"
    ]
    assert len(worker_logs) == 4
    assert {record.request_id for record in worker_logs} == {"test-run-id"}
    stack_traces = [getattr(record, "stack_trace", None) for record in worker_logs]
    assert sum(trace is not None for trace in stack_traces) == 2
    assert all("worker diagnostic" in trace for trace in stack_traces if trace)


def test_process_log_listener_with_inline_executor(monkeypatch, caplog) -> None:
    from concurrent.futures import Future

    from bannedfuncdetector.application.internal.directory_runners import (
        iter_parallel_directory_results,
    )
    from bannedfuncdetector.application.internal.execution_plans import (
        DirectoryScanPlan,
    )
    import bannedfuncdetector.application.internal.directory_runners as runners

    class InlineProcessExecutor:
        def __init__(self, *, max_workers, initializer, initargs):
            self.previous_handlers = logging.getLogger().handlers[:]
            self.previous_level = logging.getLogger().level
            initializer(*initargs)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            logging.getLogger().handlers[:] = self.previous_handlers
            logging.getLogger().setLevel(self.previous_level)

        def submit(self, worker, job):
            future = Future()
            future.set_result(worker(job))
            return future

    monkeypatch.setattr(
        runners.concurrent.futures, "ProcessPoolExecutor", InlineProcessExecutor
    )
    monkeypatch.setattr(runners, "ensure_request_id", lambda: "inline-run")
    caplog.set_level(logging.WARNING, logger="test.process_worker")
    plan = DirectoryScanPlan(
        runtime=create_application_wiring(),
        worker_entrypoint=_logging_worker,
    )

    results = list(iter_parallel_directory_results(["inline.bin"], plan, 1))

    assert len(results) == 1
    assert any(
        record.name == "test.process_worker" and record.request_id == "inline-run"
        for record in caplog.records
    )
