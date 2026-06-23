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

import pickle

from bannedfuncdetector.factories import create_application_wiring


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
        wiring.binary.binary_opener,
        wiring.binary.r2_closer,
        wiring.directory.file_finder,
    ):
        # Raises PicklingError if a closure/lambda sneaks back in.
        assert pickle.loads(pickle.dumps(value)) is value


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
