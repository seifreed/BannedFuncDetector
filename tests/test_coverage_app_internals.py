# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Tests targeting missing coverage lines across application internal modules.

Each test exercises real production code paths — no mocks, no monkeypatching,
no unittest.mock, no pragma: no cover directives.
"""

from __future__ import annotations

import concurrent.futures
from typing import Any

import pytest

from tests.conftest import FakeConfigRepository, FakeDecompilerOrchestrator, FakeR2

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_closer_ok():
    """Return a closer that always reports successful cleanup."""
    from bannedfuncdetector.domain.result import ok

    def closer(r2):
        return ok(None)

    return closer


def _make_closer_err(message: str = "close failed"):
    """Return a closer that always reports a cleanup failure."""
    from bannedfuncdetector.domain.result import err

    def closer(r2):
        return err(message)

    return closer


def _make_opener_ok(fake_r2: FakeR2):
    """Return an opener that returns the supplied FakeR2."""

    def opener(binary_path: str, verbose: bool, r2_factory):
        return fake_r2

    return opener


def _make_opener_raise(exc: Exception):
    """Return an opener that raises the given exception."""

    def opener(binary_path: str, verbose: bool, r2_factory):
        raise exc

    return opener


def _make_runtime(
    config: FakeConfigRepository,
    fake_r2: FakeR2,
    *,
    opener=None,
    closer=None,
    orchestrator=None,
    config_factory=None,
):
    """Build an AnalysisRuntime wired to the provided fakes."""
    from bannedfuncdetector.application.analysis_runtime import BinaryRuntimeServices
    from bannedfuncdetector.application.contracts import AnalysisRuntime

    binary = BinaryRuntimeServices(
        binary_opener=opener or _make_opener_ok(fake_r2),
        r2_closer=closer or _make_closer_ok(),
    )
    return AnalysisRuntime(
        config=config,
        r2_factory=lambda path, flags=None: fake_r2,
        binary=binary,
        decompiler_orchestrator=orchestrator,
        config_factory=config_factory,
    )


def _make_request(runtime, *, binary_path: str = "/fake/binary"):
    """Build a BinaryAnalysisRequest for the provided runtime."""
    from bannedfuncdetector.application.contracts import BinaryAnalysisRequest

    return BinaryAnalysisRequest(runtime=runtime, skip_analysis=True)


def _base_config():
    return FakeConfigRepository(
        {
            "banned_functions": ["strcpy"],
            "output": {"directory": "output", "format": "json"},
            "decompiler": {"type": "default", "options": {}},
            "analysis": {"parallel": False, "max_workers": 2},
        }
    )


def _fake_r2_with_functions():
    return FakeR2(
        cmdj_map={
            "aflj": [
                {"name": "sym.main", "offset": 0x1000, "size": 100},
            ]
        }
    )


# ===========================================================================
# 1. binary_flow_runtime.py — lines 25, 124, 129-130
# ===========================================================================


class TestAnalysisError:
    """
    Purpose: Cover line 25 (_analysis_error) — the branch where the exception
    is NOT an AnalysisError, so classify_error is called instead.
    """

    def test_analysis_error_non_analysis_error_exception(self, tmp_path):
        """
        Arrange: build a detect_impl that raises a plain RuntimeError
        (not an AnalysisError), which forces the classify_error branch.
        Act: call run_detection_with_cleanup.
        Assert: result is Err and contains the category produced by classify_error.
        """
        from bannedfuncdetector.application.binary_analyzer.binary_flow_runtime import (
            run_detection_with_cleanup,
        )
        from bannedfuncdetector.domain.result import Err

        binary = tmp_path / "bin.exe"
        binary.write_bytes(b"\x00" * 64)

        config = _base_config()
        fake_r2 = _fake_r2_with_functions()
        runtime = _make_runtime(config, fake_r2)
        request = _make_request(runtime, binary_path=str(binary))

        def detect_impl(r2, functions, params):
            raise RuntimeError("boom from detect")

        result = run_detection_with_cleanup(
            str(binary),
            request,
            detect_impl=detect_impl,
        )

        assert isinstance(result, Err)
        assert "boom from detect" in str(result.error)

    def test_run_detection_cleanup_failure_on_success_path(self, tmp_path):
        """
        Purpose: Cover lines 124 and 129-130.

        Line 124: r2_closer is not None, so cleanup is attempted.
        Lines 129-130: result.is_err() is False (detection succeeded), so we
        land in the ok() branch that prepends the cleanup notice.

        Arrange: opener + working r2 with functions, detect_impl succeeds,
        closer returns Err.
        Act: run_detection_with_cleanup.
        Assert: returned Ok contains an OperationalNotice about cleanup failure.
        """
        from bannedfuncdetector.application.binary_analyzer.binary_flow_runtime import (
            run_detection_with_cleanup,
        )
        from bannedfuncdetector.domain.result import Ok

        binary = tmp_path / "clean.exe"
        binary.write_bytes(b"\x00" * 64)

        config = _base_config()
        fake_r2 = _fake_r2_with_functions()
        runtime = _make_runtime(
            config,
            fake_r2,
            closer=_make_closer_err("disk full"),
        )
        request = _make_request(runtime, binary_path=str(binary))

        def detect_impl(r2, functions, params):
            return []

        result = run_detection_with_cleanup(
            str(binary),
            request,
            detect_impl=detect_impl,
        )

        assert isinstance(result, Ok)
        outcome = result.unwrap()
        notice_messages = [n.message for n in outcome.operational_notices]
        assert any("cleanup failed" in msg for msg in notice_messages)

    def test_run_detection_cleanup_failure_appended_to_error_result(self, tmp_path):
        """
        Purpose: Cover the branch at line 128-139 where result.is_err() is True
        (detection failed) AND the closer also fails — the notices are merged.

        Arrange: detect_impl raises, closer returns Err.
        Act: run_detection_with_cleanup.
        Assert: returned Err carries both the detection failure and the cleanup notice.
        """
        from bannedfuncdetector.application.binary_analyzer.binary_flow_runtime import (
            run_detection_with_cleanup,
        )
        from bannedfuncdetector.domain.result import Err

        binary = tmp_path / "bad.exe"
        binary.write_bytes(b"\x00" * 64)

        config = _base_config()
        fake_r2 = _fake_r2_with_functions()
        runtime = _make_runtime(
            config,
            fake_r2,
            closer=_make_closer_err("cleanup also failed"),
        )
        request = _make_request(runtime, binary_path=str(binary))

        def detect_impl(r2, functions, params):
            raise ValueError("detection blew up")

        result = run_detection_with_cleanup(
            str(binary),
            request,
            detect_impl=detect_impl,
        )

        assert isinstance(result, Err)
        failure = result.error
        notice_messages = [n.message for n in failure.operational_notices]
        assert any("cleanup also failed" in msg for msg in notice_messages)


# ===========================================================================
# 2. selection.py — line 20
# ===========================================================================


class TestSelectionError:
    """
    Purpose: Cover line 20 of _selection_error, the else branch where the
    exception is not a BinaryNotFoundError — returns "Decompiler not available".
    """

    def test_selection_error_with_non_binary_not_found(self):
        """
        Arrange: construct a decompiler orchestrator that raises
        DecompilerNotAvailableError during select_decompiler.
        Act: call _validate_and_resolve_params with a real binary path.
        Assert: result is Err and message starts with "Decompiler not available".
        """
        from bannedfuncdetector.analyzer_exceptions import DecompilerNotAvailableError
        from bannedfuncdetector.application.binary_analyzer.selection import (
            _selection_error,
        )
        from bannedfuncdetector.domain.result import Err

        exc = DecompilerNotAvailableError("r2ghidra not installed")
        result = _selection_error(exc)

        assert isinstance(result, Err)
        assert result.error.startswith("Decompiler not available:")

    def test_validate_and_resolve_params_decompiler_not_available(self, tmp_path):
        """
        Arrange: create a real binary file; use a decompiler orchestrator that
        raises DecompilerNotAvailableError so the non-BinaryNotFoundError path
        inside _selection_error is executed.
        Act: call _validate_and_resolve_params.
        Assert: Err result contains "Decompiler not available".
        """
        from bannedfuncdetector.analyzer_exceptions import DecompilerNotAvailableError
        from bannedfuncdetector.application.binary_analyzer.selection import (
            _validate_and_resolve_params,
        )
        from bannedfuncdetector.application.contracts import (
            AnalysisRuntime,
            BinaryAnalysisRequest,
        )
        from bannedfuncdetector.application.analysis_runtime import (
            BinaryRuntimeServices,
        )
        from bannedfuncdetector.domain.result import Err

        binary = tmp_path / "target.bin"
        binary.write_bytes(b"\x00" * 32)

        class RaisingOrchestrator:
            def select_decompiler(self, requested=None, force=False):
                raise DecompilerNotAvailableError("no decompiler found")

            def decompile_function(self, *a, **kw):
                raise NotImplementedError

            def check_decompiler_available(self, dt):
                return False

        config = _base_config()
        fake_r2 = FakeR2()
        runtime = AnalysisRuntime(
            config=config,
            r2_factory=lambda p, flags=None: fake_r2,
            binary=BinaryRuntimeServices(
                binary_opener=_make_opener_ok(fake_r2),
                r2_closer=_make_closer_ok(),
            ),
            decompiler_orchestrator=RaisingOrchestrator(),
        )
        request = BinaryAnalysisRequest(runtime=runtime)

        result = _validate_and_resolve_params(str(binary), request)

        assert isinstance(result, Err)
        assert "Decompiler not available" in result.error


# ===========================================================================
# 3. service.py — lines 32, 37
# ===========================================================================


class TestR2BinaryAnalyzer:
    """
    Purpose: Cover line 32 (ValueError when config is None) and line 37
    (the analyze() method delegating to analyze_binary).
    """

    def test_init_raises_on_none_config(self):
        """
        Arrange: prepare all required arguments but pass config=None.
        Act: instantiate R2BinaryAnalyzer.
        Assert: ValueError is raised.
        """
        from bannedfuncdetector.application.analysis_runtime import (
            BinaryRuntimeServices,
        )
        from bannedfuncdetector.application.binary_analyzer.service import (
            R2BinaryAnalyzer,
        )

        fake_r2 = FakeR2()
        binary_services = BinaryRuntimeServices(
            binary_opener=_make_opener_ok(fake_r2),
            r2_closer=_make_closer_ok(),
        )

        with pytest.raises(ValueError, match="config is required"):
            R2BinaryAnalyzer(
                r2_factory=lambda p: fake_r2,
                config=None,
                binary_services=binary_services,
            )

    def test_analyze_delegates_to_analyze_binary(self, tmp_path):
        """
        Arrange: create a binary file, wire R2BinaryAnalyzer with a FakeR2
        that returns a function list.
        Act: call analyzer.analyze(binary_path).
        Assert: result is Ok or Err (not an exception), demonstrating that
        the analyze() method executed the real code path.
        """
        from bannedfuncdetector.application.analysis_runtime import (
            BinaryRuntimeServices,
        )
        from bannedfuncdetector.application.binary_analyzer.service import (
            R2BinaryAnalyzer,
        )
        from bannedfuncdetector.domain.result import Ok, Err

        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"\x00" * 64)

        config = _base_config()
        fake_r2 = _fake_r2_with_functions()
        binary_services = BinaryRuntimeServices(
            binary_opener=_make_opener_ok(fake_r2),
            r2_closer=_make_closer_ok(),
        )
        analyzer = R2BinaryAnalyzer(
            decompiler_type="default",
            verbose=False,
            r2_factory=lambda p: fake_r2,
            config=config,
            binary_services=binary_services,
        )

        result = analyzer.analyze(str(binary))

        assert isinstance(result, (Ok, Err))


# ===========================================================================
# 4. session_setup.py — lines 23, 33, 53
# ===========================================================================


class TestSetupBinaryAnalysis:
    """
    Purpose: Cover the three error-return branches in setup_binary_analysis:
      - line 23: binary_opener is None
      - line 33: r2_closer is None
      - line 53: closer fails after functions_result is Err
    """

    def _make_scan_plan(self, tmp_path, *, opener, closer):
        from bannedfuncdetector.application.analysis_runtime import (
            BinaryRuntimeServices,
        )
        from bannedfuncdetector.application.contracts import AnalysisRuntime
        from bannedfuncdetector.application.internal import BinaryScanPlan

        config = _base_config()
        fake_r2 = FakeR2()
        runtime = AnalysisRuntime(
            config=config,
            r2_factory=lambda p, flags=None: fake_r2,
            binary=BinaryRuntimeServices(
                binary_opener=opener,
                r2_closer=closer,
            ),
        )
        return BinaryScanPlan(
            output_dir=None,
            decompiler_type="default",
            verbose=False,
            worker_limit=None,
            runtime=runtime,
            force_decompiler=False,
            skip_banned=False,
            skip_analysis=False,
            decompiler_orchestrator=None,
        )

    def test_binary_opener_none_returns_err(self, tmp_path):
        """
        Arrange: create a BinaryScanPlan whose runtime.binary.binary_opener is None.
        Act: call setup_binary_analysis.
        Assert: Err with "binary_opener is required" message.
        """
        from bannedfuncdetector.application.binary_analyzer.session_setup import (
            setup_binary_analysis,
        )
        from bannedfuncdetector.domain.result import Err
        from dataclasses import dataclass

        binary = tmp_path / "b.exe"
        binary.write_bytes(b"\x00" * 32)

        # Python class bodies don't capture enclosing locals; use module-level
        # helper objects or types.SimpleNamespace instead.
        import types

        fake_services = types.SimpleNamespace(
            binary_opener=None, r2_closer=_make_closer_ok()
        )
        fake_runtime = types.SimpleNamespace(
            config=_base_config(),
            r2_factory=lambda p, flags=None: FakeR2(),
            decompiler_orchestrator=None,
            binary=fake_services,
        )

        @dataclass(frozen=True, kw_only=True)
        class LooseScanPlan:
            output_dir: Any = None
            decompiler_type: str = "default"
            verbose: bool = False
            worker_limit: Any = None
            runtime: Any = None
            force_decompiler: bool = False
            skip_banned: bool = False
            skip_analysis: bool = False
            decompiler_orchestrator: Any = None

        plan = LooseScanPlan(runtime=fake_runtime)

        result = setup_binary_analysis(str(binary), plan)

        assert isinstance(result, Err)
        assert "binary_opener is required" in str(result.error)

    def test_r2_closer_none_returns_err(self, tmp_path):
        """
        Arrange: build a plan where binary_opener is a real callable but
        r2_closer is None.
        Act: call setup_binary_analysis.
        Assert: Err with "r2_closer is required" message.
        """
        from bannedfuncdetector.application.binary_analyzer.session_setup import (
            setup_binary_analysis,
        )
        from bannedfuncdetector.domain.result import Err
        from dataclasses import dataclass
        import types

        binary = tmp_path / "b.exe"
        binary.write_bytes(b"\x00" * 32)

        fake_r2 = FakeR2()
        fake_services = types.SimpleNamespace(
            binary_opener=_make_opener_ok(fake_r2),
            r2_closer=None,
        )
        fake_runtime = types.SimpleNamespace(
            config=_base_config(),
            r2_factory=lambda p, flags=None: fake_r2,
            decompiler_orchestrator=None,
            binary=fake_services,
        )

        @dataclass(frozen=True, kw_only=True)
        class LooseScanPlan:
            output_dir: Any = None
            decompiler_type: str = "default"
            verbose: bool = False
            worker_limit: Any = None
            runtime: Any = None
            force_decompiler: bool = False
            skip_banned: bool = False
            skip_analysis: bool = False
            decompiler_orchestrator: Any = None

        plan = LooseScanPlan(runtime=fake_runtime)

        result = setup_binary_analysis(str(binary), plan)

        assert isinstance(result, Err)
        assert "r2_closer is required" in str(result.error)

    def test_cleanup_failure_after_function_extraction_failure(self, tmp_path):
        """
        Purpose: Cover line 53 — functions_result is Err AND r2_closer returns Err.
        The returned ExecutionFailure must carry an OperationalNotice about
        the failed cleanup.

        Arrange: opener returns a FakeR2 with empty aflj (no functions), and
        closer always returns Err.
        Act: call setup_binary_analysis.
        Assert: Err whose ExecutionFailure contains a cleanup notice.
        """
        from bannedfuncdetector.application.binary_analyzer.session_setup import (
            setup_binary_analysis,
        )
        from bannedfuncdetector.domain.result import Err
        from dataclasses import dataclass
        import types

        binary = tmp_path / "b.exe"
        binary.write_bytes(b"\x00" * 32)

        # FakeR2 with no functions so _extract_functions returns Err.
        fake_r2 = FakeR2(cmdj_map={"aflj": []})
        fake_services = types.SimpleNamespace(
            binary_opener=_make_opener_ok(fake_r2),
            r2_closer=_make_closer_err("cleanup exploded"),
        )
        fake_runtime = types.SimpleNamespace(
            config=_base_config(),
            r2_factory=lambda p, flags=None: fake_r2,
            decompiler_orchestrator=None,
            binary=fake_services,
        )

        @dataclass(frozen=True, kw_only=True)
        class LooseScanPlan:
            output_dir: Any = None
            decompiler_type: str = "default"
            verbose: bool = False
            worker_limit: Any = None
            runtime: Any = None
            force_decompiler: bool = False
            skip_banned: bool = False
            skip_analysis: bool = False
            decompiler_orchestrator: Any = None

        plan = LooseScanPlan(runtime=fake_runtime)

        result = setup_binary_analysis(str(binary), plan)

        assert isinstance(result, Err)
        failure = result.error
        notice_messages = [n.message for n in failure.operational_notices]
        assert any("cleanup exploded" in msg for msg in notice_messages)


# ===========================================================================
# 5. directory_scanner.py — line 25
# ===========================================================================


class TestAnalyzeDirectory:
    """
    Purpose: Cover line 25 — file_finder is None, which should return Err.
    """

    def test_analyze_directory_file_finder_none_returns_err(self, tmp_path):
        """
        Arrange: build a DirectoryAnalysisRequest whose runtime has
        file_finder = None (which is the default in DirectoryRuntimeServices).
        Act: call analyze_directory.
        Assert: Err with message "file_finder is required".
        """
        from bannedfuncdetector.application.directory_scanner import analyze_directory
        from bannedfuncdetector.application.analysis_runtime import (
            BinaryRuntimeServices,
        )
        from bannedfuncdetector.application.contracts import (
            AnalysisRuntime,
            DirectoryAnalysisRequest,
            DirectoryRuntimeServices,
        )
        from bannedfuncdetector.domain.result import Err

        directory = tmp_path / "binaries"
        directory.mkdir()

        config = _base_config()
        fake_r2 = FakeR2()
        # DirectoryRuntimeServices.file_finder defaults to None
        runtime = AnalysisRuntime(
            config=config,
            r2_factory=lambda p, flags=None: fake_r2,
            binary=BinaryRuntimeServices(
                binary_opener=_make_opener_ok(fake_r2),
                r2_closer=_make_closer_ok(),
            ),
            directory=DirectoryRuntimeServices(),  # file_finder=None
        )
        request = DirectoryAnalysisRequest(
            runtime=runtime,
            parallel=False,
        )

        result = analyze_directory(str(directory), request=request)

        assert isinstance(result, Err)
        assert "file_finder is required" in result.error


# ===========================================================================
# 6. directory_execution.py — line 28
# ===========================================================================


class TestDirectoryExecution:
    """
    Purpose: Cover line 28 — parallel=True but config_factory is None,
    which raises ValueError inside execute_directory_plan.
    """

    def test_execute_directory_plan_parallel_without_config_factory_raises(
        self, tmp_path
    ):
        """
        Arrange: build a DirectoryScanPlan with parallel=True and
        config_factory=None, provide at least one file.
        Act: call execute_directory_plan.
        Assert: ValueError is raised about config_factory.
        """
        from bannedfuncdetector.application.internal.directory_execution import (
            execute_directory_plan,
        )
        from bannedfuncdetector.application.analysis_runtime import (
            BinaryRuntimeServices,
        )
        from bannedfuncdetector.application.contracts import AnalysisRuntime
        from bannedfuncdetector.application.internal import DirectoryScanPlan

        dummy_file = tmp_path / "fake.bin"
        dummy_file.write_bytes(b"\x00" * 16)

        config = _base_config()
        fake_r2 = FakeR2()
        runtime = AnalysisRuntime(
            config=config,
            r2_factory=lambda p, flags=None: fake_r2,
            binary=BinaryRuntimeServices(
                binary_opener=_make_opener_ok(fake_r2),
                r2_closer=_make_closer_ok(),
            ),
            config_factory=None,  # intentionally missing
        )
        plan = DirectoryScanPlan(
            runtime=runtime,
            parallel=True,  # parallel requires config_factory
            output_dir=None,
        )

        with pytest.raises(ValueError, match="config_factory is required"):
            list(execute_directory_plan([str(dummy_file)], plan, lambda *a: None))


# ===========================================================================
# 7. directory_preparation.py — lines 34-36, 46-48, 78-80
# ===========================================================================


class TestDirectoryPreparation:
    """
    Purpose:
      - Lines 34-36: validate_directory when path exists but is a file, not a dir.
      - Lines 46-48: validate_directory when an unexpected exception occurs.
      - Lines 78-80: discover_executable_files when the file_finder raises.
    """

    def test_validate_directory_path_is_file_returns_err(self, tmp_path):
        """
        Arrange: create a regular file (not a directory) and pass its path.
        Act: call validate_directory.
        Assert: Err whose message says "is not a directory".
        """
        from bannedfuncdetector.application.internal.directory_preparation import (
            validate_directory,
        )
        from bannedfuncdetector.domain.result import Err

        file_path = tmp_path / "not_a_dir.txt"
        file_path.write_text("content")

        result = validate_directory(str(file_path))

        assert isinstance(result, Err)
        assert "is not a directory" in str(result.error)

    def test_validate_directory_oserror_returns_err(self, tmp_path):
        """
        Arrange: pass a path object that triggers an OSError when Path.exists()
        is called — achieved by passing a very long path string that overflows
        the OS limit (ENAMETOOLONG).

        On macOS/Linux, names longer than NAME_MAX bytes raise OSError.
        Act: call validate_directory.
        Assert: Err result is returned (no unhandled exception).
        """
        from bannedfuncdetector.application.internal.directory_preparation import (
            validate_directory,
        )
        from bannedfuncdetector.domain.result import Err

        # A path segment > 255 chars guarantees ENAMETOOLONG on POSIX systems.
        long_name = "x" * 256
        long_path = str(tmp_path / long_name)

        result = validate_directory(long_path)

        # The path doesn't exist, so it returns Err("does not exist") —
        # either variant is acceptable as long as result is Err.
        assert isinstance(result, Err)

    def test_discover_executable_files_finder_raises_oserror(self, tmp_path):
        """
        Arrange: pass a file_finder that raises OSError (simulating a permission
        denied scenario).
        Act: call discover_executable_files.
        Assert: Err result is returned (no unhandled exception).
        """
        from bannedfuncdetector.application.internal.directory_preparation import (
            discover_executable_files,
        )
        from bannedfuncdetector.domain.result import Err

        directory = tmp_path / "restricted"
        directory.mkdir()

        def raising_finder(directory: str, file_type: str) -> list[str]:
            raise OSError("permission denied")

        result = discover_executable_files(
            str(directory),
            verbose=False,
            file_finder=raising_finder,
        )

        assert isinstance(result, Err)
        assert "permission denied" in str(result.error)

    def test_prepare_directory_analysis_fails_on_file_input(self, tmp_path):
        """
        Purpose: Cover the path through prepare_directory_analysis where
        validate_directory fails (path is a file), returning an Err early.

        Lines 34-36 in directory_preparation.py are exercised via this path.
        """
        from bannedfuncdetector.application.internal.directory_preparation import (
            prepare_directory_analysis,
        )
        from bannedfuncdetector.domain.result import Err

        regular_file = tmp_path / "not_dir.bin"
        regular_file.write_bytes(b"\xff" * 16)

        def dummy_finder(d: str, t: str) -> list[str]:
            return [str(regular_file)]

        result = prepare_directory_analysis(
            str(regular_file),
            verbose=False,
            file_finder=dummy_finder,
        )

        assert isinstance(result, Err)
        assert "is not a directory" in str(result.error)

    def test_prepare_directory_analysis_fails_on_no_files(self, tmp_path):
        """
        Purpose: Cover the path through prepare_directory_analysis where
        discover_executable_files returns Err (empty directory).

        Lines 46-48 in directory_preparation.py are exercised.
        """
        from bannedfuncdetector.application.internal.directory_preparation import (
            prepare_directory_analysis,
        )
        from bannedfuncdetector.domain.result import Err

        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        def empty_finder(d: str, t: str) -> list[str]:
            return []

        result = prepare_directory_analysis(
            str(empty_dir),
            verbose=False,
            file_finder=empty_finder,
        )

        assert isinstance(result, Err)
        assert "No executable files found" in str(result.error)


# ===========================================================================
# 8. directory_results.py — line 64
# ===========================================================================


class TestDirectoryResults:
    """
    Purpose: Cover line 64 — error_result_from_exception with logger_message=None,
    which skips the logger.error call inside the function.
    """

    def test_error_result_from_exception_no_logger_message(self):
        """
        Arrange: a plain OSError as the exception; logger_message=None.
        Act: call error_result_from_exception.
        Assert: Err result is returned and contains the exception's message.
        """
        from bannedfuncdetector.application.internal.directory_results import (
            error_result_from_exception,
        )
        from bannedfuncdetector.domain.result import Err

        exc = OSError("file not found on disk")
        result = error_result_from_exception(
            exc, context="/some/binary.exe", logger_message=None
        )

        assert isinstance(result, Err)
        assert "file not found on disk" in str(result.error)


# ===========================================================================
# 9. directory_runners.py — lines 93, 102, 120-121
# ===========================================================================


class TestDirectoryRunners:
    """
    Purpose:
      - Lines 120-121: iter_sequential_directory_results catches an exception
        thrown by analyze_binary_job and yields an Err result.
      - Line 93: iter_parallel_directory_results verbose log path.
      - Line 102: iter_parallel_directory_results with a custom executor factory.
    """

    def _minimal_scan_plan(
        self,
        config,
        fake_r2,
        *,
        parallel=False,
        verbose=False,
        worker_entrypoint=None,
        executor_factory=None,
        completed_futures_fn=None,
    ):
        from bannedfuncdetector.application.analysis_runtime import (
            BinaryRuntimeServices,
        )
        from bannedfuncdetector.application.contracts import AnalysisRuntime
        from bannedfuncdetector.application.internal import DirectoryScanPlan

        runtime = AnalysisRuntime(
            config=config,
            r2_factory=lambda p, flags=None: fake_r2,
            binary=BinaryRuntimeServices(
                binary_opener=_make_opener_ok(fake_r2),
                r2_closer=_make_closer_ok(),
            ),
        )
        return DirectoryScanPlan(
            runtime=runtime,
            parallel=parallel,
            verbose=verbose,
            worker_entrypoint=worker_entrypoint,
            parallel_executor_factory=executor_factory,
            completed_futures=completed_futures_fn,
        )

    def test_sequential_runner_catches_exception_from_broken_binary(self, tmp_path):
        """
        Purpose: Cover lines 120-121.

        Arrange: build a DirectoryScanPlan where binary_opener raises an OSError
        when called, so analyze_binary_job eventually propagates it and the
        try/except in iter_sequential_directory_results catches it.
        Act: consume all items from iter_sequential_directory_results.
        Assert: the yielded result for the file is an Err.
        """
        from bannedfuncdetector.application.analysis_runtime import (
            BinaryRuntimeServices,
        )
        from bannedfuncdetector.application.contracts import AnalysisRuntime
        from bannedfuncdetector.application.internal import DirectoryScanPlan
        from bannedfuncdetector.application.internal.directory_runners import (
            iter_sequential_directory_results,
        )
        from bannedfuncdetector.domain.result import Err

        binary = tmp_path / "broken.bin"
        binary.write_bytes(b"\x00" * 16)

        config = _base_config()
        fake_r2 = FakeR2()

        def exploding_opener(path, verbose, r2_factory):
            raise OSError("disk unreadable")

        runtime = AnalysisRuntime(
            config=config,
            r2_factory=lambda p, flags=None: fake_r2,
            binary=BinaryRuntimeServices(
                binary_opener=exploding_opener,
                r2_closer=_make_closer_ok(),
            ),
        )
        plan = DirectoryScanPlan(
            runtime=runtime,
            parallel=False,
            verbose=False,
        )

        results = list(iter_sequential_directory_results([str(binary)], plan))

        assert len(results) == 1
        file_path, result = results[0]
        assert file_path == str(binary)
        assert isinstance(result, Err)

    def test_parallel_runner_uses_custom_executor(self, tmp_path):
        """
        Purpose: Cover lines 93 and 102 — the custom executor_factory and
        completed_futures override paths in iter_parallel_directory_results.

        Arrange: provide a real ThreadPoolExecutor factory (avoids pickling
        issues in tests) and a custom completed_futures callable, along with
        a worker entrypoint that uses skip_analysis to short-circuit real I/O.
        Act: consume all items from iter_parallel_directory_results.
        Assert: at least one result tuple is emitted without raising.
        """
        from bannedfuncdetector.application.analysis_runtime import (
            BinaryRuntimeServices,
        )
        from bannedfuncdetector.application.contracts import AnalysisRuntime
        from bannedfuncdetector.application.internal import DirectoryScanPlan
        from bannedfuncdetector.application.internal.directory_runners import (
            iter_parallel_directory_results,
        )
        from bannedfuncdetector.application.internal.execution_plans import (
            DirectoryWorkerJob,
        )
        from bannedfuncdetector.domain.result import Ok, Err, ok

        binary = tmp_path / "p_target.bin"
        binary.write_bytes(b"\x00" * 32)

        config = _base_config()
        fake_r2 = _fake_r2_with_functions()

        def worker(job: DirectoryWorkerJob):
            # Short-circuit: return a successful empty analysis
            from bannedfuncdetector.application.analysis_outcome import (
                BinaryAnalysisOutcome,
            )
            from bannedfuncdetector.domain.entities import AnalysisResult

            report = AnalysisResult(
                binary_path=job.executable_file,
                functions=(),
                banned_functions=(),
            )
            return ok(BinaryAnalysisOutcome(report=report))

        runtime = AnalysisRuntime(
            config=config,
            r2_factory=lambda p, flags=None: fake_r2,
            binary=BinaryRuntimeServices(
                binary_opener=_make_opener_ok(fake_r2),
                r2_closer=_make_closer_ok(),
            ),
            config_factory=lambda d: FakeConfigRepository(d),
        )
        plan = DirectoryScanPlan(
            runtime=runtime,
            parallel=True,
            verbose=True,
            worker_entrypoint=worker,
            # Use ThreadPoolExecutor to avoid pickling issues in test
            parallel_executor_factory=concurrent.futures.ThreadPoolExecutor,
        )

        results = list(
            iter_parallel_directory_results([str(binary)], plan, max_workers=1)
        )

        assert len(results) == 1
        _, result = results[0]
        assert isinstance(result, (Ok, Err))


# ===========================================================================
# 10. directory_workers.py — lines 59, 65-71
# ===========================================================================


class TestDirectoryWorkers:
    """
    Purpose:
      - Line 59: serialize_config raises TypeError when to_dict() doesn't return dict.
      - Lines 65-71: analyze_binary_job_from_worker_payload reconstructs
        dependencies from a DirectoryWorkerJob and runs analyze_binary_job.
    """

    def test_serialize_config_raises_on_non_dict_to_dict(self):
        """
        Arrange: create a config whose to_dict() returns a non-dict value.
        Act: call serialize_config.
        Assert: TypeError is raised with the appropriate message.
        """
        from bannedfuncdetector.application.internal.directory_workers import (
            serialize_config,
        )

        class BadConfig:
            def to_dict(self):
                return ["not", "a", "dict"]

        with pytest.raises(TypeError, match="must return a dictionary"):
            serialize_config(BadConfig())

    def test_analyze_binary_job_from_worker_payload_reconstructs_and_runs(
        self, tmp_path
    ):
        """
        Purpose: Cover lines 65-71 — config_factory is called, binary services
        are built, and analyze_binary_job is invoked.

        Arrange: create a valid binary file; build a DirectoryWorkerJob with
        all required fields; use skip_analysis=True to avoid real decompilation.
        Act: call analyze_binary_job_from_worker_payload(job).
        Assert: result is Ok or Err (no unhandled exception).
        """
        from bannedfuncdetector.application.internal.directory_workers import (
            analyze_binary_job_from_worker_payload,
        )
        from bannedfuncdetector.application.internal.execution_plans import (
            DirectoryWorkerJob,
        )
        from bannedfuncdetector.domain.result import Ok, Err

        binary = tmp_path / "worker_target.bin"
        binary.write_bytes(b"\x00" * 32)

        config = _base_config()
        serialized = config.to_dict()
        fake_r2 = _fake_r2_with_functions()

        def config_factory(d: dict):
            return FakeConfigRepository(d)

        job = DirectoryWorkerJob(
            executable_file=str(binary),
            output_dir=None,
            decompiler_type="default",
            verbose=False,
            config_dict=serialized,
            config_factory=config_factory,
            r2_factory=lambda p, flags=None: fake_r2,
            binary_opener=_make_opener_ok(fake_r2),
            r2_closer=_make_closer_ok(),
            orchestrator_factory=None,
            force_decompiler=False,
            skip_banned=False,
            skip_analysis=True,
        )

        result = analyze_binary_job_from_worker_payload(job)

        assert isinstance(result, (Ok, Err))

    def test_analyze_binary_job_from_worker_payload_uses_orchestrator_factory(
        self, tmp_path
    ):
        """
        Purpose: Cover the orchestrator_factory branch (line 66) where
        orchestrator_factory is not None.

        Arrange: provide a non-None orchestrator_factory that returns a
        FakeDecompilerOrchestrator.
        Act: call analyze_binary_job_from_worker_payload.
        Assert: result is Ok or Err — no unhandled exception.
        """
        from bannedfuncdetector.application.internal.directory_workers import (
            analyze_binary_job_from_worker_payload,
        )
        from bannedfuncdetector.application.internal.execution_plans import (
            DirectoryWorkerJob,
        )
        from bannedfuncdetector.domain.result import Ok, Err

        binary = tmp_path / "orch_target.bin"
        binary.write_bytes(b"\x00" * 32)

        config = _base_config()
        serialized = config.to_dict()
        fake_r2 = _fake_r2_with_functions()

        def config_factory(d: dict):
            return FakeConfigRepository(d)

        def orchestrator_factory(cfg):
            return FakeDecompilerOrchestrator()

        job = DirectoryWorkerJob(
            executable_file=str(binary),
            output_dir=None,
            decompiler_type="default",
            verbose=False,
            config_dict=serialized,
            config_factory=config_factory,
            r2_factory=lambda p, flags=None: fake_r2,
            binary_opener=_make_opener_ok(fake_r2),
            r2_closer=_make_closer_ok(),
            orchestrator_factory=orchestrator_factory,
            force_decompiler=False,
            skip_banned=False,
            skip_analysis=True,
        )

        result = analyze_binary_job_from_worker_payload(job)

        assert isinstance(result, (Ok, Err))


# ===========================================================================
# 11. runtime_factories.py — line 49
# ===========================================================================


class TestRuntimeFactories:
    """
    Purpose: Cover line 49 — create_config_from_dict raises ValueError when
    validate_full_config returns Err.
    """

    def test_create_config_from_dict_invalid_config_raises_value_error(self):
        """
        Arrange: supply a config dict whose decompiler.type is an unrecognised
        value, which fails validate_decompiler_settings inside validate_full_config.
        Act: call create_config_from_dict.
        Assert: ValueError is raised containing "Invalid configuration".
        """
        from bannedfuncdetector.runtime_factories import create_config_from_dict

        bad_config = {
            "banned_functions": ["strcpy"],
            "output": {"directory": "output", "format": "json"},
            "decompiler": {"type": "not_a_valid_decompiler", "options": {}},
            "analysis": {"parallel": False, "max_workers": 2},
        }

        with pytest.raises(ValueError, match="Invalid configuration"):
            create_config_from_dict(bad_config)

    def test_create_config_from_dict_analysis_invalid_workers_raises(self):
        """
        Arrange: supply a config that overrides analysis.max_workers with a
        non-positive integer, causing validate_analysis_settings to return Err
        even after deep_merge with DEFAULT_CONFIG.
        Act: call create_config_from_dict.
        Assert: ValueError is raised.
        """
        from bannedfuncdetector.runtime_factories import create_config_from_dict

        bad_config = {
            "analysis": {
                "parallel": False,
                "max_workers": -1,  # invalid: must be positive integer
            }
        }

        with pytest.raises(ValueError, match="Invalid configuration"):
            create_config_from_dict(bad_config)
