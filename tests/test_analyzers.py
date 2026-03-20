import json
import os

import pytest
import bannedfuncdetector.application.binary_analyzer as analyzers
from bannedfuncdetector.application.analysis_outcome import BinaryAnalysisOutcome
import bannedfuncdetector.application.binary_analyzer.binary_flow_runtime as binary_flow_runtime
import bannedfuncdetector.application.binary_analyzer.session_setup as analyzer_session_setup
import bannedfuncdetector.application.binary_analyzer.selection as analyzer_selection
import bannedfuncdetector.application.directory_scanner as directory_scanner
from bannedfuncdetector.domain.result import Ok, ok
from bannedfuncdetector.infrastructure.adapters.r2_session import (
    close_r2_client,
    open_binary_with_r2,
)
from bannedfuncdetector.analyzer_exceptions import TransientR2Error
from bannedfuncdetector.application.analysis_runtime import BinaryRuntimeServices
from bannedfuncdetector.application.contracts import (
    BinaryAnalysisRequest,
    FunctionAnalysisRequest,
    AnalysisRuntime,
    DirectoryRuntimeServices,
    DirectoryAnalysisRequest,
)
from bannedfuncdetector.application.dto_mappers import function_descriptor_from_dto
from bannedfuncdetector.factories import create_config_from_dict
from bannedfuncdetector.runtime_factories import (
    _default_binary_opener,
    _default_r2_closer,
    _default_file_finder,
)
from bannedfuncdetector.domain import AnalysisResult, BannedFunction
from conftest import FakeDecompilerOrchestrator, open_r2pipe_with_retry

analyzers.analyze_directory = directory_scanner.analyze_directory


def _default_binary_services():
    return BinaryRuntimeServices(
        binary_opener=_default_binary_opener,
        r2_closer=_default_r2_closer,
    )


def make_config():
    return create_config_from_dict({"decompiler": {"type": "default"}})


def fake_r2_factory(binary_path: str):
    return open_r2pipe_with_retry(binary_path, flags=["-2"])


def make_runtime(**kwargs):
    config = make_config()
    if "binary" not in kwargs:
        kwargs["binary"] = _default_binary_services()
    if "directory" not in kwargs:
        kwargs["directory"] = DirectoryRuntimeServices(file_finder=_default_file_finder)
    return AnalysisRuntime(
        config=config,
        config_factory=create_config_from_dict,
        r2_factory=fake_r2_factory,
        **kwargs,
    )


def make_binary_request(runtime: AnalysisRuntime | None = None, **kwargs):
    return BinaryAnalysisRequest.for_runtime(runtime or make_runtime(), **kwargs)


def make_directory_request(runtime: AnalysisRuntime | None = None, **kwargs):
    return DirectoryAnalysisRequest.for_runtime(runtime or make_runtime(), **kwargs)


class StaticDecompilerOrchestrator:
    def __init__(self, code: str = "", *, should_raise: bool = False):
        self.code = code
        self.should_raise = should_raise

    def decompile_function(self, r2, func_name, decompiler_type):
        if self.should_raise:
            raise RuntimeError("boom")
        return ok(self.code)

    def select_decompiler(self, requested=None, force=False):
        return requested or "default"

    def check_decompiler_available(self, decompiler_type):
        return True


class ImmediateFuture:
    def __init__(self, *, value=None, exception: Exception | None = None):
        self._value = value
        self._exception = exception

    def result(self):
        if self._exception is not None:
            raise self._exception
        return self._value


class ImmediateProcessPoolExecutor:
    def __init__(self, *_args, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def submit(self, fn, *args, **kwargs):
        try:
            return ImmediateFuture(value=fn(*args, **kwargs))
        except Exception as exc:
            return ImmediateFuture(exception=exc)


def identity_completed_futures(futures):
    return futures


def test_analyze_function_detect_by_name():
    fake_func = function_descriptor_from_dto({"name": "strcpy", "offset": 4096})
    result = analyzers.analyze_function(
        None,
        fake_func,
        request=FunctionAnalysisRequest(
            runtime=make_runtime(),
            banned_functions={"strcpy"},
            decompiler_type="default",
            verbose=True,
        ),
    )
    assert result.is_ok()
    assert result.unwrap().detection_method == "name"


def test_analyze_function_decompile_no_match(compiled_binary):
    r2 = open_r2pipe_with_retry(compiled_binary, flags=["-2"])
    try:
        r2.cmd("aaa")
        functions = r2.cmdj("aflj")
        result = analyzers.analyze_function(
            r2,
            function_descriptor_from_dto(functions[0]),
            request=FunctionAnalysisRequest(
                runtime=make_runtime(),
                banned_functions={"nonexistent"},
                decompiler_type="default",
            ),
        )
        # When no banned functions found, returns Err
        assert result.is_err()
    finally:
        r2.quit()


def test_analyze_function_decompile_empty():
    """Test that empty decompilation results in Err (no banned functions found)."""
    func = function_descriptor_from_dto({"name": "f", "offset": 1})
    result = analyzers.analyze_function(
        None,
        func,
        request=FunctionAnalysisRequest(
            runtime=AnalysisRuntime(
                config=make_config(),
                config_factory=create_config_from_dict,
                r2_factory=fake_r2_factory,
                binary=_default_binary_services(),
                decompiler_orchestrator=FakeDecompilerOrchestrator(
                    decompile_result=ok("")
                ),
            ),
            banned_functions={"strcpy"},
        ),
    )
    # When decompilation is empty, returns Err (no banned functions found)
    assert result.is_err()


def test_analyze_binary_and_output(compiled_binary, tmp_path):
    output_dir = tmp_path / "out"
    result = analyzers.analyze_binary(
        compiled_binary,
        request=make_binary_request(
            output_dir=str(output_dir),
            decompiler_type="r2ghidra",
            worker_limit=1,
        ),
    )
    assert result.is_ok()
    output_file = (
        output_dir / f"{os.path.basename(compiled_binary)}_banned_functions.json"
    )
    assert output_file.exists()
    data = json.loads(output_file.read_text())
    assert data["total_functions"] >= 1


def test_analyze_binary_verbose_output(compiled_binary, tmp_path):
    output_dir = tmp_path / "out"
    result = analyzers.analyze_binary(
        compiled_binary,
        request=make_binary_request(
            output_dir=str(output_dir),
            decompiler_type="default",
            verbose=True,
        ),
    )
    assert result.is_ok()


def test_analyze_binary_missing_file(tmp_path):
    result = analyzers.analyze_binary(
        str(tmp_path / "missing.bin"), request=make_binary_request()
    )
    assert result.is_err()
    assert "not found" in str(result.error).lower()


def test_setup_binary_analysis_preserves_extract_error(compiled_binary):
    class DummyR2:
        def cmd(self, _command):
            return ""

        def cmdj(self, _command):
            raise RuntimeError("boom")

        def quit(self):
            pass

    runtime = AnalysisRuntime(
        config=make_config(),
        config_factory=create_config_from_dict,
        r2_factory=lambda _path: DummyR2(),
        binary=BinaryRuntimeServices(
            binary_opener=lambda path, verbose, r2_factory: r2_factory(path),
            r2_closer=_default_r2_closer,
        ),
    )
    params = analyzer_selection._validate_and_resolve_params(
        compiled_binary,
        BinaryAnalysisRequest(
            runtime=runtime,
        ),
    ).unwrap()

    result = analyzer_session_setup.setup_binary_analysis(
        compiled_binary,
        params,
    )

    assert result.is_err()
    assert str(
        result.error
    ) == "Runtime error for {}: Runtime error extracting functions from binary: boom".format(
        compiled_binary
    )


def test_open_binary_with_r2_retries_transient_open_failure(compiled_binary):
    class DummyR2:
        def cmd(self, _command):
            return ""

    attempts = {"count": 0}

    def flaky_factory(_binary_path):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise BrokenPipeError("transient")
        return DummyR2()

    result = open_binary_with_r2(
        compiled_binary,
        r2_factory=flaky_factory,
    )

    assert isinstance(result, DummyR2)
    assert attempts["count"] == 2


def test_open_binary_with_r2_retries_transient_initial_analysis_failure(
    compiled_binary,
):
    import errno

    class DummyR2:
        def __init__(self, should_fail: bool):
            self.should_fail = should_fail

        def cmd(self, command):
            if command == "aaa" and self.should_fail:
                raise OSError(errno.EPIPE, "broken pipe")
            return ""

        def quit(self):
            return None

    attempts = {"count": 0}

    def flaky_factory(_binary_path):
        attempts["count"] += 1
        return DummyR2(should_fail=attempts["count"] == 1)

    result = open_binary_with_r2(
        compiled_binary,
        r2_factory=flaky_factory,
    )

    assert isinstance(result, DummyR2)
    assert attempts["count"] == 2


def test_open_binary_with_r2_does_not_retry_non_transient_runtime_error(
    compiled_binary,
):
    attempts = {"count": 0}

    def failing_factory(_binary_path):
        attempts["count"] += 1
        raise RuntimeError("permanent setup failure")

    with pytest.raises(RuntimeError, match="permanent setup failure"):
        open_binary_with_r2(
            compiled_binary,
            r2_factory=failing_factory,
        )

    assert attempts["count"] == 1


def test_open_binary_with_r2_retries_explicit_transient_r2_error(compiled_binary):
    class DummyR2:
        def cmd(self, _command):
            return ""

    attempts = {"count": 0}

    def flaky_factory(_binary_path):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise TransientR2Error("transient r2 startup")
        return DummyR2()

    result = open_binary_with_r2(
        compiled_binary,
        r2_factory=flaky_factory,
    )

    assert isinstance(result, DummyR2)
    assert attempts["count"] == 2


def test_analyze_binary_reports_real_finalization_errors(compiled_binary, tmp_path):
    output_target = tmp_path / "not_a_directory"
    output_target.write_text("occupied")

    result = analyzers.analyze_binary(
        compiled_binary,
        request=make_binary_request(
            output_dir=str(output_target),
            decompiler_type="default",
            worker_limit=1,
        ),
    )

    assert result.is_err()
    assert "while finalizing analysis" in str(result.error)


def test_run_detection_with_cleanup_surfaces_cleanup_failure(compiled_binary):
    class DummyR2:
        def cmd(self, _command):
            return ""

        def cmdj(self, _command):
            return [{"name": "main", "offset": 0x1000}]

        def quit(self):
            raise RuntimeError("close boom")

    params = analyzer_selection._validate_and_resolve_params(
        compiled_binary,
        BinaryAnalysisRequest(
            runtime=AnalysisRuntime(
                config=make_config(),
                config_factory=create_config_from_dict,
                r2_factory=lambda _path: DummyR2(),
                binary=BinaryRuntimeServices(
                    binary_opener=lambda path, verbose, r2_factory: r2_factory(path),
                    r2_closer=close_r2_client,
                ),
            ),
        ),
    ).unwrap()

    result = binary_flow_runtime.run_detection_with_cleanup(
        compiled_binary,
        BinaryAnalysisRequest(
            runtime=params.runtime,
            output_dir=None,
            decompiler_type=None,
            verbose=False,
        ),
        detect_impl=lambda _r2, _functions, _params: [],
    )

    assert result.is_ok()
    assert result.unwrap().operational_notices
    assert "cleanup failed" in result.unwrap().operational_notices[0].message
    assert result.unwrap().operational_notices[0].file_path == compiled_binary


def test_analyze_binary_accepts_runtime(tmp_path):
    result = analyzers.analyze_binary(
        str(tmp_path / "missing.bin"), request=make_binary_request()
    )
    assert result.is_err()
    assert "not found" in str(result.error).lower()


def test_analyze_directory_missing(tmp_path):
    result = analyzers.analyze_directory(
        str(tmp_path / "missing"), request=make_directory_request()
    )
    assert result.is_err()
    assert "does not exist" in str(result.error).lower()


def test_analyze_directory_accepts_runtime(tmp_path):
    result = analyzers.analyze_directory(
        str(tmp_path / "missing"), request=make_directory_request()
    )
    assert result.is_err()
    assert "does not exist" in str(result.error).lower()


def test_analyze_directory_no_pe(tmp_path):
    (tmp_path / "note.txt").write_text("hi")
    result = analyzers.analyze_directory(
        str(tmp_path), request=make_directory_request()
    )
    assert result.is_err()
    # Error message may say "no pe files" or "no executable files"
    error_lower = str(result.error).lower()
    assert "no pe files" in error_lower or "no executable" in error_lower


def test_analyze_directory_with_pe(pe_file, tmp_path):
    # Move PE file into directory
    dest = tmp_path / "sample.exe"
    os.rename(pe_file, dest)
    result = analyzers.analyze_directory(
        str(tmp_path),
        request=make_directory_request(
            output_dir=str(tmp_path / "out"),
            max_workers=1,
        ),
    )
    assert result.is_ok()
    assert result.unwrap().summary.total_files == 1


def test_analyze_directory_verbose_success(tmp_path, pe_file):
    dest = tmp_path / "sample.exe"
    os.rename(pe_file, dest)

    def successful_worker(job):
        return Ok(
            BinaryAnalysisOutcome(
                report=AnalysisResult(
                    file_name=os.path.basename(job.executable_file),
                    file_path=job.executable_file,
                    total_functions=1,
                    detected_functions=tuple(),
                    analysis_date="2026-03-11T00:00:00",
                )
            )
        )

    result = analyzers.analyze_directory(
        str(tmp_path),
        request=make_directory_request(
            output_dir=str(tmp_path / "out"),
            max_workers=1,
            verbose=True,
            runtime=make_runtime(
                directory=DirectoryRuntimeServices(
                    file_finder=_default_file_finder,
                    worker_entrypoint=successful_worker,
                    executor_factory=ImmediateProcessPoolExecutor,
                    completed_futures=identity_completed_futures,
                ),
            ),
        ),
    )
    assert result.is_ok()
    assert result.unwrap().summary.analyzed_files == 1


def test_analyze_function_exception():
    """Test that exceptions during decompilation return Err."""
    result = analyzers.analyze_function(
        None,
        function_descriptor_from_dto({"name": "f", "offset": 1}),
        request=FunctionAnalysisRequest(
            runtime=AnalysisRuntime(
                config=make_config(),
                config_factory=create_config_from_dict,
                r2_factory=fake_r2_factory,
                binary=_default_binary_services(),
                decompiler_orchestrator=FakeDecompilerOrchestrator(
                    decompile_result=RuntimeError("boom"),
                ),
            ),
            banned_functions=set(),
            verbose=True,
        ),
    )
    # When an exception occurs, returns Err
    assert result.is_err()


def test_analyze_function_decompile_match():
    """Test that banned functions in decompiled code are detected."""
    func = function_descriptor_from_dto({"name": "f", "offset": 1})
    result = analyzers.analyze_function(
        None,
        func,
        request=FunctionAnalysisRequest(
            runtime=AnalysisRuntime(
                config=make_config(),
                config_factory=create_config_from_dict,
                r2_factory=fake_r2_factory,
                binary=_default_binary_services(),
                decompiler_orchestrator=FakeDecompilerOrchestrator(
                    decompile_result=ok("strcpy(")
                ),
            ),
            banned_functions={"strcpy"},
            verbose=True,
        ),
    )
    assert result.is_ok()
    assert result.unwrap().detection_method == "decompilation"


def test_analyze_binary_no_decompiler(tmp_path):
    """Test binary analysis when decompiler selection uses default fallback."""
    temp_file = tmp_path / "bin"
    temp_file.write_text("data")

    class DummyR2:
        def cmd(self, _):
            return None

        def cmdj(self, _):
            return None

        def quit(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    result = analyzers.analyze_binary(
        str(temp_file),
        request=BinaryAnalysisRequest(
            runtime=AnalysisRuntime(
                config=make_config(),
                r2_factory=lambda *_args, **_kwargs: DummyR2(),
                binary=BinaryRuntimeServices(
                    binary_opener=lambda path, verbose, r2_factory: r2_factory(path),
                    r2_closer=close_r2_client,
                ),
                decompiler_orchestrator=FakeDecompilerOrchestrator(
                    decompile_result=ok("")
                ),
            ),
            decompiler_type="r2ghidra",
            verbose=True,
        ),
    )
    # When no functions are found, result is Err
    assert result.is_err()


def test_analyze_binary_no_functions(tmp_path):
    """Test binary analysis when no functions are found."""
    temp_file = tmp_path / "bin"
    temp_file.write_text("data")

    class DummyR2:
        def cmd(self, _):
            return None

        def cmdj(self, _):
            return None

        def quit(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    result = analyzers.analyze_binary(
        str(temp_file),
        request=BinaryAnalysisRequest(
            runtime=AnalysisRuntime(
                config=make_config(),
                r2_factory=lambda *_args, **_kwargs: DummyR2(),
                binary=BinaryRuntimeServices(
                    binary_opener=lambda path, verbose, r2_factory: r2_factory(path),
                    r2_closer=close_r2_client,
                ),
                decompiler_orchestrator=FakeDecompilerOrchestrator(
                    decompile_result=ok("")
                ),
            ),
            verbose=True,
        ),
    )
    # When no functions are found, result is Err
    assert result.is_err()


def test_analyze_binary_worker_error(compiled_binary):
    def failing_parallel_executor(*_args, **_kwargs):
        raise RuntimeError("boom")

    result = analyzers.analyze_binary(
        compiled_binary,
        request=make_binary_request(
            verbose=True,
            worker_limit=1,
            parallel_executor=failing_parallel_executor,
        ),
    )
    assert result.is_err()


def test_analyze_binary_verbose_result(compiled_binary):
    detection = BannedFunction(
        name="f",
        address=0x1,
        size=0,
        banned_calls=("strcpy",),
        detection_method="decompilation",
    )

    def successful_parallel_executor(*_args, **_kwargs):
        return [detection]

    result = analyzers.analyze_binary(
        compiled_binary,
        request=make_binary_request(
            verbose=True,
            worker_limit=1,
            parallel_executor=successful_parallel_executor,
        ),
    )
    assert result.is_ok()


def test_analyze_binary_exception(tmp_path):
    """Test that R2 client exceptions return Err."""
    temp_file = tmp_path / "bin"
    temp_file.write_text("data")

    def raise_error(*_args, **_kwargs):
        raise RuntimeError("boom")

    result = analyzers.analyze_binary(
        str(temp_file),
        request=BinaryAnalysisRequest(
            runtime=AnalysisRuntime(
                config=make_config(),
                r2_factory=raise_error,
                binary=BinaryRuntimeServices(
                    binary_opener=lambda path, verbose, r2_factory: r2_factory(path),
                    r2_closer=close_r2_client,
                ),
                decompiler_orchestrator=FakeDecompilerOrchestrator(
                    decompile_result=ok("")
                ),
            ),
        ),
    )
    # Now returns Err instead of raising AnalysisError
    assert result.is_err()


def test_analyze_directory_verbose_error(tmp_path, pe_file):
    dest = tmp_path / "sample.exe"
    os.rename(pe_file, dest)

    def failing_worker(_job):
        raise RuntimeError("boom")

    result = analyzers.analyze_directory(
        str(tmp_path),
        request=make_directory_request(
            output_dir=str(tmp_path / "out"),
            max_workers=1,
            verbose=True,
            runtime=make_runtime(
                directory=DirectoryRuntimeServices(
                    file_finder=_default_file_finder,
                    worker_entrypoint=failing_worker,
                    executor_factory=ImmediateProcessPoolExecutor,
                    completed_futures=identity_completed_futures,
                ),
            ),
        ),
    )
    assert result.is_ok()
    assert result.unwrap().summary.total_files == 1


def test_analyze_directory_default_workers(tmp_path, pe_file):
    dest = tmp_path / "sample.exe"
    os.rename(pe_file, dest)

    def successful_worker(job):
        return Ok(
            BinaryAnalysisOutcome(
                report=AnalysisResult(
                    file_name=os.path.basename(job.executable_file),
                    file_path=job.executable_file,
                    total_functions=1,
                    detected_functions=tuple(),
                    analysis_date="2026-03-11T00:00:00",
                )
            )
        )

    result = analyzers.analyze_directory(
        str(tmp_path),
        request=make_directory_request(
            output_dir=str(tmp_path / "out"),
            max_workers=None,
            runtime=make_runtime(
                directory=DirectoryRuntimeServices(
                    file_finder=_default_file_finder,
                    worker_entrypoint=successful_worker,
                    executor_factory=ImmediateProcessPoolExecutor,
                    completed_futures=identity_completed_futures,
                ),
            ),
        ),
    )
    assert result.is_ok()
    assert result.unwrap().summary.total_files == 1


def test_analyze_directory_parallel_serializes_config(tmp_path, pe_file):
    dest = tmp_path / "sample.exe"
    os.rename(pe_file, dest)
    seen: dict[str, object] = {}

    def fake_worker(job):
        seen["config_dict"] = job.config_dict
        seen["decompiler_type"] = job.decompiler_type
        seen["config_factory"] = job.config_factory
        seen["r2_factory"] = job.r2_factory
        seen["flags"] = (job.force_decompiler, job.skip_banned, job.skip_analysis)
        return Ok(
            BinaryAnalysisOutcome(
                report=AnalysisResult(
                    file_name=os.path.basename(job.executable_file),
                    file_path=job.executable_file,
                    total_functions=1,
                    detected_functions=(
                        BannedFunction(
                            name="main",
                            address=0x1000,
                            size=0,
                            banned_calls=("strcpy",),
                            detection_method="decompilation",
                        ),
                    ),
                    analysis_date="2026-03-11T00:00:00",
                )
            )
        )

    config = create_config_from_dict({"decompiler": {"type": "r2dec"}})
    result = analyzers.analyze_directory(
        str(tmp_path),
        request=make_directory_request(
            output_dir=str(tmp_path / "out"),
            decompiler_type="r2dec",
            max_workers=1,
            parallel=True,
            force_decompiler=True,
            skip_banned=True,
            skip_analysis=False,
            runtime=AnalysisRuntime(
                config=config,
                config_factory=create_config_from_dict,
                r2_factory=fake_r2_factory,
                binary=_default_binary_services(),
                directory=DirectoryRuntimeServices(
                    file_finder=_default_file_finder,
                    worker_entrypoint=fake_worker,
                    executor_factory=ImmediateProcessPoolExecutor,
                    completed_futures=identity_completed_futures,
                ),
            ),
        ),
    )

    assert result.is_ok()
    assert seen["config_dict"]["decompiler"]["type"] == "r2dec"
    assert seen["decompiler_type"] == "r2dec"
    assert seen["config_factory"] is create_config_from_dict
    assert seen["r2_factory"] is fake_r2_factory
    assert seen["flags"] == (True, True, False)
