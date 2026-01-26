import json
import os
import concurrent.futures

import pytest
import r2pipe

import bannedfuncdetector.application.binary_analyzer as binary_analyzer
import bannedfuncdetector.application.binary_analyzer as analyzers
import bannedfuncdetector.application.parallel_analyzer as parallel_analyzer
import bannedfuncdetector.application.directory_scanner as directory_scanner

# Also import analyze_directory from directory_scanner for backward compat
analyzers.analyze_directory = directory_scanner.analyze_directory
from bannedfuncdetector.domain.result import Ok, Err, ok, err


def test_analyze_function_detect_by_name():
    fake_func = {"name": "strcpy", "offset": 4096}
    result = analyzers.analyze_function(
        None,
        fake_func,
        banned_functions=["strcpy"],
        decompiler_type="default",
        verbose=True,
    )
    assert result.is_ok()
    assert result.unwrap()["detection_method"] == "name"


def test_analyze_function_decompile_no_match(compiled_binary):
    r2 = r2pipe.open(compiled_binary, flags=["-2"])
    try:
        r2.cmd("aaa")
        functions = r2.cmdj("aflj")
        result = analyzers.analyze_function(
            r2,
            functions[0],
            banned_functions=["nonexistent"],
            decompiler_type="default",
            verbose=False,
        )
        # When no banned functions found, returns Err
        assert result.is_err()
    finally:
        r2.quit()


def test_analyze_function_decompile_empty(monkeypatch):
    """Test that empty decompilation results in Err (no banned functions found)."""
    # Create a mock orchestrator that returns empty decompilation
    class MockOrchestrator:
        def decompile_function(self, r2, func_name, decompiler_type):
            return ok("")

        def select_decompiler(self, requested=None, force=False):
            return "default"

        def check_decompiler_available(self, decompiler_type):
            return True

    # Patch the orchestrator factory to return our mock
    monkeypatch.setattr(
        "bannedfuncdetector.infrastructure.decompilers.orchestrator.create_decompiler_orchestrator",
        lambda config=None: MockOrchestrator()
    )

    func = {"name": "f", "offset": 1}
    result = analyzers.analyze_function(None, func, banned_functions=["strcpy"], verbose=False)
    # When decompilation is empty, returns Err (no banned functions found)
    assert result.is_err()


def test_analyze_binary_and_output(compiled_binary, tmp_path):
    output_dir = tmp_path / "out"
    result = analyzers.analyze_binary(
        compiled_binary,
        output_dir=str(output_dir),
        decompiler_type="r2ghidra",
        verbose=False,
        worker_limit=1,
    )
    assert result.is_ok()
    output_file = output_dir / f"{os.path.basename(compiled_binary)}_banned_functions.json"
    assert output_file.exists()
    data = json.loads(output_file.read_text())
    assert data["total_functions"] >= 1


def test_analyze_binary_verbose_output(compiled_binary, tmp_path):
    output_dir = tmp_path / "out"
    result = analyzers.analyze_binary(
        compiled_binary,
        output_dir=str(output_dir),
        decompiler_type="default",
        verbose=True,
        worker_limit=None,
    )
    assert result.is_ok()


def test_analyze_binary_missing_file(tmp_path):
    result = analyzers.analyze_binary(str(tmp_path / "missing.bin"))
    assert result.is_err()
    assert "not found" in result.error.lower()


def test_analyze_directory_missing(tmp_path):
    result = analyzers.analyze_directory(str(tmp_path / "missing"))
    assert result.is_err()
    assert "does not exist" in result.error.lower()


def test_analyze_directory_no_pe(tmp_path):
    (tmp_path / "note.txt").write_text("hi")
    result = analyzers.analyze_directory(str(tmp_path))
    assert result.is_err()
    # Error message may say "no pe files" or "no executable files"
    error_lower = result.error.lower()
    assert "no pe files" in error_lower or "no executable" in error_lower


def test_analyze_directory_with_pe(pe_file, tmp_path):
    # Move PE file into directory
    dest = tmp_path / "sample.exe"
    os.rename(pe_file, dest)
    result = analyzers.analyze_directory(str(tmp_path), output_dir=str(tmp_path / "out"), max_workers=1, verbose=False)
    assert result.is_ok()
    assert result.unwrap()["total_files"] == 1


def test_analyze_directory_verbose_success(monkeypatch, tmp_path, pe_file):
    from bannedfuncdetector.domain.result import Ok
    dest = tmp_path / "sample.exe"
    os.rename(pe_file, dest)

    class DummyFuture:
        def __init__(self, value):
            self._value = value
        def result(self):
            return self._value

    class DummyExecutor:
        def __init__(self, *args, **kwargs):
            self._futures = []
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def submit(self, *_args, **_kwargs):
            # Must return Ok(...) since _collect_analysis_results expects Result type
            future = DummyFuture(Ok({"unsafe_functions": 1}))
            self._futures.append(future)
            return future

    monkeypatch.setattr(directory_scanner.concurrent.futures, "ProcessPoolExecutor", DummyExecutor)
    monkeypatch.setattr(directory_scanner.concurrent.futures, "as_completed", lambda futs: futs)
    result = analyzers.analyze_directory(str(tmp_path), output_dir=str(tmp_path / "out"), max_workers=1, verbose=True)
    assert result.is_ok()
    assert result.unwrap()["analyzed_files"] == 1


def test_analyze_function_exception(monkeypatch):
    """Test that exceptions during decompilation return Err."""
    def raise_error(*_args, **_kwargs):
        raise RuntimeError("boom")

    # Create a mock orchestrator that raises an exception
    class MockOrchestrator:
        def decompile_function(self, r2, func_name, decompiler_type):
            raise RuntimeError("boom")

        def select_decompiler(self, requested=None, force=False):
            return "default"

        def check_decompiler_available(self, decompiler_type):
            return True

    monkeypatch.setattr(
        "bannedfuncdetector.infrastructure.decompilers.orchestrator.create_decompiler_orchestrator",
        lambda config=None: MockOrchestrator()
    )
    result = analyzers.analyze_function(None, {"name": "f", "offset": 1}, banned_functions=[], verbose=True)
    # When an exception occurs, returns Err
    assert result.is_err()


def test_analyze_function_decompile_match(monkeypatch):
    """Test that banned functions in decompiled code are detected."""
    # Create a mock orchestrator that returns code with banned function
    class MockOrchestrator:
        def decompile_function(self, r2, func_name, decompiler_type):
            return ok("strcpy(")

        def select_decompiler(self, requested=None, force=False):
            return "default"

        def check_decompiler_available(self, decompiler_type):
            return True

    monkeypatch.setattr(
        "bannedfuncdetector.infrastructure.decompilers.orchestrator.create_decompiler_orchestrator",
        lambda config=None: MockOrchestrator()
    )
    func = {"name": "f", "offset": 1}
    result = analyzers.analyze_function(None, func, banned_functions=["strcpy"], verbose=True)
    assert result.is_ok()
    assert result.unwrap()["detection_method"] == "decompilation"


def test_analyze_binary_no_decompiler(monkeypatch, tmp_path):
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

    # Create a mock orchestrator that selects default decompiler
    class MockOrchestrator:
        def decompile_function(self, r2, func_name, decompiler_type):
            return ok("")

        def select_decompiler(self, requested=None, force=False):
            return "default"

        def check_decompiler_available(self, decompiler_type):
            return True

    monkeypatch.setattr(
        "bannedfuncdetector.infrastructure.decompilers.orchestrator.create_decompiler_orchestrator",
        lambda config=None: MockOrchestrator()
    )
    monkeypatch.setattr(
        "bannedfuncdetector.factories.create_r2_client",
        lambda *_args, **_kwargs: DummyR2()
    )
    result = analyzers.analyze_binary(str(temp_file), decompiler_type="r2ghidra", verbose=True)
    # When no functions are found, result is Err
    assert result.is_err()


def test_analyze_binary_no_functions(monkeypatch, tmp_path):
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

    # Create a mock orchestrator
    class MockOrchestrator:
        def decompile_function(self, r2, func_name, decompiler_type):
            return ok("")

        def select_decompiler(self, requested=None, force=False):
            return "default"

        def check_decompiler_available(self, decompiler_type):
            return True

    monkeypatch.setattr(
        "bannedfuncdetector.infrastructure.decompilers.orchestrator.create_decompiler_orchestrator",
        lambda config=None: MockOrchestrator()
    )
    monkeypatch.setattr(
        "bannedfuncdetector.factories.create_r2_client",
        lambda *_args, **_kwargs: DummyR2()
    )
    result = analyzers.analyze_binary(str(temp_file), verbose=True)
    # When no functions are found, result is Err
    assert result.is_err()


def test_analyze_binary_worker_error(monkeypatch, compiled_binary):
    class DummyFuture:
        def __init__(self, exc):
            self._exc = exc
        def result(self):
            raise self._exc

    class DummyExecutor:
        def __init__(self, *args, **kwargs):
            self._args = args
            self._kwargs = kwargs
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def submit(self, *_args, **_kwargs):
            return DummyFuture(RuntimeError("boom"))

    monkeypatch.setattr(parallel_analyzer.concurrent.futures, "ThreadPoolExecutor", DummyExecutor)
    monkeypatch.setattr(parallel_analyzer.concurrent.futures, "as_completed", lambda futs: futs)
    result = analyzers.analyze_binary(compiled_binary, verbose=True, worker_limit=1)
    assert result.is_ok()


def test_analyze_binary_verbose_result(monkeypatch, compiled_binary):
    class DummyFuture:
        def __init__(self, value):
            self._value = value
        def result(self):
            return self._value

    class DummyExecutor:
        def __init__(self, *args, **kwargs):
            self._args = args
            self._kwargs = kwargs
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def submit(self, *_args, **_kwargs):
            return DummyFuture(ok({"name": "f", "address": "0x1"}))

    monkeypatch.setattr(parallel_analyzer.concurrent.futures, "ThreadPoolExecutor", DummyExecutor)
    monkeypatch.setattr(parallel_analyzer.concurrent.futures, "as_completed", lambda futs: futs)
    result = analyzers.analyze_binary(compiled_binary, verbose=True, worker_limit=1)
    assert result.is_ok()


def test_analyze_binary_exception(monkeypatch, tmp_path):
    """Test that R2 client exceptions return Err."""
    temp_file = tmp_path / "bin"
    temp_file.write_text("data")

    def raise_error(*_args, **_kwargs):
        raise RuntimeError("boom")

    # Create a mock orchestrator
    class MockOrchestrator:
        def decompile_function(self, r2, func_name, decompiler_type):
            return ok("")

        def select_decompiler(self, requested=None, force=False):
            return "default"

        def check_decompiler_available(self, decompiler_type):
            return True

    monkeypatch.setattr(
        "bannedfuncdetector.infrastructure.decompilers.orchestrator.create_decompiler_orchestrator",
        lambda config=None: MockOrchestrator()
    )
    monkeypatch.setattr(
        "bannedfuncdetector.factories.create_r2_client",
        raise_error
    )
    result = analyzers.analyze_binary(str(temp_file))
    # Now returns Err instead of raising AnalysisError
    assert result.is_err()


def test_analyze_directory_verbose_error(monkeypatch, tmp_path, pe_file):
    dest = tmp_path / "sample.exe"
    os.rename(pe_file, dest)

    class DummyFuture:
        def __init__(self, exc):
            self._exc = exc
        def result(self):
            raise self._exc

    class DummyExecutor:
        def __init__(self, *args, **kwargs):
            self._futures = []
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def submit(self, *_args, **_kwargs):
            future = DummyFuture(RuntimeError("boom"))
            self._futures.append(future)
            return future

    monkeypatch.setattr(directory_scanner.concurrent.futures, "ProcessPoolExecutor", DummyExecutor)
    monkeypatch.setattr(directory_scanner.concurrent.futures, "as_completed", lambda futs: futs)
    result = analyzers.analyze_directory(str(tmp_path), output_dir=str(tmp_path / "out"), max_workers=1, verbose=True)
    assert result.is_ok()
    assert result.unwrap()["total_files"] == 1


def test_analyze_directory_default_workers(monkeypatch, tmp_path, pe_file):
    dest = tmp_path / "sample.exe"
    os.rename(pe_file, dest)

    class DummyFuture:
        def __init__(self, value):
            self._value = value
        def result(self):
            return self._value

    class DummyExecutor:
        def __init__(self, *args, **kwargs):
            self._futures = []
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def submit(self, *_args, **_kwargs):
            future = DummyFuture({"unsafe_functions": 0})
            self._futures.append(future)
            return future

    monkeypatch.setattr(directory_scanner.concurrent.futures, "ProcessPoolExecutor", DummyExecutor)
    monkeypatch.setattr(directory_scanner.concurrent.futures, "as_completed", lambda futs: futs)
    result = analyzers.analyze_directory(str(tmp_path), output_dir=str(tmp_path / "out"), max_workers=None, verbose=False)
    assert result.is_ok()
    assert result.unwrap()["total_files"] == 1
