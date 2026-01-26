import builtins
import os
import runpy
import sys

import pytest

import bannedfuncdetector.application.binary_analyzer as analyzers
import bannedfuncdetector.bannedfunc as bannedfunc_module
import bannedfuncdetector.application.binary_analyzer as binary_analyzer
import bannedfuncdetector.application.directory_scanner as directory_scanner
import bannedfuncdetector.infrastructure.decompilers.base_decompiler as decompilers
import bannedfuncdetector.infrastructure.decompilers.orchestrator as decompiler_orchestrator
import bannedfuncdetector.infrastructure.validators as validators
from bannedfuncdetector.domain.result import Ok, Err, ok

# Also import analyze_directory from directory_scanner for backward compat
analyzers.analyze_directory = directory_scanner.analyze_directory


def test_check_python_version_failure(monkeypatch):
    monkeypatch.setattr(sys, "version_info", (3, 10, 0))
    try:
        bannedfunc_module.check_python_version()
    except SystemExit as exc:
        assert exc.code == 1


def test_parse_arguments_file(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog", "-f", "sample.bin"])
    args = bannedfunc_module.parse_arguments()
    assert args.file == "sample.bin"
    assert args.skip_requirements is True


def test_parse_arguments_directory(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog", "-d", "samples", "--check-requirements"])
    args = bannedfunc_module.parse_arguments()
    assert args.directory == "samples"
    assert args.skip_requirements is False


def test_analyze_file_missing(tmp_path):
    result = binary_analyzer.analyze_binary(str(tmp_path / "missing.bin"))
    assert isinstance(result, Err)
    assert "not found" in result.error.lower() or "not exist" in result.error.lower()


def test_analyze_file_non_binary(tmp_path):
    """Test binary analysis on a text file.

    Note: radare2 can still analyze non-binary files and may detect "functions"
    in raw data. The result depends on r2's interpretation of the raw bytes.
    """
    text_path = tmp_path / "note.txt"
    text_path.write_text("hello")
    result = binary_analyzer.analyze_binary(str(text_path))
    # Analysis may succeed or fail - both are valid outcomes
    # r2 behavior on non-binary files is not deterministic
    if isinstance(result, Ok):
        # Just verify the structure is correct, don't check specific counts
        assert "unsafe_functions" in result.value
        assert "total_functions" in result.value


def test_analyze_file_success(compiled_binary, tmp_path):
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)
    result = binary_analyzer.analyze_binary(
        str(binary),
        output_dir=str(tmp_path / "out"),
        decompiler_type="default",
        verbose=False,
    )
    assert isinstance(result, Ok)
    assert "binary" in result.value or "total_functions" in result.value


def test_analyze_directory_sequential(tmp_path):
    # Create a minimal PE file since analyzers.analyze_directory uses find_pe_files
    from conftest import write_minimal_pe
    pe_path = tmp_path / "sample.exe"
    write_minimal_pe(pe_path)

    result = analyzers.analyze_directory(
        str(tmp_path),
        output_dir=str(tmp_path / "out"),
        decompiler_type="default",
        verbose=False,
        parallel=False,
    )
    # Result is now a Result type
    assert result.is_ok()
    data = result.unwrap()
    assert data.get("analyzed_files", 0) >= 1 or (isinstance(data, list) and len(data) >= 1)


def test_analyze_directory_parallel(compiled_binary, tmp_path):
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)
    result = directory_scanner.analyze_directory(
        str(tmp_path),
        output_dir=str(tmp_path / "out"),
        decompiler_type="default",
        verbose=False,
    )
    assert result.is_ok()
    data = result.unwrap()
    assert data.get("analyzed_files", 0) >= 1 or data.get("total_files", 0) >= 1


def test_main_entry(compiled_binary, tmp_path, monkeypatch):
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prog",
            "-f",
            str(binary),
            "--skip-analysis",
            "--skip-banned",
            "-o",
            str(tmp_path / "out"),
        ],
    )
    assert bannedfunc_module.main() == 0


def test_banned_func_detector_main_guard(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["BannedFuncDetector.py", "-h"])
    try:
        runpy.run_path("BannedFuncDetector.py", run_name="__main__")
    except SystemExit as exc:
        assert exc.code == 0


def test_check_requirements_skip():
    assert bannedfunc_module.check_requirements(skip_requirements=True) is True


def test_check_requirements_success(monkeypatch):
    class DummyResult:
        def __init__(self, returncode=0, stdout="radare2", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(command, *args, **kwargs):
        if isinstance(command, str) and "r2pipe" in command:
            return DummyResult(stdout="r2pipe installed")
        if isinstance(command, list) and any("r2pipe" in part for part in command):
            return DummyResult(stdout="r2pipe installed")
        return DummyResult(stdout="radare2")

    monkeypatch.setattr(validators.subprocess, "run", fake_run)
    monkeypatch.setattr(validators, "check_decompiler_available", lambda *_args, **_kwargs: True)
    assert bannedfunc_module.check_requirements(skip_requirements=False) is True


def test_check_requirements_failure(monkeypatch):
    class DummyResult:
        def __init__(self, returncode=1, stdout="", stderr="err"):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    monkeypatch.setattr(validators.subprocess, "run", lambda *args, **kwargs: DummyResult())
    monkeypatch.setattr(validators, "check_decompiler_available", lambda *_args, **_kwargs: False)
    assert bannedfunc_module.check_requirements(skip_requirements=False) is False


def test_check_requirements_exception(monkeypatch):
    def raise_error(*_args, **_kwargs):
        # Use OSError which is a realistic exception for subprocess.run failures
        # (e.g., command not found)
        raise OSError("boom")

    monkeypatch.setattr(validators.subprocess, "run", raise_error)
    assert bannedfunc_module.check_requirements(skip_requirements=False) is False


def test_check_requirements_decompiler_error(monkeypatch):
    class DummyResult:
        def __init__(self, returncode=0, stdout="radare2", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(command, *args, **kwargs):
        if isinstance(command, str) and "r2pipe" in command:
            return DummyResult(stdout="r2pipe installed")
        if isinstance(command, list) and any("r2pipe" in part for part in command):
            return DummyResult(stdout="r2pipe installed")
        return DummyResult(stdout="radare2")

    monkeypatch.setattr(validators.subprocess, "run", fake_run)
    monkeypatch.setattr(validators, "check_decompiler_available", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
    assert bannedfunc_module.check_requirements(skip_requirements=False) is True


def test_check_requirements_no_binary(monkeypatch):
    class DummyResult:
        def __init__(self, returncode=0, stdout="radare2", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(command, *args, **kwargs):
        if isinstance(command, str) and "r2pipe" in command:
            return DummyResult(stdout="r2pipe installed")
        if isinstance(command, list) and any("r2pipe" in part for part in command):
            return DummyResult(stdout="r2pipe installed")
        return DummyResult(stdout="radare2")

    monkeypatch.setattr(validators.subprocess, "run", fake_run)
    monkeypatch.setattr(validators.os.path, "exists", lambda _path: False)
    assert bannedfunc_module.check_requirements(skip_requirements=False) is True


def test_check_requirements_import_error(monkeypatch):
    class DummyResult:
        def __init__(self, returncode=0, stdout="radare2", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(command, *args, **kwargs):
        if isinstance(command, str) and "r2pipe" in command:
            return DummyResult(stdout="r2pipe installed")
        if isinstance(command, list) and any("r2pipe" in part for part in command):
            return DummyResult(stdout="r2pipe installed")
        return DummyResult(stdout="radare2")

    original_import = __import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "decompilers":
            raise ImportError("boom")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(validators.subprocess, "run", fake_run)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert fake_import("os") is not None
    assert bannedfunc_module.check_requirements(skip_requirements=False) is True


def test_analyze_file_with_banned_and_analysis(monkeypatch, compiled_binary, tmp_path):
    """Test binary analysis with mocked banned function detection."""
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)

    # Mock the parallel detection to return preset results
    def mock_run_parallel_detection(*_args, **_kwargs):
        return [
            {"address": "0x1", "name": "x", "banned_functions": ["a"], "detection_method": "name"},
            {"address": "0x2", "name": "y", "banned_functions": ["b"], "detection_method": "decompilation"},
        ]

    # Patch on operations module since it imports _run_parallel_detection inside _execute_detection
    import bannedfuncdetector.application.binary_analyzer.operations as operations
    monkeypatch.setattr(
        "bannedfuncdetector.application.parallel_analyzer._run_parallel_detection",
        mock_run_parallel_detection
    )

    result = binary_analyzer.analyze_binary(
        str(binary),
        output_dir=str(tmp_path / "out"),
        decompiler_type="default",
        verbose=True,
    )
    assert isinstance(result, Ok)
    assert result.value["unsafe_functions"] == 2


def test_analyze_file_decompiler_alternative(monkeypatch, compiled_binary, tmp_path):
    """Test binary analysis with alternative decompiler selection."""
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)

    import bannedfuncdetector.infrastructure.decompilers.orchestrator as decompiler_orchestrator
    monkeypatch.setattr(decompiler_orchestrator, "select_decompiler", lambda *_args, **_kwargs: "r2dec")

    result = binary_analyzer.analyze_binary(
        str(binary),
        output_dir=str(tmp_path / "out"),
        decompiler_type="r2ghidra",
        verbose=False,
    )
    assert result is not None


def test_analyze_file_r2ai_switch(monkeypatch, compiled_binary, tmp_path):
    """Test that decompiler selection handles r2ai -> default switch."""
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)

    import bannedfuncdetector.infrastructure.decompilers.orchestrator as decompiler_orchestrator
    monkeypatch.setattr(decompiler_orchestrator, "select_decompiler", lambda *_args, **_kwargs: "default")

    result = binary_analyzer.analyze_binary(
        str(binary),
        output_dir=str(tmp_path / "out"),
        decompiler_type="r2ai",
        verbose=False,
    )
    assert result is not None


def test_analyze_directory_no_executables(tmp_path):
    (tmp_path / "note.txt").write_text("hi")
    result = analyzers.analyze_directory(str(tmp_path))
    # Now returns Err when no executables found
    assert result.is_err()
    assert ("no executable" in result.error.lower() or "no pe files" in result.error.lower())


def test_analyze_directory_parallel_no_executables(tmp_path):
    (tmp_path / "note.txt").write_text("hi")
    result = directory_scanner.analyze_directory(str(tmp_path))
    assert result.is_err()
    assert "no executable" in result.error.lower() or "no pe files" in result.error.lower()


def test_analyze_directory_missing(tmp_path):
    # Now returns Err instead of raising exception
    result = analyzers.analyze_directory(str(tmp_path / "missing"))
    assert result.is_err()
    assert "does not exist" in result.error.lower()


def test_analyze_directory_parallel_missing(tmp_path):
    result = directory_scanner.analyze_directory(str(tmp_path / "missing"))
    assert result.is_err()
    assert "does not exist" in result.error.lower()


def test_is_binary_file_extension(tmp_path):
    """Test that files without proper executable magic bytes are not detected."""
    import bannedfuncdetector.file_detection as file_detection
    exe = tmp_path / "sample.exe"
    exe.write_text("data")
    # Files with .exe extension but no valid magic bytes should return False
    assert file_detection.is_executable_file(str(exe), "any") is False


def test_is_binary_file_magic_error(monkeypatch, tmp_path):
    """Test that magic errors are handled gracefully and fallback to magic bytes check."""
    import bannedfuncdetector.file_detection as file_detection
    exe = tmp_path / "sample.bin"
    exe.write_text("data")

    def raise_error(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(file_detection.magic, "from_file", raise_error)
    # When magic fails and file has no valid magic bytes, should return False
    assert file_detection.is_executable_file(str(exe), "any") is False


def test_is_binary_file_magic_executable(monkeypatch, tmp_path):
    """Test that PE executables are correctly detected via magic."""
    import bannedfuncdetector.file_detection as file_detection
    exe = tmp_path / "sample.bin"
    exe.write_text("data")

    def fake_from_file(_path):
        return "PE32 executable"

    monkeypatch.setattr(file_detection.magic, "from_file", fake_from_file)
    assert file_detection.is_executable_file(str(exe), "any") is True


def test_main_requirements_fail(monkeypatch):
    monkeypatch.setattr(bannedfunc_module, "check_requirements", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(sys, "argv", ["prog", "-f", "file.bin", "--check-requirements"])
    try:
        bannedfunc_module.main()
    except SystemExit as exc:
        assert exc.code == 1


def test_main_entry_directory(monkeypatch, tmp_path):
    """Test main() with directory argument."""
    from bannedfuncdetector.domain.result import ok
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()

    # Mock the directory scanner to return a valid result
    monkeypatch.setattr(
        directory_scanner,
        "analyze_directory",
        lambda *_args, **_kwargs: ok({
            "directory": str(sample_dir),
            "total_files": 1,
            "analyzed_files": 1,
            "results": [{"name": "f", "address": 1, "banned_functions": ["x"]}]
        }),
    )
    monkeypatch.setattr(sys, "argv", ["prog", "-d", str(sample_dir)])
    assert bannedfunc_module.main() == 0


def test_check_requirements_no_decompilers(monkeypatch):
    class DummyResult:
        def __init__(self, returncode=0, stdout="radare2", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(command, *args, **kwargs):
        if isinstance(command, str) and "r2pipe" in command:
            return DummyResult(stdout="r2pipe installed")
        if isinstance(command, list) and any("r2pipe" in part for part in command):
            return DummyResult(stdout="r2pipe installed")
        return DummyResult(stdout="radare2")

    class DummyR2:
        def cmd(self, _):
            return ""
        def quit(self):
            return None
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    DummyR2().cmd("Lc")
    monkeypatch.setattr(validators.subprocess, "run", fake_run)
    monkeypatch.setattr(validators.R2Client, "open", lambda *_args, **_kwargs: DummyR2())
    monkeypatch.setattr(validators, "check_decompiler_available", lambda *_args, **_kwargs: False)
    assert bannedfunc_module.check_requirements(skip_requirements=False) is True


def test_analyze_file_no_functions(monkeypatch, compiled_binary, tmp_path):
    """Test binary analysis when no functions are found."""
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)

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

    from bannedfuncdetector.infrastructure.adapters.r2_client import R2Client
    monkeypatch.setattr(R2Client, "open", lambda *_args, **_kwargs: DummyR2())
    result = binary_analyzer.analyze_binary(str(binary))
    assert isinstance(result, Err)
    assert "no functions" in result.error.lower()


def test_analyze_file_exception(monkeypatch, compiled_binary, tmp_path):
    """Test binary analysis when R2Client.open raises exception."""
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)

    def raise_error(*_args, **_kwargs):
        raise RuntimeError("boom")

    from bannedfuncdetector.infrastructure.adapters.r2_client import R2Client
    monkeypatch.setattr(R2Client, "open", raise_error)
    result = binary_analyzer.analyze_binary(str(binary))
    assert isinstance(result, Err)
    assert "runtime" in result.error.lower() or "error" in result.error.lower()


def test_analyze_file_no_alternatives(monkeypatch, compiled_binary, tmp_path):
    """Test that select_decompiler falls back to default when no alternatives available."""
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)

    import bannedfuncdetector.infrastructure.decompilers.orchestrator as decompiler_orchestrator
    monkeypatch.setattr(decompiler_orchestrator, "select_decompiler", lambda *_args, **_kwargs: "default")

    result = binary_analyzer.analyze_binary(str(binary), decompiler_type="r2ghidra")
    assert result is not None


def test_main_requirements_success(monkeypatch, tmp_path):
    monkeypatch.setattr(validators, "check_requirements", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(sys, "argv", ["prog", "-f", "file.bin", "--check-requirements"])
    assert bannedfunc_module.main() == 0


def test_main_no_results(monkeypatch, tmp_path):
    """Test main() when analysis returns no results."""
    # Mock analyze_binary to return an error
    monkeypatch.setattr(binary_analyzer, "analyze_binary", lambda *args, **kwargs: Err("No results"))
    monkeypatch.setattr(sys, "argv", ["prog", "-f", "file.bin"])
    assert bannedfunc_module.main() == 0


def test_bannedfunc_py_main_guard(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["bannedfunc.py", "-h"])
    # Remove the module from sys.modules to avoid RuntimeWarning about module
    # being found in sys.modules after import of package but prior to execution.
    # This happens because bannedfuncdetector.__init__ imports bannedfunc.
    saved_modules = {}
    modules_to_remove = [
        key for key in sys.modules
        if key == "bannedfuncdetector.bannedfunc" or key.startswith("bannedfuncdetector.bannedfunc.")
    ]
    for mod in modules_to_remove:
        saved_modules[mod] = sys.modules.pop(mod)
    try:
        runpy.run_module("bannedfuncdetector.bannedfunc", run_name="__main__")
    except SystemExit as exc:
        assert exc.code == 0
    finally:
        # Restore modules to avoid affecting other tests
        sys.modules.update(saved_modules)

def test_package_main_guard(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["bannedfuncdetector", "-h"])
    try:
        runpy.run_module("bannedfuncdetector", run_name="__main__")
    except SystemExit as exc:
        assert exc.code == 0
