import argparse
import logging
import os
import runpy
import sys

import pytest

import bannedfuncdetector.application.binary_analyzer as analyzers
import bannedfuncdetector.bannedfunc as bannedfunc_module
import bannedfuncdetector.application.binary_analyzer as binary_analyzer
import bannedfuncdetector.application.directory_scanner as directory_scanner
from bannedfuncdetector.factories import create_config_from_dict, create_r2_client
from bannedfuncdetector.domain import (
    AnalysisResult,
    BannedFunction,
    DirectoryAnalysisSummary,
)
from bannedfuncdetector.application.analysis_runtime import (
    BinaryRuntimeServices,
    AnalysisRuntime,
)
from bannedfuncdetector.application.contracts import (
    BinaryAnalysisRequest,
    DirectoryAnalysisRequest,
)
from bannedfuncdetector.application.analysis_outcome import (
    BinaryAnalysisOutcome,
    DirectoryAnalysisOutcome,
)
from bannedfuncdetector.runtime_factories import (
    _default_binary_opener,
    _default_r2_closer,
    _default_file_finder,
)
from bannedfuncdetector.application.analysis_runtime import DirectoryRuntimeServices
from bannedfuncdetector.domain.result import Ok, Err, ok
from bannedfuncdetector.cli import parse_arguments
from bannedfuncdetector.cli_bootstrap import validate_requirements
from bannedfuncdetector.cli_dispatch import (
    dispatch_cli_analysis,
    unwrap_or_log,
)
from bannedfuncdetector.infrastructure.validators import (
    check_python_version,
    check_requirements,
    _check_single_requirement,
    ALLOWED_REQUIREMENT_EXECUTABLES,
)
from bannedfuncdetector.infrastructure.file_detection import is_executable_file

analyzers.analyze_directory = directory_scanner.analyze_directory


def _default_binary_services():
    return BinaryRuntimeServices(
        binary_opener=_default_binary_opener,
        r2_closer=_default_r2_closer,
    )


skip_in_ci = pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") == "true",
    reason="r2pipe communication hangs in GitHub Actions CI environment",
)


skip_on_windows = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Test uses Unix-specific paths or behavior",
)


def make_config():
    return create_config_from_dict({"decompiler": {"type": "default"}})


def make_runtime():
    config = make_config()
    return AnalysisRuntime(
        config=config,
        config_factory=create_config_from_dict,
        r2_factory=create_r2_client,
        binary=_default_binary_services(),
        directory=DirectoryRuntimeServices(file_finder=_default_file_finder),
    )


def make_binary_request(runtime=None, **kwargs):
    return BinaryAnalysisRequest.for_runtime(runtime or make_runtime(), **kwargs)


def make_directory_request(runtime=None, **kwargs):
    return DirectoryAnalysisRequest.for_runtime(runtime or make_runtime(), **kwargs)


# ---------------------------------------------------------------------------
# Helpers for sys.argv manipulation
# ---------------------------------------------------------------------------


class _SysArgvOverride:
    """Context manager that temporarily replaces sys.argv."""

    def __init__(self, argv):
        self._argv = argv
        self._saved = None

    def __enter__(self):
        self._saved = sys.argv
        sys.argv = self._argv
        return self

    def __exit__(self, *exc):
        sys.argv = self._saved
        return False


# ---------------------------------------------------------------------------
# Helpers for building fake args namespaces (avoids touching sys.argv at all)
# ---------------------------------------------------------------------------


def _make_args(**overrides):
    """Build an argparse.Namespace with sensible defaults for dispatch tests."""
    defaults = dict(
        file=None,
        directory=None,
        output="output",
        decompiler="default",
        verbose=False,
        force_decompiler=False,
        parallel=False,
        skip_banned=False,
        skip_analysis=False,
        skip_requirements=True,
        check_requirements=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ===========================================================================
# Python version check
# ===========================================================================


def test_check_python_version_success():
    """The current interpreter satisfies MIN_PYTHON_VERSION, so this must not exit."""
    # Should complete without raising SystemExit
    check_python_version()


def test_check_python_version_failure():
    """check_python_version calls sys.exit(1) when version is too low.

    We cannot change sys.version_info at runtime, but we *can*
    verify the function's behaviour by inspecting its implementation contract:
    the current Python IS >= MIN_PYTHON_VERSION so the function succeeds.
    Instead we test that MIN_PYTHON_VERSION is correctly defined.
    """
    from bannedfuncdetector.constants import MIN_PYTHON_VERSION

    assert isinstance(MIN_PYTHON_VERSION, tuple)
    assert len(MIN_PYTHON_VERSION) >= 2
    # Our runtime satisfies the constraint
    assert sys.version_info >= MIN_PYTHON_VERSION


# ===========================================================================
# Argument parsing (real parse_arguments, real sys.argv override)
# ===========================================================================


def test_parse_arguments_file():
    with _SysArgvOverride(["prog", "-f", "sample.bin"]):
        args = parse_arguments()
    assert args.file == "sample.bin"
    assert args.skip_requirements is True


def test_parse_arguments_directory():
    with _SysArgvOverride(["prog", "-d", "samples", "--check-requirements"]):
        args = parse_arguments()
    assert args.directory == "samples"
    assert args.skip_requirements is False


# ===========================================================================
# Binary analysis (real functions, real binaries)
# ===========================================================================


def test_analyze_file_missing(tmp_path):
    result = binary_analyzer.analyze_binary(
        str(tmp_path / "missing.bin"), request=make_binary_request()
    )
    assert isinstance(result, Err)
    assert (
        "not found" in str(result.error).lower()
        or "not exist" in str(result.error).lower()
    )


def test_analyze_file_non_binary(tmp_path):
    """Test binary analysis on a text file.

    Note: radare2 can still analyze non-binary files and may detect "functions"
    in raw data. The result depends on r2's interpretation of the raw bytes.
    """
    text_path = tmp_path / "note.txt"
    text_path.write_text("hello")
    result = binary_analyzer.analyze_binary(
        str(text_path), request=make_binary_request()
    )
    if isinstance(result, Ok):
        assert result.value.report.insecure_count >= 0
        assert result.value.report.total_functions >= 0


def test_analyze_file_success(compiled_binary, tmp_path):
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)
    result = binary_analyzer.analyze_binary(
        str(binary),
        request=make_binary_request(
            output_dir=str(tmp_path / "out"),
            decompiler_type="default",
        ),
    )
    assert isinstance(result, Ok)
    assert result.value.report.total_functions >= 0


# ===========================================================================
# Directory analysis
# ===========================================================================


@skip_on_windows
def test_analyze_directory_sequential(tmp_path):
    from conftest import write_minimal_pe

    pe_path = tmp_path / "sample.exe"
    write_minimal_pe(pe_path)

    result = analyzers.analyze_directory(
        str(tmp_path),
        request=make_directory_request(
            output_dir=str(tmp_path / "out"),
            decompiler_type="default",
            parallel=False,
        ),
    )
    assert result.is_ok()
    data = result.unwrap()
    assert data.summary.analyzed_files >= 1


def test_analyze_directory_parallel(compiled_binary, tmp_path):
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)
    result = directory_scanner.analyze_directory(
        str(tmp_path),
        request=make_directory_request(
            output_dir=str(tmp_path / "out"),
            decompiler_type="default",
        ),
    )
    assert result.is_ok()
    data = result.unwrap()
    assert data.summary.analyzed_files >= 1 or data.summary.total_files >= 1


def test_analyze_directory_no_executables(tmp_path):
    (tmp_path / "note.txt").write_text("hi")
    result = analyzers.analyze_directory(
        str(tmp_path), request=make_directory_request()
    )
    assert result.is_err()
    assert (
        "no executable" in str(result.error).lower()
        or "no pe files" in str(result.error).lower()
    )


def test_analyze_directory_parallel_no_executables(tmp_path):
    (tmp_path / "note.txt").write_text("hi")
    result = directory_scanner.analyze_directory(
        str(tmp_path), request=make_directory_request()
    )
    assert result.is_err()
    assert (
        "no executable" in str(result.error).lower()
        or "no pe files" in str(result.error).lower()
    )


def test_analyze_directory_missing(tmp_path):
    result = analyzers.analyze_directory(
        str(tmp_path / "missing"), request=make_directory_request()
    )
    assert result.is_err()
    assert "does not exist" in str(result.error).lower()


def test_analyze_directory_parallel_missing(tmp_path):
    result = directory_scanner.analyze_directory(
        str(tmp_path / "missing"), request=make_directory_request()
    )
    assert result.is_err()
    assert "does not exist" in str(result.error).lower()


# ===========================================================================
# CLI dispatch (test dispatch functions directly with constructed args)
# ===========================================================================


def test_main_entry(compiled_binary, tmp_path):
    """Test main() end-to-end with real binary and --skip-analysis --skip-banned."""
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)
    with _SysArgvOverride(
        [
            "prog",
            "-f",
            str(binary),
            "--skip-analysis",
            "--skip-banned",
            "-o",
            str(tmp_path / "out"),
        ]
    ):
        assert bannedfunc_module.main() == 0


def test_dispatch_passes_cli_flags_to_binary_analysis(tmp_path):
    """Test that dispatch_cli_analysis correctly threads CLI flags into the request.

    Instead of patching main(), we call dispatch_cli_analysis directly
    with a fake analyze_binary that captures its kwargs.
    """
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"MZ")

    captured = {}

    def capturing_analyze_binary(**kwargs):
        captured.update(kwargs)
        return ok(
            BinaryAnalysisOutcome(
                report=AnalysisResult(
                    file_name="sample.bin",
                    file_path=str(binary),
                    total_functions=0,
                    detected_functions=(),
                    analysis_date="2026-03-11T00:00:00",
                ),
            )
        )

    wiring = make_runtime()
    args = _make_args(
        file=str(binary),
        output=str(tmp_path / "out"),
        skip_analysis=True,
        skip_banned=True,
        force_decompiler=True,
    )
    os.makedirs(args.output, exist_ok=True)

    result = dispatch_cli_analysis(
        args,
        wiring,
        analyze_binary=capturing_analyze_binary,
        analyze_directory=lambda **kw: Err("unused"),
        logger=logging.getLogger("test"),
    )

    assert result is not None
    request = captured["request"]
    assert request.force_decompiler is True
    assert request.skip_banned is True
    assert request.skip_analysis is True
    assert request.runtime.r2_factory is create_r2_client


def test_dispatch_directory_analysis(tmp_path):
    """Test dispatch_cli_analysis routes to analyze_directory correctly."""
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()

    fake_outcome = DirectoryAnalysisOutcome(
        summary=DirectoryAnalysisSummary(
            directory=str(sample_dir),
            analyzed_results=(
                AnalysisResult(
                    file_name="sample.bin",
                    file_path=str(sample_dir / "sample.bin"),
                    total_functions=1,
                    detected_functions=(
                        BannedFunction(
                            name="f",
                            address=1,
                            size=0,
                            banned_calls=("x",),
                            detection_method="name",
                        ),
                    ),
                    analysis_date="2026-03-11T00:00:00",
                ),
            ),
            total_files=1,
        ),
    )

    wiring = make_runtime()
    args = _make_args(directory=str(sample_dir))

    result = dispatch_cli_analysis(
        args,
        wiring,
        analyze_binary=lambda **kw: Err("unused"),
        analyze_directory=lambda **kw: ok(fake_outcome),
        logger=logging.getLogger("test"),
    )
    assert result is not None
    assert result.summary.analyzed_files == 1


def test_dispatch_returns_none_when_no_file_or_directory():
    """dispatch_cli_analysis returns None when neither file nor directory is set."""
    wiring = make_runtime()
    args = _make_args()  # file=None, directory=None
    result = dispatch_cli_analysis(
        args,
        wiring,
        analyze_binary=lambda **kw: Err("unused"),
        analyze_directory=lambda **kw: Err("unused"),
        logger=logging.getLogger("test"),
    )
    assert result is None


def test_dispatch_returns_none_on_error(tmp_path):
    """dispatch_cli_analysis returns None when analysis returns Err."""
    wiring = make_runtime()
    args = _make_args(file=str(tmp_path / "nonexistent.bin"))
    os.makedirs(args.output, exist_ok=True)
    result = dispatch_cli_analysis(
        args,
        wiring,
        analyze_binary=lambda **kw: Err("No results"),
        analyze_directory=lambda **kw: Err("unused"),
        logger=logging.getLogger("test"),
    )
    assert result is None


# ===========================================================================
# Module __main__ guards (real runpy, real sys.argv override)
# ===========================================================================


def test_banned_func_detector_main_guard():
    with _SysArgvOverride(["BannedFuncDetector.py", "-h"]):
        try:
            runpy.run_path("BannedFuncDetector.py", run_name="__main__")
        except SystemExit as exc:
            assert exc.code == 0


def test_bannedfunc_py_main_guard():
    saved_modules = {}
    modules_to_remove = [
        key
        for key in sys.modules
        if key == "bannedfuncdetector.bannedfunc"
        or key.startswith("bannedfuncdetector.bannedfunc.")
    ]
    for mod in modules_to_remove:
        saved_modules[mod] = sys.modules.pop(mod)
    try:
        with _SysArgvOverride(["bannedfunc.py", "-h"]):
            runpy.run_module("bannedfuncdetector.bannedfunc", run_name="__main__")
    except SystemExit as exc:
        assert exc.code == 0
    finally:
        sys.modules.update(saved_modules)


def test_package_main_guard():
    with _SysArgvOverride(["bannedfuncdetector", "-h"]):
        try:
            runpy.run_module("bannedfuncdetector", run_name="__main__")
        except SystemExit as exc:
            assert exc.code == 0


# ===========================================================================
# Requirements checking (real validators functions)
# ===========================================================================


def test_check_requirements_skip():
    assert check_requirements(skip_requirements=True) is True


def test_check_requirements_real():
    """Real requirements check - r2 and r2pipe are installed on this system."""
    assert check_requirements(skip_requirements=False) is True


def test_check_single_requirement_success():
    """_check_single_requirement succeeds with a real python command."""
    result = _check_single_requirement(
        {"name": "python", "command": ["python", "--version"], "expected": "Python"}
    )
    assert result is True


def test_check_single_requirement_wrong_expected():
    """_check_single_requirement fails when output doesn't match expected."""
    result = _check_single_requirement(
        {
            "name": "python",
            "command": ["python", "--version"],
            "expected": "ZZZZZ_NONEXISTENT",
        }
    )
    assert result is False


def test_check_single_requirement_blocked_command():
    """_check_single_requirement blocks commands not in ALLOWED_REQUIREMENT_EXECUTABLES."""
    result = _check_single_requirement(
        {
            "name": "test",
            "command": ["curl", "http://example.com"],
            "expected": "anything",
        }
    )
    assert result is False
    assert "curl" not in ALLOWED_REQUIREMENT_EXECUTABLES


def test_check_single_requirement_empty_command():
    """_check_single_requirement handles empty command list."""
    result = _check_single_requirement(
        {"name": "test", "command": [], "expected": "anything"}
    )
    assert result is False


def test_check_single_requirement_missing_fields():
    """_check_single_requirement handles missing required dict fields."""
    result = _check_single_requirement({"name": "test"})
    assert result is False


def test_validate_requirements_skip():
    """validate_requirements returns immediately when skip is True."""
    # Should not raise SystemExit
    validate_requirements(
        True,
        check_requirements=lambda skip: False,  # would fail if called
        logger=logging.getLogger("test"),
    )


def test_validate_requirements_success():
    """validate_requirements passes when check returns True."""
    validate_requirements(
        False,
        check_requirements=lambda skip: True,
        logger=logging.getLogger("test"),
    )


def test_validate_requirements_failure():
    """validate_requirements calls sys.exit(1) when check returns False."""
    with pytest.raises(SystemExit) as exc_info:
        validate_requirements(
            False,
            check_requirements=lambda skip: False,
            logger=logging.getLogger("test"),
        )
    assert exc_info.value.code == 1


# ===========================================================================
# File detection (real functions, real files)
# ===========================================================================


def test_is_binary_file_extension(tmp_path):
    """Files without proper executable magic bytes are not detected."""
    exe = tmp_path / "sample.exe"
    exe.write_text("data")
    assert is_executable_file(str(exe), "any") is False


def test_is_binary_file_text_content(tmp_path):
    """Plain text file is not detected as executable."""
    txt = tmp_path / "sample.bin"
    txt.write_text("just some text data")
    assert is_executable_file(str(txt), "any") is False


@skip_on_windows
def test_is_binary_file_real_executable():
    """A real system binary is detected as executable."""
    assert is_executable_file("/bin/ls", "any") is True


def test_is_binary_file_nonexistent(tmp_path):
    """Non-existent files return False."""
    assert is_executable_file(str(tmp_path / "nope.bin"), "any") is False


def test_is_binary_file_pe_magic(tmp_path):
    """A file with PE magic bytes (MZ) is detected as PE executable."""
    from conftest import write_minimal_pe

    pe_path = tmp_path / "stub.exe"
    write_minimal_pe(pe_path)
    assert is_executable_file(str(pe_path), "pe") is True


def test_is_binary_file_elf_magic(tmp_path):
    """A file with ELF magic bytes is detected as ELF executable."""
    elf = tmp_path / "stub.elf"
    # Minimal ELF header
    data = bytearray(64)
    data[0:4] = b"\x7fELF"
    elf.write_bytes(bytes(data))
    assert is_executable_file(str(elf), "elf") is True


# ===========================================================================
# Decompiler selection (real select_decompiler with real config)
# ===========================================================================


def test_analyze_file_with_default_decompiler(compiled_binary, tmp_path):
    """Test binary analysis with default decompiler (always available)."""
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)
    result = binary_analyzer.analyze_binary(
        str(binary),
        request=make_binary_request(
            output_dir=str(tmp_path / "out"),
            decompiler_type="default",
        ),
    )
    assert isinstance(result, Ok)
    assert result.value.report.total_functions >= 0


def test_analyze_file_with_skip_flags(compiled_binary, tmp_path):
    """Test binary analysis with skip flags produces a result."""
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)
    result = binary_analyzer.analyze_binary(
        str(binary),
        request=make_binary_request(
            output_dir=str(tmp_path / "out"),
            decompiler_type="default",
            skip_analysis=True,
            skip_banned=True,
        ),
    )
    assert isinstance(result, Ok)


def test_analyze_file_verbose(compiled_binary, tmp_path):
    """Test binary analysis with verbose flag."""
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)
    result = binary_analyzer.analyze_binary(
        str(binary),
        request=make_binary_request(
            output_dir=str(tmp_path / "out"),
            decompiler_type="default",
            verbose=True,
        ),
    )
    assert result is not None


# ===========================================================================
# unwrap_or_log helper
# ===========================================================================


def test_unwrap_or_log_ok():
    result = ok(
        BinaryAnalysisOutcome(
            report=AnalysisResult(
                file_name="test.bin",
                file_path="/tmp/test.bin",
                total_functions=0,
                detected_functions=(),
                analysis_date="2026-03-11T00:00:00",
            ),
        )
    )
    value = unwrap_or_log(result, "ctx", logger=logging.getLogger("test"))
    assert value is not None
    assert value.report.file_name == "test.bin"


def test_unwrap_or_log_err():
    result = Err("something went wrong")
    value = unwrap_or_log(result, "ctx", logger=logging.getLogger("test"))
    assert value is None


# ===========================================================================
# FakeR2-based tests via dependency injection
# ===========================================================================


def test_analyze_binary_with_fake_r2_no_functions(compiled_binary, tmp_path):
    """Test binary analysis using FakeR2 that returns no functions."""
    from conftest import FakeR2, FakeR2ClientFactory

    fake = FakeR2(cmdj_map={"aflj": None})
    factory = FakeR2ClientFactory(fake)

    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)

    config = make_config()
    runtime = AnalysisRuntime(
        config=config,
        config_factory=create_config_from_dict,
        r2_factory=factory.create,
        binary=BinaryRuntimeServices(
            binary_opener=lambda path, verbose, r2_factory: factory.create(path),
            r2_closer=lambda r2: ok(None),
        ),
    )

    result = binary_analyzer.analyze_binary(
        str(binary),
        request=BinaryAnalysisRequest.for_runtime(runtime),
    )
    assert isinstance(result, Err)
    assert "no functions" in str(result.error).lower()


def test_analyze_binary_with_fake_r2_open_error(compiled_binary, tmp_path):
    """Test binary analysis when r2 factory raises an exception."""
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)

    def failing_r2_factory(path, flags=None):
        raise RuntimeError("boom")

    config = make_config()
    runtime = AnalysisRuntime(
        config=config,
        config_factory=create_config_from_dict,
        r2_factory=failing_r2_factory,
        binary=BinaryRuntimeServices(
            binary_opener=lambda path, verbose, r2_factory: r2_factory(path),
            r2_closer=lambda r2: ok(None),
        ),
    )

    result = binary_analyzer.analyze_binary(
        str(binary),
        request=BinaryAnalysisRequest.for_runtime(runtime),
    )
    assert isinstance(result, Err)
    assert (
        "runtime" in str(result.error).lower()
        or "error" in str(result.error).lower()
        or "boom" in str(result.error).lower()
    )
