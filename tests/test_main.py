import argparse
import errno
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
    os.environ.get("BFD_SKIP_R2_TESTS") == "1",
    reason="r2-dependent test; set BFD_SKIP_R2_TESTS=1 to skip when r2 is unavailable",
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


def test_parse_arguments_check_requirements_standalone():
    # --check-requirements is a system check with no target, so it parses
    # without -f/-d.
    with _SysArgvOverride(["prog", "--check-requirements"]):
        args = parse_arguments()
    assert args.file is None
    assert args.directory is None
    assert args.check_requirements is True
    assert args.skip_requirements is False


def test_parse_arguments_requires_target_or_check():
    # Neither a target nor --check-requirements: argparse errors out.
    with _SysArgvOverride(["prog"]):
        with pytest.raises(SystemExit):
            parse_arguments()


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


# test_analyze_directory_missing (sequential) lives in test_analyzers.py; only
# the parallel directory_scanner variant is exercised here.
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


def test_main_check_requirements_standalone(tmp_path):
    """main() with only --check-requirements runs the check and exits 0,
    without attempting any analysis."""
    with _SysArgvOverride(["prog", "--check-requirements", "-o", str(tmp_path / "o")]):
        assert bannedfunc_module.main() == 0


def test_configure_logging_verbose_toggles_debug_level():
    """verbose=True lowers the root level to DEBUG so the logger.debug
    diagnostics become visible; verbose=False keeps INFO."""
    from bannedfuncdetector.cli_bootstrap import configure_logging

    root = logging.getLogger()
    saved_level = root.level
    saved_handlers = root.handlers[:]
    try:
        root.handlers.clear()
        configure_logging(verbose=True)
        assert root.level == logging.DEBUG
        root.handlers.clear()
        configure_logging(verbose=False)
        assert root.level == logging.INFO
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_configure_logging_json_redacts_secrets_and_control_characters(
    monkeypatch, capsys
):
    import json
    from pathlib import Path

    from bannedfuncdetector.cli_bootstrap import configure_logging

    monkeypatch.setenv("BFD_LOG_FORMAT", "json")
    monkeypatch.setenv("BFD_ENVIRONMENT", "test")
    monkeypatch.delenv("BFD_LOG_LEVEL", raising=False)
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        root.handlers.clear()
        configure_logging()
        logging.getLogger("test.logging").warning(
            "request access_token=abc123 client_secret=private "
            "password='quoted secret value' "
            "client_secret=\"multi word secret\" "
            'payload={"password": "json-secret", "api_key": "json-key", '
            '"Authorization": "Bearer json-token", "Cookie": "session=json-cookie"} '
            "--api-key cli-secret --password='cli quoted secret' "
            "Cookie: session=secret-value; tracking=private-cookie\n"
            "https://user:password@service.test/path?api_key=url-secret\nINJECTED"
            "\x85NEXT\u2028LINE\u2029PARAGRAPH file=%s",
            Path.home() / "input.bin",
            extra={
                "request_id": "access_token=id-secret",
                "operation": "password=operation-secret",
                "event_name": "safe-event\nFORGED",
            },
        )
        event = json.loads(capsys.readouterr().err)
        assert event["level"] == "WARNING"
        assert event["service"] == "bannedfuncdetector"
        assert event["component"] == "test.logging"
        assert event["environment"] == "test"
        assert "abc123" not in event["message"]
        assert "private" not in event["message"]
        assert "secret-value" not in event["message"]
        assert "quoted secret value" not in event["message"]
        assert "multi word secret" not in event["message"]
        assert "json-secret" not in event["message"]
        assert "json-key" not in event["message"]
        assert "json-token" not in event["message"]
        assert "json-cookie" not in event["message"]
        assert "cli-secret" not in event["message"]
        assert "cli quoted secret" not in event["message"]
        assert "private-cookie" not in event["message"]
        assert "user" not in event["message"]
        assert "url-secret" not in event["message"]
        assert "https://service.test" in event["message"]
        assert "\\x0a" in event["message"]
        assert "\\x85" in event["message"]
        assert "\\u2028" in event["message"]
        assert "\\u2029" in event["message"]
        assert str(Path.home()) not in event["message"]
        assert str(Path("~") / "input.bin") in event["message"]
        assert "id-secret" not in event["request_id"]
        assert event["operation"] == "password=[REDACTED]"
        assert event["event_name"] == "safe-event\\x0aFORGED"
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_configure_logging_level_environment_overrides_verbose(monkeypatch):
    from bannedfuncdetector.cli_bootstrap import configure_logging

    monkeypatch.setenv("BFD_LOG_LEVEL", "WARNING")
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        configure_logging(verbose=True)
        assert root.level == logging.WARNING
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_invalid_logging_level_falls_back_to_info(monkeypatch):
    from bannedfuncdetector.cli_bootstrap import configure_logging

    monkeypatch.setenv("BFD_LOG_LEVEL", "ROOT")
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        root.handlers.clear()
        configure_logging()
        assert root.level == logging.INFO
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_preconfigured_handlers_keep_destination_and_receive_sanitizer(monkeypatch):
    from io import StringIO

    from bannedfuncdetector.cli_bootstrap import configure_logging

    monkeypatch.setenv("BFD_LOG_FORMAT", "json")
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    root.handlers[:] = [handler]
    try:
        configure_logging()
        logging.getLogger("test.logging").warning(
            "https://user:pass@service.test/path?token=hidden"
        )
        try:
            raise RuntimeError("client_secret=trace-hidden")
        except RuntimeError:
            logging.getLogger("test.logging").exception("operation failed")
        assert root.handlers == [handler]
        assert "user" not in stream.getvalue()
        assert "hidden" not in stream.getvalue()
        assert "trace-hidden" not in stream.getvalue()
        assert "https://service.test" in stream.getvalue()
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_json_logging_includes_context_request_id(monkeypatch, capsys):
    import json

    from bannedfuncdetector.cli_bootstrap import configure_logging, log_context

    monkeypatch.setenv("BFD_LOG_FORMAT", "json")
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        root.handlers.clear()
        configure_logging()
        with log_context("run-123"):
            logging.getLogger("test.logging").info(
                "analysis started",
                extra={
                    "operation": "binary_analysis",
                    "event_name": "analysis_finished",
                    "duration_ms": 12.5,
                    "outcome": "success",
                    "error_type": "RuntimeError",
                },
            )
        event = json.loads(capsys.readouterr().err)
        assert event["request_id"] == "run-123"
        assert event["operation"] == "binary_analysis"
        assert event["event_name"] == "analysis_finished"
        assert event["duration_ms"] == 12.5
        assert event["outcome"] == "success"
        assert event["error_type"] == "RuntimeError"
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_new_request_id_changes_between_cli_runs():
    from bannedfuncdetector.cli_bootstrap import new_request_id

    assert new_request_id() != new_request_id()


def test_operation_context_is_nested_restored_and_overridable(monkeypatch, capsys):
    import json

    from bannedfuncdetector.cli_bootstrap import configure_logging, operation_context

    monkeypatch.setenv("BFD_LOG_FORMAT", "json")
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        root.handlers.clear()
        configure_logging()
        logger = logging.getLogger("test.operation")
        with operation_context("directory_analysis"):
            logger.info("directory event")
            with operation_context("binary_analysis"):
                logger.info("binary event")
                logger.info("explicit event", extra={"operation": "custom_operation"})
            logger.info("directory event resumed")
        logger.info("outside event")

        events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
        assert [event.get("operation") for event in events] == [
            "directory_analysis",
            "binary_analysis",
            "custom_operation",
            "directory_analysis",
            None,
        ]
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_library_log_context_is_unique_and_restores_parent():
    from bannedfuncdetector.cli_bootstrap import (
        ensure_request_id,
        log_context,
        new_log_context,
    )

    with log_context("outer"):
        with new_log_context() as first_id:
            assert ensure_request_id() == first_id
            assert first_id != "outer"
        assert ensure_request_id() == "outer"
        with new_log_context() as second_id:
            assert second_id != first_id


def test_exception_stack_trace_is_sanitized_in_json_logs(monkeypatch, capsys):
    import json

    from bannedfuncdetector.cli_bootstrap import configure_logging

    monkeypatch.setenv("BFD_LOG_FORMAT", "json")
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        root.handlers.clear()
        configure_logging()
        try:
            raise RuntimeError("access_token=hidden-value")
        except RuntimeError:
            logging.getLogger("test.logging").exception("operation failed")
        event = json.loads(capsys.readouterr().err)
        assert "stack_trace" in event
        assert event["error_type"] == "RuntimeError"
        assert "hidden-value" not in event["stack_trace"]
        assert "tests/test_main.py" in event["stack_trace"]
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_logging_formatting_failures_do_not_escape(monkeypatch, capsys):
    import json

    from bannedfuncdetector.cli_bootstrap import configure_logging

    class BadValue:
        def __str__(self):
            raise ValueError("secret formatting detail")

    class BadException(Exception):
        def __str__(self):
            raise RuntimeError("secret exception detail")

    def fail_traceback_formatter(_frames):
        raise RuntimeError("secret formatter detail")

    monkeypatch.setenv("BFD_LOG_FORMAT", "json")
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        root.handlers.clear()
        configure_logging()
        logger = logging.getLogger("test.logging")
        logger.warning("bad value: %s", BadValue())
        import traceback

        monkeypatch.setattr(traceback, "format_list", fail_traceback_formatter)
        try:
            raise BadException()
        except BadException:
            logger.exception("bad exception")

        events = [
            json.loads(line) for line in capsys.readouterr().err.splitlines()
        ]
        assert events[0]["message"] == "[log message formatting failed: ValueError]"
        assert events[1]["error_type"] == "BadException"
        assert events[1]["stack_trace"] == "[stack trace formatting failed: RuntimeError]"
        assert "secret" not in events[1]["stack_trace"]
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_exception_arguments_set_structured_error_type(monkeypatch, capsys):
    import json

    from bannedfuncdetector.cli_bootstrap import configure_logging

    monkeypatch.setenv("BFD_LOG_FORMAT", "json")
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        root.handlers.clear()
        configure_logging()
        logging.getLogger("test.logging").error(
            "operation failed: %s", RuntimeError("diagnostic")
        )

        event = json.loads(capsys.readouterr().err)
        assert event["error_type"] == "RuntimeError"
        assert "diagnostic" in event["message"]
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_log_messages_are_bounded():
    from bannedfuncdetector.infrastructure.logging_config import (
        _MAX_LOG_MESSAGE_CHARS,
        _safe_message,
    )

    message = _safe_message("x" * (_MAX_LOG_MESSAGE_CHARS + 100))

    assert len(message) == _MAX_LOG_MESSAGE_CHARS
    assert message.endswith("[truncated]")


def test_safe_exception_fields_keep_type_and_numeric_code_only():
    from bannedfuncdetector.infrastructure.logging_config import safe_exception_fields

    fields = safe_exception_fields(OSError(13, "password=private-value"))

    assert fields == {"error_type": "PermissionError", "error_code": 13}
    assert "private-value" not in str(fields)


def test_safe_stack_trace_omits_exception_text_and_handles_missing_traceback():
    from bannedfuncdetector.application.observability import (
        current_request_id as legacy_current_request_id,
        safe_stack_trace,
    )
    from bannedfuncdetector.infrastructure.logging_config import _safe_exception_text
    from bannedfuncdetector.observability import (
        current_request_id,
        new_request_id,
    )

    exc = RuntimeError("token=private-value")
    assert safe_stack_trace(exc) == ""
    assert _safe_exception_text((type(exc), exc, None)) == ""

    try:
        raise exc
    except RuntimeError as caught:
        stack_trace = safe_stack_trace(caught)

    assert "test_main.py" in stack_trace
    assert " in test_safe_stack_trace_omits_exception_text_and_handles_missing_traceback" in stack_trace
    assert "token=private-value" not in stack_trace
    assert new_request_id() == current_request_id() == legacy_current_request_id()


def test_configure_logging_supports_stdout_destination(monkeypatch, capsys):
    from bannedfuncdetector.cli_bootstrap import configure_logging

    monkeypatch.setenv("BFD_LOG_DESTINATION", "stdout")
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        root.handlers.clear()
        configure_logging()
        logging.getLogger("test.destination").warning("stdout event")

        assert "stdout event" in capsys.readouterr().out
    finally:
        for handler in root.handlers:
            if handler not in saved_handlers:
                handler.close()
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_configure_logging_rotates_file_destination(monkeypatch, tmp_path):
    import bannedfuncdetector.infrastructure.logging_config as logging_config

    log_file = tmp_path / "detector.log"
    monkeypatch.setenv("BFD_LOG_DESTINATION", f"file:{log_file}")
    monkeypatch.setattr(logging_config, "_LOG_FILE_MAX_BYTES", 32)
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        root.handlers.clear()
        logging_config.configure_logging()
        logger = logging.getLogger("test.destination")
        for index in range(8):
            logger.warning("record %s %s", index, "x" * 64)
        root.handlers[0].flush()

        assert log_file.exists()
        assert (tmp_path / "detector.log.1").exists()
        assert (tmp_path / "detector.log.5").exists()
        assert not (tmp_path / "detector.log.6").exists()
        if os.name == "posix":
            import stat

            assert stat.S_IMODE(log_file.stat().st_mode) == 0o600
            assert stat.S_IMODE((tmp_path / "detector.log.1").stat().st_mode) == 0o600
    finally:
        for handler in root.handlers:
            if handler not in saved_handlers:
                handler.close()
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


@pytest.mark.parametrize("invalid_destination", ["unknown", "file"])
def test_invalid_log_destination_falls_back_to_stderr(
    monkeypatch, capsys, tmp_path, invalid_destination
):
    import json

    from bannedfuncdetector.cli_bootstrap import configure_logging

    if invalid_destination == "file":
        destination = f"file:{tmp_path / 'missing' / 'detector.log'}"
        expected_error = "FileNotFoundError"
    else:
        destination = "network"
        expected_error = "ValueError"
    monkeypatch.setenv("BFD_LOG_DESTINATION", destination)
    monkeypatch.setenv("BFD_LOG_FORMAT", "json")
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        root.handlers.clear()
        configure_logging()
        event = json.loads(capsys.readouterr().err)

        assert event["event_name"] == "logging_destination_fallback"
        assert event["error_type"] == expected_error
    finally:
        for handler in root.handlers:
            if handler not in saved_handlers:
                handler.close()
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_exception_stack_trace_is_sanitized_in_text_logs(monkeypatch, capsys):
    from bannedfuncdetector.cli_bootstrap import configure_logging

    monkeypatch.setenv("BFD_LOG_FORMAT", "text")
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        root.handlers.clear()
        configure_logging()
        try:
            raise RuntimeError("client_secret=hidden-value")
        except RuntimeError:
            logging.getLogger("test.logging").exception("operation failed")
        output = capsys.readouterr().err
        assert 'File "' in output
        assert "hidden-value" not in output
        assert "tests/test_main.py" in output
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_text_formatter_sanitizes_forwarded_stack_trace():
    from bannedfuncdetector.infrastructure.logging_config import (
        _TextLogFormatter,
        operation_context,
    )

    record = logging.LogRecord(
        "test.logging",
        logging.ERROR,
        __file__,
        1,
        "worker failed\u2028forged line",
        (),
        None,
    )
    record.request_id = "worker-run"
    record.stack_trace = "RuntimeError: api_key=hidden-value"

    output = _TextLogFormatter().format(record)
    with operation_context("binary_analysis"):
        scoped_output = _TextLogFormatter().format(record)

    assert output.split(" ", 4)[0].endswith("Z")
    assert output.split(" ", 4)[1:4] == [
        "ERROR",
        "test.logging",
        "request_id=worker-run",
    ]
    assert "hidden-value" not in output
    assert "REDACTED" in output
    assert "\\u2028" in output
    assert "operation=binary_analysis" in scoped_output


def test_worker_queue_handler_preserves_context_and_exception(monkeypatch):
    from queue import Queue

    from bannedfuncdetector.infrastructure.logging_config import (
        configure_worker_logging,
        log_context,
    )

    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    log_queue = Queue()
    try:
        monkeypatch.setenv("BFD_LOG_LEVEL", "DEBUG")
        configure_worker_logging(verbose=False, log_queue=log_queue)
        with log_context("worker-run"):
            logging.getLogger("test.queue").warning("worker message")
            try:
                raise RuntimeError("queue exception")
            except RuntimeError:
                logging.getLogger("test.queue").exception("worker error")
        records = [log_queue.get_nowait(), log_queue.get_nowait()]
        assert all(record.request_id == "worker-run" for record in records)
        assert all(record.exc_info is None for record in records)
        assert records[0].message == "worker message"
        assert records[1].stack_trace
        assert "queue exception" not in records[1].stack_trace
        assert records[1].message == "worker error"
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_worker_logging_uses_configured_level(monkeypatch):
    from queue import Queue

    from bannedfuncdetector.cli_bootstrap import configure_worker_logging

    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        monkeypatch.setenv("BFD_LOG_LEVEL", "ERROR")
        configure_worker_logging(verbose=True, log_queue=Queue())
        assert root.level == logging.ERROR
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_saturated_worker_log_queue_reports_drops_and_preserves_errors(
    monkeypatch, capsys
):
    from concurrent.futures import ThreadPoolExecutor
    import json
    from queue import Queue

    from bannedfuncdetector.infrastructure.logging_config import (
        _ContextQueueHandler,
        _RequestContextFilter,
        operation_context,
    )

    monkeypatch.setattr(logging, "raiseExceptions", False)
    monkeypatch.setenv("BFD_LOG_FORMAT", "json")
    log_queue = Queue(maxsize=1)
    log_queue.put_nowait("already queued")
    handler = _ContextQueueHandler(log_queue)
    handler.addFilter(_RequestContextFilter())
    info_records = [
        logging.LogRecord(
            "test.queue", logging.INFO, __file__, 1, "api_key=hidden-value", (), None
        )
        for _ in range(32)
    ]
    error_record = logging.LogRecord(
        "test.queue", logging.ERROR, __file__, 1, "critical event", (), None
    )
    error_record.error_type = "RuntimeError"

    with operation_context("directory_analysis"):
        handler.handle(info_records[0])
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(handler.handle, info_records[1:]))
    with operation_context("directory_analysis"):
        handler.handle(error_record)

    assert log_queue.qsize() == 1
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert [event.get("event_name") for event in events] == [
        "worker_log_queue_saturated",
        None,
    ]
    assert events[0]["outcome"] == "degraded"
    assert events[0]["operation"] == "directory_analysis"
    assert events[1]["level"] == "ERROR"
    assert events[1]["error_type"] == "RuntimeError"
    assert events[1]["operation"] == "directory_analysis"
    assert "hidden-value" not in "\n".join(event["message"] for event in events)

    log_queue.get_nowait()
    recovered_record = logging.LogRecord(
        "test.queue", logging.INFO, __file__, 1, "recovered", (), None
    )
    with operation_context("directory_analysis"):
        handler.handle(recovered_record)
    recovered = json.loads(capsys.readouterr().err)
    assert recovered["event_name"] == "worker_log_queue_recovered"
    assert recovered["dropped_count"] == len(info_records)
    assert log_queue.get_nowait().message == "recovered"


def test_failed_stream_destination_does_not_raise(monkeypatch):
    class BrokenStream:
        def write(self, _value):
            raise OSError("destination unavailable")

        def flush(self):
            pass

    monkeypatch.setattr(logging, "raiseExceptions", False)
    handler = logging.StreamHandler(BrokenStream())
    record = logging.LogRecord("test.sink", logging.ERROR, __file__, 1, "event", (), None)

    handler.handle(record)


def test_concurrent_logging_configuration_is_idempotent(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    from bannedfuncdetector.infrastructure.logging_config import (
        _RequestContextFilter,
        _SanitizingFilter,
        configure_logging,
    )

    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        root.handlers.clear()
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(configure_logging, [False] * 64))

        assert len(root.handlers) == 1
        assert sum(
            isinstance(item, _RequestContextFilter)
            for item in root.handlers[0].filters
        ) == 1
        assert sum(
            isinstance(item, _SanitizingFilter)
            for item in root.handlers[0].filters
        ) == 1
    finally:
        for handler in root.handlers:
            if handler not in saved_handlers:
                handler.close()
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_main_warns_when_all_detection_skipped(compiled_binary, tmp_path, caplog):
    """Disabling both detection methods must warn that zero findings is
    meaningless — otherwise it reads as a clean target."""
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)
    with _SysArgvOverride(
        [
            "prog",
            "-f",
            str(binary),
            "--skip-banned",
            "--skip-analysis",
            "-o",
            str(tmp_path / "out"),
        ]
    ):
        with caplog.at_level("WARNING"):
            bannedfunc_module.main()
    assert any("nothing was checked" in r.message for r in caplog.records)


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


def test_requirement_failure_does_not_log_process_output(monkeypatch, caplog):
    from types import SimpleNamespace

    from bannedfuncdetector.infrastructure import validators

    monkeypatch.setattr(
        validators,
        "_run_command",
        lambda _command: SimpleNamespace(
            returncode=1,
            stdout="password=hunter2",
            stderr="token=private-value",
        ),
    )
    caplog.set_level(logging.ERROR, logger=validators.__name__)

    assert not validators._check_single_requirement(
        {
            "name": "sample",
            "command": ["python", "--version"],
            "expected": "expected output",
        }
    )
    assert "hunter2" not in caplog.text
    assert "private-value" not in caplog.text
    assert "exit_code=1" in caplog.text
    event = next(record for record in caplog.records if record.event_name == "requirement_check_failed")
    assert event.operation == "requirement_check"
    assert event.outcome == "error"
    assert event.error_code == 1


def test_requirement_exception_log_omits_exception_text(monkeypatch, caplog):
    from bannedfuncdetector.infrastructure import validators

    def fail(_command):
        raise PermissionError(errno.EACCES, "token=private-value")

    monkeypatch.setattr(validators, "_run_command", fail)
    caplog.set_level(logging.ERROR, logger=validators.__name__)

    assert not validators._check_single_requirement(
        {
            "name": "sample",
            "command": ["python", "--version"],
            "expected": "Python",
        }
    )

    record = next(
        record for record in caplog.records if record.event_name == "requirement_command_failed"
    )
    assert record.operation == "requirement_check"
    assert record.error_type == "PermissionError"
    assert record.error_code == errno.EACCES
    assert "private-value" not in caplog.text


def test_check_single_requirement_blocked_command(caplog):
    """_check_single_requirement blocks commands not in ALLOWED_REQUIREMENT_EXECUTABLES."""
    caplog.set_level(logging.ERROR, logger="bannedfuncdetector.infrastructure.validators")
    result = _check_single_requirement(
        {
            "name": "test",
            "command": ["curl", "token=private-value"],
            "expected": "anything",
        }
    )
    assert result is False
    assert "curl" not in ALLOWED_REQUIREMENT_EXECUTABLES
    event = next(record for record in caplog.records if record.event_name == "requirement_command_blocked")
    assert event.operation == "requirement_check"
    assert event.outcome == "blocked"
    assert event.error_type == "ValueError"
    assert "curl" not in caplog.text
    assert "private-value" not in caplog.text


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


def test_check_single_requirement_missing_name_is_handled(caplog):
    caplog.set_level(logging.ERROR, logger="bannedfuncdetector.infrastructure.validators")
    result = _check_single_requirement({"command": ["python", "--version"]})

    assert result is False
    event = next(
        record
        for record in caplog.records
        if record.event_name == "requirement_configuration_error"
    )
    assert event.error_type == "KeyError"
    assert "unknown" in event.getMessage()


def test_validate_requirements_skip():
    """validate_requirements returns immediately when skip is True."""
    # Should not raise SystemExit
    validate_requirements(
        True,
        check_requirements=lambda skip: False,  # would fail if called
        logger=logging.getLogger("test"),
    )


def test_validate_requirements_success(caplog):
    """validate_requirements passes when check returns True."""
    from bannedfuncdetector.cli_bootstrap import configure_logging

    logger = logging.getLogger("test.requirements")
    caplog.set_level(logging.INFO, logger=logger.name)
    configure_logging()
    validate_requirements(
        False,
        check_requirements=lambda skip: True,
        logger=logger,
    )
    event = next(
        record
        for record in caplog.records
        if getattr(record, "event_name", None) == "requirements_check_completed"
    )
    assert event.operation == "requirements_check"
    assert event.duration_ms >= 0
    assert event.outcome == "success"


def test_validate_requirements_failure(caplog):
    """validate_requirements calls sys.exit(1) when check returns False."""
    from bannedfuncdetector.cli_bootstrap import configure_logging

    logger = logging.getLogger("test.requirements")
    caplog.set_level(logging.ERROR, logger=logger.name)
    configure_logging()
    with pytest.raises(SystemExit) as exc_info:
        validate_requirements(
            False,
            check_requirements=lambda skip: False,
            logger=logger,
        )
    assert exc_info.value.code == 1
    event = next(
        record
        for record in caplog.records
        if getattr(record, "event_name", None) == "requirements_check_failed"
    )
    assert event.operation == "requirements_check"
    assert event.duration_ms >= 0
    assert event.outcome == "error"
    assert event.error_code == 1


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


def test_unwrap_or_log_adds_structured_execution_error_fields(caplog):
    from bannedfuncdetector.application.analysis_error import (
        BinaryExecutionError,
        ExecutionFailure,
    )

    result = Err(
        ExecutionFailure(
            error=BinaryExecutionError(
                category="I/O error",
                context="sample.bin",
                message="access denied",
                phase="opening_binary",
            )
        )
    )

    with caplog.at_level(logging.ERROR):
        assert unwrap_or_log(result, "Analysis failed", logger=logging.getLogger()) is None

    record = next(record for record in caplog.records if record.event_name == "analysis_error")
    assert record.outcome == "error"
    assert record.error_category == "I/O error"
    assert record.error_phase == "opening_binary"
    assert "access denied" in record.getMessage()


def test_unwrap_or_log_does_not_repeat_logged_execution_failure(caplog):
    from bannedfuncdetector.application.analysis_error import (
        BinaryExecutionError,
        ExecutionFailure,
    )

    result = Err(
        ExecutionFailure(
            error=BinaryExecutionError(
                category="Runtime error", context="sample.bin", message="failed"
            ),
            logged=True,
        )
    )

    with caplog.at_level(logging.ERROR):
        assert (
            unwrap_or_log(result, "Analysis failed", logger=logging.getLogger()) is None
        )

    assert caplog.text == ""


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


def test_main_output_dir_is_a_file_returns_1(compiled_binary, tmp_path):
    """`-o <regular file>` must fail cleanly (exit 1), not raise FileExistsError.

    os.makedirs(path, exist_ok=True) still raises when the path exists but is a
    regular file; main() now catches that and returns 1 instead of crashing.
    """
    binary = tmp_path / "sample.bin"
    os.link(compiled_binary, binary)
    output_file = tmp_path / "output_is_a_file"
    output_file.write_text("not a directory")

    with _SysArgvOverride(
        [
            "prog",
            "-f",
            str(binary),
            "--skip-analysis",
            "--skip-banned",
            "-o",
            str(output_file),
        ]
    ):
        assert bannedfunc_module.main() == 1
