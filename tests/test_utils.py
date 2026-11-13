import os
import logging
import subprocess
import sys

import pytest

from bannedfuncdetector.infrastructure.file_detection import (
    is_executable_file,
    find_pe_files,
)
from bannedfuncdetector.infrastructure.adapters.r2ai_server import (
    check_r2ai_server_available,
)
from conftest import start_test_server

skip_on_windows = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Test uses Unix-specific paths or behavior",
)


@skip_on_windows
def test_is_executable_file_and_find_pe_files(pe_file, tmp_path):
    non_pe = tmp_path / "note.txt"
    non_pe.write_text("hello")
    assert is_executable_file(pe_file, "pe") is True
    assert is_executable_file(str(non_pe), "pe") is False
    pe_files = find_pe_files(str(tmp_path))
    assert pe_file in pe_files


def test_is_executable_file_missing(tmp_path):
    missing = tmp_path / "missing.exe"
    assert is_executable_file(str(missing), "pe") is False


def test_check_r2ai_server_available_success_models():
    server_url, server = start_test_server(
        ping_status=200,
        models_status=200,
        models_payload=b'{"models": ["a", "b"]}',
    )
    try:
        assert check_r2ai_server_available(server_url) is True
    finally:
        server.shutdown()


def test_r2ai_logs_omit_remote_url_and_model_data(monkeypatch, caplog):
    from bannedfuncdetector.infrastructure.adapters import r2ai_server

    secret_model = "remote\nlevel=CRITICAL token=super-secret"

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"models": [secret_model]}

    monkeypatch.setattr(r2ai_server.requests, "get", lambda *_args, **_kwargs: Response())
    caplog.set_level(logging.INFO, logger=r2ai_server.__name__)
    server_url = "https://user:password@example.test/private?token=url-secret"

    assert r2ai_server.check_r2ai_server_available(server_url) is True
    r2ai_server._log_model_list([secret_model], header="Available models:")

    log_text = caplog.text
    assert "user:password" not in log_text
    assert "private" not in log_text
    assert "url-secret" not in log_text
    assert "super-secret" not in log_text
    assert "level=CRITICAL" not in log_text
    assert "Available model count: 1" in log_text
    assert secret_model not in log_text
    records = [record for record in caplog.records if record.name == r2ai_server.__name__]
    assert any(record.event_name == "optional_service_available" for record in records)
    assert any("Models available in r2ai-server: 1" == record.getMessage() for record in records)


def test_r2ai_start_failure_logs_type_without_exception_text(monkeypatch, caplog):
    from bannedfuncdetector.infrastructure.adapters import r2ai_server

    monkeypatch.setattr(r2ai_server, "_get_models_from_cli", lambda: ["model-a"])

    def fail_command(_model):
        raise RuntimeError("password=private-value")

    monkeypatch.setattr(r2ai_server, "_build_server_command", fail_command)
    caplog.set_level(logging.ERROR, logger=r2ai_server.__name__)

    assert r2ai_server._start_r2ai_server(
        "http://localhost:8080", prompt_callback=lambda _prompt: "model-a"
    ) is False

    assert "private-value" not in caplog.text
    event = next(record for record in caplog.records if record.name == r2ai_server.__name__)
    assert event.event_name == "external_service_start_failed"
    assert event.error_type == "RuntimeError"


def test_r2ai_model_fetch_failure_is_logged_once(monkeypatch, caplog):
    from bannedfuncdetector.infrastructure.adapters import r2ai_server

    class PingResponse:
        status_code = 200

    def fail_models(url, **_kwargs):
        if url.endswith("/ping"):
            return PingResponse()
        raise r2ai_server.requests.ConnectionError("password=private-value")

    monkeypatch.setattr(r2ai_server.requests, "get", fail_models)
    caplog.set_level(logging.WARNING, logger=r2ai_server.__name__)

    assert r2ai_server.check_r2ai_server_available("http://localhost:8080") is True

    warnings = [
        record
        for record in caplog.records
        if record.name == r2ai_server.__name__ and record.levelno == logging.WARNING
    ]
    assert len(warnings) == 1
    assert warnings[0].event_name == "optional_service_models_failed"
    assert warnings[0].error_type == "ConnectionError"
    assert warnings[0].duration_ms >= 0
    assert "private-value" not in caplog.text

    class ModelsErrorResponse:
        status_code = 503

    def return_http_error(url, **_kwargs):
        return PingResponse() if url.endswith("/ping") else ModelsErrorResponse()

    caplog.clear()
    monkeypatch.setattr(r2ai_server.requests, "get", return_http_error)
    assert r2ai_server.check_r2ai_server_available("http://localhost:8080") is True
    warnings = [
        record
        for record in caplog.records
        if record.name == r2ai_server.__name__ and record.levelno == logging.WARNING
    ]
    assert len(warnings) == 1
    assert warnings[0].error_type == "HTTPStatusError"
    assert warnings[0].error_code == 503
    assert warnings[0].duration_ms >= 0


def test_check_r2ai_server_available_success_no_models():
    server_url, server = start_test_server(
        ping_status=200,
        models_status=200,
        models_payload=b'{"models": []}',
    )
    try:
        assert check_r2ai_server_available(server_url) is True
    finally:
        server.shutdown()


def test_check_r2ai_server_available_models_error():
    server_url, server = start_test_server(
        ping_status=200,
        models_status=200,
        models_payload=b"not-json",
    )
    try:
        assert check_r2ai_server_available(server_url) is True
    finally:
        server.shutdown()


def test_check_r2ai_server_available_ping_fail():
    server_url, server = start_test_server(ping_status=500)
    try:
        assert check_r2ai_server_available(server_url) is False
    finally:
        server.shutdown()


def test_check_r2ai_server_available_start_cancel(
    r2ai_server_shim, path_with_shim, mock_stdin
):
    with path_with_shim(r2ai_server_shim), mock_stdin("n\n"):
        assert check_r2ai_server_available("http://127.0.0.1:9") is False


def test_check_r2ai_server_available_start_success(
    r2ai_server_shim, path_with_shim, mock_stdin
):
    server_url, server = start_test_server(
        ping_status=200,
        models_status=200,
        models_payload=b'{"models": ["a"]}',
    )
    try:
        with path_with_shim(r2ai_server_shim), mock_stdin("y\n\n"):
            assert check_r2ai_server_available(server_url) is True
    finally:
        server.shutdown()


def test_check_r2ai_server_available_start_with_model(
    r2ai_server_shim, path_with_shim, mock_stdin
):
    server_url, server = start_test_server(
        ping_status=200,
        models_status=200,
        models_payload=b'{"models": ["a"]}',
    )
    try:
        with path_with_shim(r2ai_server_shim), mock_stdin("y\ncustom-model\n"):
            assert check_r2ai_server_available(server_url) is True
    finally:
        server.shutdown()


def test_check_r2ai_server_available_models_unavailable(
    r2ai_server_shim, path_with_shim, mock_stdin
):
    # Replace shim with one that returns empty models list
    script = r2ai_server_shim.parent / "r2ai-server"
    script.write_text(
        '#!/bin/sh\nif [ "$1" = "-h" ]; then exit 0; fi\nif [ "$1" = "-m" ]; then exit 1; fi\nexit 0\n'
    )
    os.chmod(script, 0o755)

    with path_with_shim(r2ai_server_shim), mock_stdin("y\n\n"):
        assert check_r2ai_server_available("http://127.0.0.1:9") is False


def test_check_r2ai_server_available_not_installed_cancel(
    r2ai_server_fail_shim, path_with_shim, mock_stdin
):
    with path_with_shim(r2ai_server_fail_shim), mock_stdin("n\n"):
        assert check_r2ai_server_available("http://127.0.0.1:9") is False


def test_check_r2ai_server_available_install_path(
    r2ai_server_fail_shim, r2pm_shim, path_with_shim, mock_stdin
):
    with path_with_shim(r2ai_server_fail_shim), mock_stdin("y\nn\n"):
        assert check_r2ai_server_available("http://127.0.0.1:18081") is False


def test_check_r2ai_server_available_subprocess_error(mock_stdin, tmp_path):
    # Ensure r2ai-server is not found in PATH (replace PATH entirely)
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = str(tmp_path)
    try:
        with mock_stdin("n\n"):
            assert check_r2ai_server_available("http://127.0.0.1:9") is False
    finally:
        os.environ["PATH"] = original_path


def test_check_r2ai_server_available_server_already_running():
    """Test check_r2ai_server_available when server is already running (ping succeeds)."""
    server_url, server = start_test_server(ping_status=200, models_status=200)
    try:
        assert check_r2ai_server_available(server_url) is True
    finally:
        server.shutdown()


def test_check_r2ai_server_available_models_many():
    server_url, server = start_test_server(
        ping_status=200,
        models_status=200,
        models_payload=b'{"models": ["a","b","c","d","e","f","g"]}',
    )
    try:
        assert check_r2ai_server_available(server_url) is True
    finally:
        server.shutdown()


def test_start_test_server_unknown_path():
    import requests

    server_url, server = start_test_server()
    try:
        response = requests.get(f"{server_url}/unknown", timeout=2)
        assert response.status_code == 404
    finally:
        server.shutdown()


def test_check_r2ai_server_available_ping_ok_but_models_fail():
    """Test check_r2ai_server_available when ping works but models endpoint fails."""
    server_url, server = start_test_server(ping_status=200, models_status=500)
    try:
        # Should still return True since ping succeeded
        assert check_r2ai_server_available(server_url) is True
    finally:
        server.shutdown()


def test_launch_server_process_popen_error():
    """Test _launch_server_process handles Popen failure gracefully."""
    from bannedfuncdetector.infrastructure.adapters.r2ai_server import (
        _launch_server_process,
    )

    def raise_error(*_args, **_kwargs):
        raise OSError("boom")

    # _launch_server_process accepts a popen callable for testability
    try:
        _launch_server_process(
            ["r2ai-server", "-l", "r2ai"],
            popen=raise_error,
        )
        launched = True
    except OSError:
        launched = False
    assert launched is False


def test_check_r2ai_server_available_start_server_timeout(
    r2ai_server_no_server_shim, path_with_shim, mock_stdin
):
    with path_with_shim(r2ai_server_no_server_shim), mock_stdin("y\n\n"):
        assert check_r2ai_server_available("http://127.0.0.1:18083") is False


def test_prompt_install_r2ai_server_run_error():
    """Test _prompt_install_r2ai_server handles install failure gracefully."""
    from bannedfuncdetector.infrastructure.adapters.r2ai_server import (
        _prompt_install_r2ai_server,
    )

    def failing_run(command, *args, **kwargs):
        raise subprocess.CalledProcessError(1, command, "Install failed")

    result = _prompt_install_r2ai_server(
        "http://127.0.0.1:9",
        prompt_callback=lambda _prompt: "y",
        run=failing_run,
    )
    assert result is False


def test_run_r2ai_server_command_missing_binary_returns_failure(monkeypatch):
    """A genuinely-absent binary surfaces as a returncode=1 result, not an exception."""
    from bannedfuncdetector.infrastructure.adapters import r2ai_server

    def missing(*_args, **_kwargs):
        raise FileNotFoundError("No such file or directory: 'r2ai-server'")

    monkeypatch.setattr(r2ai_server.subprocess, "run", missing)
    result = r2ai_server._run_r2ai_server_command(["r2ai-server", "-h"])
    assert result.returncode == 1
    assert "r2ai-server" in result.stderr


def test_handle_r2ai_server_not_running_missing_binary_offers_install(monkeypatch):
    """When the binary is absent, the user is offered installation (not silently False)."""
    from bannedfuncdetector.infrastructure.adapters import r2ai_server

    def missing(*_args, **_kwargs):
        raise FileNotFoundError("No such file or directory: 'r2ai-server'")

    monkeypatch.setattr(r2ai_server.subprocess, "run", missing)
    prompts: list[str] = []

    def record_decline(prompt: str) -> str:
        prompts.append(prompt)
        return "n"

    result = r2ai_server._handle_r2ai_server_not_running(
        "http://127.0.0.1:9",
        auto_start=False,
        prompt_callback=record_decline,
    )
    assert result is False
    assert any("install" in prompt.lower() for prompt in prompts)


def test_handle_r2ai_server_not_running_prompt_ioerror_returns_false(monkeypatch):
    """An I/O failure while prompting the user is handled, not propagated."""
    from bannedfuncdetector.infrastructure.adapters import r2ai_server

    installed = subprocess.CompletedProcess(
        ["r2ai-server", "-h"], returncode=0, stdout="usage", stderr=""
    )
    monkeypatch.setattr(
        r2ai_server, "_run_r2ai_server_command", lambda *_a, **_k: installed
    )

    def failing_prompt(_prompt: str) -> str:
        raise OSError("stdin unavailable")

    result = r2ai_server._handle_r2ai_server_not_running(
        "http://127.0.0.1:9",
        auto_start=False,
        prompt_callback=failing_prompt,
    )
    assert result is False
