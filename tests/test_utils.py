import io
import os
import subprocess
import sys

from bannedfuncdetector.file_detection import is_executable_file, find_pe_files
from bannedfuncdetector.infrastructure.adapters.r2ai_server import check_r2ai_server_available
from conftest import start_test_server


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


def test_check_r2ai_server_available_start_cancel(r2ai_server_shim, stdin_stream):
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{r2ai_server_shim.parent}:{original_path}"
    original_stdin = sys.stdin
    sys.stdin = stdin_stream("n\n")
    try:
        assert check_r2ai_server_available("http://127.0.0.1:9") is False
    finally:
        sys.stdin = original_stdin
        os.environ["PATH"] = original_path


def test_check_r2ai_server_available_start_success(r2ai_server_shim, stdin_stream):
    server_url, server = start_test_server(
        ping_status=200,
        models_status=200,
        models_payload=b'{"models": ["a"]}',
    )
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{r2ai_server_shim.parent}:{original_path}"
    original_stdin = sys.stdin
    sys.stdin = stdin_stream("y\n\n")
    try:
        assert check_r2ai_server_available(server_url) is True
    finally:
        sys.stdin = original_stdin
        os.environ["PATH"] = original_path
        server.shutdown()


def test_check_r2ai_server_available_start_with_model(r2ai_server_shim, stdin_stream):
    server_url, server = start_test_server(
        ping_status=200,
        models_status=200,
        models_payload=b'{"models": ["a"]}',
    )
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{r2ai_server_shim.parent}:{original_path}"
    original_stdin = sys.stdin
    sys.stdin = stdin_stream("y\ncustom-model\n")
    try:
        assert check_r2ai_server_available(server_url) is True
    finally:
        sys.stdin = original_stdin
        os.environ["PATH"] = original_path
        server.shutdown()


def test_check_r2ai_server_available_models_unavailable(r2ai_server_shim, stdin_stream):
    # Replace shim with one that returns empty models list
    script = r2ai_server_shim.parent / "r2ai-server"
    script.write_text("#!/bin/sh\nif [ \"$1\" = \"-h\" ]; then exit 0; fi\nif [ \"$1\" = \"-m\" ]; then exit 1; fi\nexit 0\n")
    os.chmod(script, 0o755)

    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{r2ai_server_shim.parent}:{original_path}"
    original_stdin = sys.stdin
    sys.stdin = stdin_stream("y\n\n")
    try:
        assert check_r2ai_server_available("http://127.0.0.1:9") is False
    finally:
        sys.stdin = original_stdin
        os.environ["PATH"] = original_path


def test_check_r2ai_server_available_not_installed_cancel(r2ai_server_fail_shim, stdin_stream):
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{r2ai_server_fail_shim.parent}:{original_path}"
    original_stdin = sys.stdin
    sys.stdin = stdin_stream("n\n")
    try:
        assert check_r2ai_server_available("http://127.0.0.1:9") is False
    finally:
        sys.stdin = original_stdin
        os.environ["PATH"] = original_path


def test_check_r2ai_server_available_install_path(r2ai_server_fail_shim, r2pm_shim, stdin_stream):
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{r2ai_server_fail_shim.parent}:{original_path}"
    original_stdin = sys.stdin
    sys.stdin = stdin_stream("y\nn\n")
    try:
        assert check_r2ai_server_available("http://127.0.0.1:18081") is False
    finally:
        sys.stdin = original_stdin
        os.environ["PATH"] = original_path


def test_check_r2ai_server_available_subprocess_error(stdin_stream, tmp_path):
    # Ensure r2ai-server is not found in PATH
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = str(tmp_path)
    original_stdin = sys.stdin
    sys.stdin = stdin_stream("n\n")
    try:
        assert check_r2ai_server_available("http://127.0.0.1:9") is False
    finally:
        sys.stdin = original_stdin
        os.environ["PATH"] = original_path


def test_check_r2ai_server_available_start_server_loop(r2ai_server_with_models_shim, stdin_stream, path_with_shim):
    path_manager = path_with_shim(r2ai_server_with_models_shim)
    original_path = path_manager["original_path"]
    os.environ["PATH"] = path_manager["modified_path"]
    original_stdin = sys.stdin
    sys.stdin = stdin_stream("y\n\n")
    try:
        assert check_r2ai_server_available("http://127.0.0.1:18080") is True
    finally:
        sys.stdin = original_stdin
        os.environ["PATH"] = original_path


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


def test_check_r2ai_server_available_start_server_with_model(r2ai_server_single_model_shim, stdin_stream, path_with_shim):
    path_manager = path_with_shim(r2ai_server_single_model_shim)
    original_path = path_manager["original_path"]
    os.environ["PATH"] = path_manager["modified_path"]
    original_stdin = sys.stdin
    sys.stdin = stdin_stream("y\ncustom-model\n")
    try:
        assert check_r2ai_server_available("http://127.0.0.1:18082") is True
    finally:
        sys.stdin = original_stdin
        os.environ["PATH"] = original_path


def test_check_r2ai_server_available_start_server_error(monkeypatch, r2ai_server_shim, stdin_stream):
    import bannedfuncdetector.infrastructure.adapters.r2ai_server as r2ai_server
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{r2ai_server_shim.parent}:{original_path}"
    original_stdin = sys.stdin
    sys.stdin = stdin_stream("y\n\n")

    def raise_error(*_args, **_kwargs):
        # Use OSError which is a realistic exception for subprocess.Popen failures
        # (e.g., command not found)
        raise OSError("boom")

    class DummyResult:
        def __init__(self, returncode=0, stdout="model-a\n"):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = ""

    def fake_run(command, *args, **kwargs):
        if isinstance(command, list) and "-m" in command:
            return DummyResult(stdout="model-a\n")
        return DummyResult(stdout="usage: r2ai-server")

    monkeypatch.setattr(r2ai_server.subprocess, "run", fake_run)
    monkeypatch.setattr(r2ai_server.subprocess, "Popen", raise_error)
    try:
        assert check_r2ai_server_available("http://127.0.0.1:9") is False
    finally:
        sys.stdin = original_stdin
        os.environ["PATH"] = original_path


def test_check_r2ai_server_available_start_server_timeout(r2ai_server_no_server_shim, stdin_stream, path_with_shim):
    path_manager = path_with_shim(r2ai_server_no_server_shim)
    original_path = path_manager["original_path"]
    os.environ["PATH"] = path_manager["modified_path"]
    original_stdin = sys.stdin
    sys.stdin = stdin_stream("y\n\n")
    try:
        assert check_r2ai_server_available("http://127.0.0.1:18083") is False
    finally:
        sys.stdin = original_stdin
        os.environ["PATH"] = original_path


def test_check_r2ai_server_available_install_error(monkeypatch, r2ai_server_fail_shim, stdin_stream):
    import bannedfuncdetector.infrastructure.adapters.r2ai_server as r2ai_server
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{r2ai_server_fail_shim.parent}:{original_path}"
    original_stdin = sys.stdin
    sys.stdin = stdin_stream("y\n")

    def fake_run(command, *args, **kwargs):
        # Check if this is an r2pm install command (may have absolute path after _resolve_command)
        cmd_str = str(command)
        if "r2pm" in cmd_str and "install" in cmd_str:
            # Use subprocess.CalledProcessError which is caught by the exception handler
            raise subprocess.CalledProcessError(1, command, "Install failed")
        class Dummy:
            returncode = 1
            stdout = ""
            stderr = ""
        return Dummy()

    monkeypatch.setattr(r2ai_server.subprocess, "run", fake_run)
    try:
        assert check_r2ai_server_available("http://127.0.0.1:18084") is False
    finally:
        sys.stdin = original_stdin
        os.environ["PATH"] = original_path
