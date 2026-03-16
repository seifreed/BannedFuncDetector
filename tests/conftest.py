import copy
import io
import os
import subprocess
import textwrap
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import pytest
import r2pipe


# Type aliases for better readability
CommandHandler = Union[str, Callable[[], str], None]
CommandJsonHandler = Union[Dict[str, Any], List[Any], Callable[[], Any], None]
CommandMap = Dict[str, CommandHandler]
CommandJsonMap = Dict[str, CommandJsonHandler]


class FakeR2:
    """
    A comprehensive fake r2pipe instance for testing.

    Supports both simple value returns and callable handlers for dynamic responses.
    Tracks all calls made to cmd() and cmdj() for verification in tests.
    Supports pattern matching with '*' suffix for partial command matching.

    Attributes:
        cmd_map: Mapping of commands to their responses (str, callable, or None)
        cmdj_map: Mapping of commands to their JSON responses (dict, list, callable, or None)
        calls: List of (method, command) tuples tracking all calls made

    Examples:
        >>> fake = FakeR2(cmd_map={"aaa": "analysis done"})
        >>> fake.cmd("aaa")
        'analysis done'

        >>> fake = FakeR2(cmdj_map={"aflj": [{"name": "main"}]})
        >>> fake.cmdj("aflj")
        [{'name': 'main'}]

        >>> fake = FakeR2(cmd_map={"s *": ""})  # Pattern matching
        >>> fake.cmd("s main")
        ''
    """

    def __init__(
        self,
        cmd_map: Optional[CommandMap] = None,
        cmdj_map: Optional[CommandJsonMap] = None,
    ) -> None:
        self.cmd_map: CommandMap = cmd_map or {}
        self.cmdj_map: CommandJsonMap = cmdj_map or {}
        self._calls: List[Tuple[str, str]] = []

    @property
    def calls(self) -> List[Tuple[str, str]]:
        """Return list of (method, command) tuples for all calls made."""
        return self._calls

    def cmd(self, command: str) -> str:
        """
        Execute a command and return string result.

        Supports exact matches and pattern matching with '*' suffix.
        Callable handlers are invoked to get the result.

        Args:
            command: The r2 command to execute

        Returns:
            The command output as a string, or empty string if not found
        """
        self._calls.append(("cmd", command))

        # Try exact match first
        handler = self.cmd_map.get(command)
        if handler is not None:
            return handler() if callable(handler) else handler

        # Try pattern matching with '*' suffix
        for key, value in self.cmd_map.items():
            if isinstance(key, str) and key.endswith("*") and command.startswith(key[:-1]):
                return value() if callable(value) else (value if value is not None else "")

        return ""

    def cmdj(self, command: str) -> Optional[Union[Dict[str, Any], List[Any]]]:
        """
        Execute a command and return JSON result.

        Callable handlers are invoked to get the result.

        Args:
            command: The r2 command to execute

        Returns:
            The command output as dict/list, or None if not found
        """
        self._calls.append(("cmdj", command))
        handler = self.cmdj_map.get(command)
        if callable(handler):
            return handler()
        return handler

    def quit(self) -> None:
        pass

    def __enter__(self) -> "FakeR2":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass


# =============================================================================
# FAKE FACTORIES FOR TESTING
# =============================================================================


class FakeR2ClientFactory:
    """
    Fake factory for creating fake R2Client instances in tests.

    This factory is designed for use in unit tests where you don't want
    to interact with real binaries. It returns a configurable fake client.

    Attributes:
        _fake_client: The fake client to return from create().

    Example:
        >>> fake_client = FakeR2(cmdj_map={"aflj": [{"name": "main"}]})
        >>> factory = FakeR2ClientFactory(fake_client)
        >>> client = factory.create("/any/path")
        >>> functions = client.cmdj("aflj")
        >>> assert functions[0]["name"] == "main"
    """

    def __init__(self, fake_client: Any) -> None:
        """
        Initialize the factory with a fake client.

        Args:
            fake_client: The fake client instance to return from create().
                        Should implement the IR2Client protocol.
        """
        self._fake_client = fake_client

    def create(
        self,
        file_path: str,
        flags: List[str] | None = None
    ) -> Any:
        """
        Return the configured fake client.

        Args:
            file_path: Ignored - the fake client is returned regardless.
            flags: Ignored - the fake client is returned regardless.

        Returns:
            The fake client configured in __init__.
        """
        return self._fake_client


# Backward-compatible alias


class FakeConfigRepository:
    """
    Fake configuration repository for testing.

    This class provides a simple implementation of IConfigRepository
    that can be configured with test-specific values.

    Attributes:
        _config: Dictionary containing the configuration values.

    Example:
        >>> fake_config = FakeConfigRepository({
        ...     "banned_functions": ["strcpy"],
        ...     "output": {"directory": "/tmp/test"}
        ... })
        >>> assert fake_config.get("banned_functions") == ["strcpy"]
        >>> assert fake_config.get_output_dir() == "/tmp/test"
    """

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        """
        Initialize the fake configuration.

        Args:
            config: Dictionary containing configuration values.
                   If None, uses an empty dictionary.
        """
        self._config = config if config is not None else {}

    def get(self, key: str, default=None):
        """Get a configuration value by key."""
        return self._config.get(key, default)

    def __getitem__(self, key: str):
        """Get a configuration value using bracket notation."""
        return self._config[key]

    def __contains__(self, key: str) -> bool:
        """Check if a key exists in configuration."""
        return key in self._config

    def get_output_dir(self) -> str:
        """Get the configured output directory path."""
        output = self._config.get("output", {})
        if isinstance(output, dict):
            return output.get("directory", "output")
        return "output"

    def keys(self):
        """Return configuration keys."""
        return self._config.keys()

    def items(self):
        """Return configuration items."""
        return self._config.items()

    def to_dict(self) -> Dict[str, Any]:
        """Return the configuration as a dictionary."""
        return copy.deepcopy(self._config)


# Backward-compatible alias


class FakeDecompilerOrchestrator:
    """
    Configurable fake implementation of IDecompilerOrchestrator for testing.

    Supports configurable return values for decompile_function,
    select_decompiler, and check_decompiler_available.

    Args:
        decompile_result: Result to return from decompile_function.
            If callable, it will be called with (r2, function_name, decompiler_type).
            If an Exception instance, it will be raised.
            Otherwise returned directly (should be a Result[str, str]).
        select_result: Value to return from select_decompiler. Defaults to "default".
        available_result: Value to return from check_decompiler_available. Defaults to True.

    Example:
        >>> from bannedfuncdetector.domain.result import ok
        >>> orch = FakeDecompilerOrchestrator(decompile_result=ok("int main() {}"))
        >>> result = orch.decompile_function(None, "main", "default")
        >>> assert result.is_ok()
    """

    def __init__(
        self,
        decompile_result: Any = None,
        select_result: str = "default",
        available_result: bool = True,
    ) -> None:
        self._decompile_result = decompile_result
        self._select_result = select_result
        self._available_result = available_result

    def decompile_function(self, r2: Any, function_name: str, decompiler_type: Any = None, **options: Any) -> Any:
        if isinstance(self._decompile_result, Exception):
            raise self._decompile_result
        if callable(self._decompile_result):
            return self._decompile_result(r2, function_name, decompiler_type)
        return self._decompile_result

    def select_decompiler(self, requested: Any = None, force: bool = False) -> str:
        return self._select_result

    def check_decompiler_available(self, decompiler_type: Any) -> bool:
        return self._available_result


@pytest.fixture
def fake_r2() -> FakeR2:
    """
    Fixture providing a basic FakeR2 instance with empty maps.

    Returns:
        A FakeR2 instance ready for configuration
    """
    return FakeR2()


@pytest.fixture
def fake_r2_factory() -> Callable[..., FakeR2]:
    """
    Fixture providing a factory function to create configured FakeR2 instances.

    Returns:
        A factory function that accepts cmd_map and cmdj_map parameters

    Example:
        def test_something(fake_r2_factory):
            fake = fake_r2_factory(
                cmd_map={"aaa": "done"},
                cmdj_map={"aflj": [{"name": "main"}]}
            )
    """
    def _factory(
        cmd_map: Optional[CommandMap] = None,
        cmdj_map: Optional[CommandJsonMap] = None,
    ) -> FakeR2:
        return FakeR2(cmd_map=cmd_map, cmdj_map=cmdj_map)
    return _factory


@pytest.fixture
def fake_r2_with_functions() -> FakeR2:
    """
    Fixture providing a FakeR2 instance pre-configured with function data.

    Includes common function list data useful for tests that need function information.

    Returns:
        A FakeR2 instance with aflj returning sample function data
    """
    return FakeR2(
        cmdj_map={
            "aflj": [
                {"name": "main", "offset": 0x1000, "size": 100},
                {"name": "helper", "offset": 0x1100, "size": 50},
            ]
        }
    )


@pytest.fixture
def fake_r2_with_imports() -> FakeR2:
    """
    Fixture providing a FakeR2 instance pre-configured with import data.

    Includes sample import data useful for testing import detection.

    Returns:
        A FakeR2 instance with iij returning sample import data
    """
    return FakeR2(
        cmdj_map={
            "iij": [
                {"name": "strcpy", "plt": 0x2000},
                {"name": "malloc", "plt": 0x2010},
            ]
        }
    )


@pytest.fixture
def fake_r2_with_strings() -> FakeR2:
    """
    Fixture providing a FakeR2 instance pre-configured with string data.

    Includes sample string data useful for testing string-based detection.

    Returns:
        A FakeR2 instance with izzj returning sample string data
    """
    return FakeR2(
        cmdj_map={
            "izzj": {
                "strings": [
                    {"string": "strcpy", "paddr": 0x3000},
                    {"string": "gets", "paddr": 0x3010},
                ]
            }
        }
    )


class _TestHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        config = self.server._config
        if self.path == "/ping":
            self.send_response(config.get("ping_status", 200))
            self.end_headers()
            self.wfile.write(b"pong")
            return
        if self.path == "/models":
            self.send_response(config.get("models_status", 200))
            self.end_headers()
            payload = config.get("models_payload", b"{}")
            self.wfile.write(payload)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        """Suppress request logging during tests."""


def start_test_server(
    ping_status: int = 200,
    models_status: int = 200,
    models_payload: bytes = b"{}",
) -> Tuple[str, HTTPServer]:
    """
    Start a test HTTP server for r2ai-server tests.

    Args:
        ping_status: HTTP status code to return for /ping endpoint
        models_status: HTTP status code to return for /models endpoint
        models_payload: Response body for /models endpoint

    Returns:
        Tuple of (server_url, server_instance)
    """
    server = HTTPServer(("127.0.0.1", 0), _TestHTTPHandler)
    server._config = {
        "ping_status": ping_status,
        "models_status": models_status,
        "models_payload": models_payload,
    }
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return f"http://{host}:{port}", server


def write_minimal_pe(path: Any) -> None:
    """
    Write a minimal valid PE file structure for testing.

    Creates a minimal PE32 executable with basic headers that passes
    file format validation checks.

    Args:
        path: Path-like object where the PE file will be written
    """
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    # COFF header
    data[0x84:0x86] = (0x014C).to_bytes(2, "little")  # Machine
    data[0x86:0x88] = (1).to_bytes(2, "little")  # NumberOfSections
    data[0x94:0x96] = (0x00E0).to_bytes(2, "little")  # SizeOfOptionalHeader
    data[0x96:0x98] = (0x010F).to_bytes(2, "little")  # Characteristics
    # Optional header (PE32)
    data[0x98:0x9A] = (0x10B).to_bytes(2, "little")
    # Section header (.text)
    data[0x178:0x180] = b".text\x00\x00\x00"
    with open(path, "wb") as handle:
        handle.write(data)


@pytest.fixture(scope="session")
def compiled_binary(tmp_path_factory):
    temp_dir = tmp_path_factory.mktemp("bin")
    source_path = temp_dir / "sample.c"
    binary_path = temp_dir / "sample.bin"
    source_path.write_text(
        textwrap.dedent(
            """
            #include <stdio.h>
            #include <string.h>
            const char *global_str = "string";
            int helper(const char *input) {
                char buf[64];
                strcpy(buf, input);
                return printf("%s", buf);
            }
            int main(void) {
                return helper("hi");
            }
            """
        )
    )
    subprocess.run(
        ["cc", "-O0", "-g", "-o", str(binary_path), str(source_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return str(binary_path)


def open_r2pipe_with_retry(binary_path: str, *, flags: list[str] | None = None, attempts: int = 3, delay: float = 0.05):
    last_error = None
    for _attempt in range(attempts):
        try:
            return r2pipe.open(binary_path, flags=flags or ["-2"])
        except (BrokenPipeError, OSError, RuntimeError) as exc:
            last_error = exc
            time.sleep(delay)
    assert last_error is not None
    raise last_error


@pytest.fixture()
def pe_file(tmp_path):
    pe_path = tmp_path / "stub.exe"
    write_minimal_pe(pe_path)
    return str(pe_path)


@pytest.fixture()
def shim_path(tmp_path):
    shim_dir = tmp_path / "shims"
    shim_dir.mkdir()
    return shim_dir


def make_executable(path: Any, content: str) -> None:
    """
    Create an executable script file with the given content.

    Args:
        path: Path-like object where the script will be written
        content: Script content (leading whitespace will be stripped)
    """
    path.write_text(content.lstrip())
    os.chmod(path, 0o755)


@pytest.fixture()
def r2ai_server_shim(shim_path):
    script = textwrap.dedent(
        """
        #!/bin/sh
        if [ "$1" = "-h" ]; then
          echo "usage: r2ai-server"
          exit 0
        fi
        if [ "$1" = "-m" ]; then
          echo "model-a"
          echo "model-b"
          exit 0
        fi
        # Simulate background server startup
        sleep 0.1
        exit 0
        """
    )
    path = shim_path / "r2ai-server"
    make_executable(path, script)
    return path


@pytest.fixture()
def r2ai_server_fail_shim(shim_path):
    script = textwrap.dedent(
        """
        #!/bin/sh
        if [ "$1" = "-h" ]; then
          exit 1
        fi
        exit 1
        """
    )
    path = shim_path / "r2ai-server"
    make_executable(path, script)
    return path


@pytest.fixture()
def r2pm_shim(shim_path):
    script = textwrap.dedent(
        """
        #!/bin/sh
        python3 - <<'PY' &
import threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/ping":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"pong")
            return
        if self.path == "/models":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"models": ["a"]}')
            return
        self.send_response(404)
        self.end_headers()
    def log_message(self, format, *args):
        return
server = HTTPServer(("127.0.0.1", 18081), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
time.sleep(3)
server.shutdown()
PY
        exit 0
        """
    )
    path = shim_path / "r2pm"
    make_executable(path, script)
    return path


@pytest.fixture()
def stdin_stream() -> Callable[[str], io.StringIO]:
    """
    Fixture providing a factory to create StringIO objects for stdin mocking.

    Returns:
        A factory function that creates a StringIO with the given value
    """
    def _set(value: str) -> io.StringIO:
        return io.StringIO(value)
    return _set


@pytest.fixture()
def r2ai_server_with_models_shim(shim_path: Any) -> Any:
    """
    Fixture providing an r2ai-server shim that lists multiple models and starts a test server.

    This shim:
    - Returns help text for -h flag
    - Lists 6 models for -m flag
    - Starts an HTTP server on port 18080 that responds to /ping

    Args:
        shim_path: Directory path for shim scripts

    Returns:
        Path to the created shim script
    """
    script = shim_path / "r2ai-server"
    make_executable(
        script,
        """#!/bin/sh
if [ "$1" = "-h" ]; then
  echo "usage: r2ai-server"
  exit 0
fi
if [ "$1" = "-m" ]; then
  echo "model-1"
  echo "model-2"
  echo "model-3"
  echo "model-4"
  echo "model-5"
  echo "model-6"
  exit 0
fi
python3 - <<'PY'
import threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/ping":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"pong")
            return
        self.send_response(404)
        self.end_headers()
    def log_message(self, format, *args):
        return
server = HTTPServer(("127.0.0.1", 18080), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
time.sleep(2)
server.shutdown()
PY
exit 0
""",
    )
    return script


@pytest.fixture()
def r2ai_server_single_model_shim(shim_path: Any) -> Any:
    """
    Fixture providing an r2ai-server shim with single model and test server on port 18082.

    This shim:
    - Returns help text for -h flag
    - Lists 1 model for -m flag
    - Starts an HTTP server on port 18082 that responds to /ping

    Args:
        shim_path: Directory path for shim scripts

    Returns:
        Path to the created shim script
    """
    script = shim_path / "r2ai-server"
    make_executable(
        script,
        """#!/bin/sh
if [ "$1" = "-h" ]; then
  echo "usage: r2ai-server"
  exit 0
fi
if [ "$1" = "-m" ]; then
  echo "model-1"
  exit 0
fi
python3 - <<'PY'
import threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/ping":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"pong")
            return
        self.send_response(404)
        self.end_headers()
    def log_message(self, format, *args):
        return
server = HTTPServer(("127.0.0.1", 18082), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
time.sleep(2)
server.shutdown()
PY
exit 0
""",
    )
    return script


@pytest.fixture()
def r2ai_server_no_server_shim(shim_path: Any) -> Any:
    """
    Fixture providing an r2ai-server shim that doesn't start an actual server.

    This shim:
    - Returns help text for -h flag
    - Lists 1 model for -m flag
    - Exits immediately without starting a server (for timeout tests)

    Args:
        shim_path: Directory path for shim scripts

    Returns:
        Path to the created shim script
    """
    script = shim_path / "r2ai-server"
    make_executable(
        script,
        """#!/bin/sh
if [ "$1" = "-h" ]; then
  echo "usage: r2ai-server"
  exit 0
fi
if [ "$1" = "-m" ]; then
  echo "model-1"
  exit 0
fi
exit 0
""",
    )
    return script


@pytest.fixture()
def path_with_shim(shim_path: Any) -> Callable[[Any], Any]:
    """
    Fixture providing a context manager factory for temporarily modifying PATH.

    Args:
        shim_path: Directory path for shim scripts

    Returns:
        A factory function that takes a shim script path and returns context manager utilities

    Example:
        def test_something(path_with_shim, r2ai_server_shim):
            path_manager = path_with_shim(r2ai_server_shim)
            original_path = path_manager["original_path"]
            os.environ["PATH"] = path_manager["modified_path"]
            try:
                # test code
            finally:
                os.environ["PATH"] = original_path
    """
    def _factory(shim_script: Any) -> Dict[str, str]:
        original_path = os.environ.get("PATH", "")
        return {
            "original_path": original_path,
            "modified_path": f"{shim_script.parent}{os.pathsep}{original_path}",
        }
    return _factory


# =============================================================================
# DEPENDENCY INJECTION FIXTURES
# =============================================================================


@pytest.fixture()
def fake_config() -> FakeConfigRepository:
    """
    Fixture providing a FakeConfigRepository with default test configuration.

    Returns:
        FakeConfigRepository: A fake configuration repository with sensible defaults.

    Example:
        def test_with_fake_config(fake_config):
            assert fake_config.get_output_dir() == "output"
    """
    return FakeConfigRepository({
        "banned_functions": ["strcpy", "strcat", "gets", "sprintf"],
        "output": {"directory": "output", "format": "json"},
        "decompiler": {"type": "default", "options": {}},
        "analysis": {"parallel": True, "max_workers": 4},
    })




@pytest.fixture()
def fake_config_factory() -> Callable[..., FakeConfigRepository]:
    """
    Fixture providing a factory function to create configured FakeConfigRepository instances.

    Returns:
        A factory function that accepts a config dict and returns a FakeConfigRepository.

    Example:
        def test_with_custom_config(fake_config_factory):
            config = fake_config_factory({"banned_functions": ["strcpy"]})
            assert config.get("banned_functions") == ["strcpy"]
    """
    def _factory(config: Optional[Dict[str, Any]] = None) -> FakeConfigRepository:
        default_config = {
            "banned_functions": ["strcpy", "strcat", "gets", "sprintf"],
            "output": {"directory": "output", "format": "json"},
            "decompiler": {"type": "default", "options": {}},
            "analysis": {"parallel": True, "max_workers": 4},
        }
        if config:
            default_config.update(config)
        return FakeConfigRepository(default_config)
    return _factory




@pytest.fixture()
def di_config():
    """
    Fixture providing a DictConfig instance for dependency injection tests.

    This uses the DictConfig class from factories module, which provides
    an isolated configuration that doesn't share state with the global singleton.

    Returns:
        DictConfig: An isolated configuration instance with sensible defaults.

    Example:
        def test_with_di_config(di_config):
            assert di_config.get_output_dir() == "output"
    """
    from bannedfuncdetector.factories import create_config_from_dict
    return create_config_from_dict({
        "banned_functions": ["strcpy", "strcat", "gets", "sprintf"],
        "output": {"directory": "output", "format": "json"},
        "decompiler": {"type": "default", "options": {}},
        "analysis": {"parallel": True, "max_workers": 4},
    })


@pytest.fixture()
def fake_r2_client_factory(fake_r2_factory: Callable[..., "FakeR2"]) -> Callable[..., FakeR2ClientFactory]:
    """
    Fixture providing a factory for creating FakeR2ClientFactory instances.

    Args:
        fake_r2_factory: The FakeR2 factory fixture.

    Returns:
        A factory function that creates FakeR2ClientFactory with configured FakeR2.

    Example:
        def test_with_fake_r2(fake_r2_client_factory):
            factory = fake_r2_client_factory(cmdj_map={"aflj": [{"name": "main"}]})
            client = factory.create("/any/path")
            assert client.cmdj("aflj")[0]["name"] == "main"
    """
    def _factory(
        cmd_map: Optional[CommandMap] = None,
        cmdj_map: Optional[CommandJsonMap] = None
    ) -> FakeR2ClientFactory:
        fake = fake_r2_factory(cmd_map=cmd_map, cmdj_map=cmdj_map)
        return FakeR2ClientFactory(fake)
    return _factory
