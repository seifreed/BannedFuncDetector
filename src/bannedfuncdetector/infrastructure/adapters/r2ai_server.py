#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - R2AI Server Management Module

This module provides utilities for checking, starting, and managing r2ai-server
instances used for AI-powered binary analysis.

The r2ai-server provides advanced decompilation and analysis capabilities through
a REST API interface. This module handles server availability checks, automatic
startup, model selection, and installation prompts.

Author: Marc Rivero | @seifreed
"""

import json
import logging
import shutil
import time
import os
import asyncio
from collections.abc import Callable, Sequence
from typing import Any, cast
from dataclasses import dataclass

import requests  # type: ignore[import-untyped]

# Configure module logger
logger = logging.getLogger(__name__)


def _is_http_ok(response: Any) -> bool:
    """Return ``True`` when a response object reports HTTP 200."""
    try:
        status_code = cast(int, response.status_code)
        return status_code == 200
    except (AttributeError, TypeError):
        return False


# =============================================================================
# R2AI SERVER UTILITIES
# =============================================================================

AFFIRMATIVE_RESPONSES = {'s', 'si', 'yes', 'y'}
ALLOWED_EXECUTABLES = frozenset({"r2ai-server", "r2pm"})


@dataclass(frozen=True)
class _CommandResult:
    """Portable result object for command execution wrappers."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


def _is_affirmative(response: str) -> bool:
    """Return True if the response is an affirmative answer."""
    return response.strip().lower() in AFFIRMATIVE_RESPONSES


def _ping_server(server_url: str, timeout: int) -> bool:
    """Return True if the server responds with HTTP 200."""
    response = requests.get(f"{server_url}/ping", timeout=timeout)
    return _is_http_ok(response)


def _wait_for_server(server_url: str, attempts: int = 10, timeout: int = 1) -> bool:
    """Poll the server until it responds or attempts are exhausted."""
    for _ in range(attempts):
        try:
            if _ping_server(server_url, timeout):
                logger.info("r2ai-server is available")
                return True
        except requests.RequestException:
            # Network or connection errors - server not ready yet
            time.sleep(1)
        except (OSError, IOError):
            # System-level network errors
            time.sleep(1)
    return False


def _run_r2ai_server_command(args: list[str]) -> _CommandResult:
    """Run an r2ai-server command and return the completed process."""
    return _run_subprocess_command(args, capture_output=True, check=False)


def _get_models_from_cli() -> list[str]:
    """Fetch available models via r2ai-server CLI."""
    models_result = _run_r2ai_server_command(['r2ai-server', '-m'])
    if models_result.returncode != 0 or not models_result.stdout.strip():
        return []
    return models_result.stdout.strip().splitlines()


def _log_model_list(models: list[str], header: str) -> None:
    """Log a list of models with a header, truncating after 5 items."""
    logger.info(header)
    for model in models[:5]:
        logger.info("    %s", model)
    if len(models) > 5:
        logger.info("    ... and %d more", len(models) - 5)


def _resolve_command(args: list[str]) -> list[str]:
    """Resolve the executable path for a command."""
    if not args:
        return args
    resolved = shutil.which(args[0])
    if resolved:
        return [resolved, *args[1:]]
    return args


def _validate_executable(args: list[str]) -> None:
    """Raise ValueError if the command's base executable is not in the allowlist."""
    if not args:
        raise ValueError("Empty command")
    base = os.path.basename(args[0])
    if base not in ALLOWED_EXECUTABLES:
        raise ValueError(f"Blocked executable not in allowlist: {base}")


async def _run_process_async(
    args: Sequence[str],
    *,
    capture_output: bool = True,
) -> _CommandResult:
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE if capture_output else None,
        stderr=asyncio.subprocess.PIPE if capture_output else None,
    )
    stdout_bytes, stderr_bytes = await process.communicate()
    if not capture_output:
        stdout_bytes = stdout_bytes if stdout_bytes is not None else b""
        stderr_bytes = stderr_bytes if stderr_bytes is not None else b""
    stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
    stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
    return _CommandResult(
        returncode=process.returncode if process.returncode is not None else 0,
        stdout=stdout,
        stderr=stderr,
    )


async def _spawn_process_async(args: Sequence[str]) -> asyncio.subprocess.Process:
    """Start a subprocess without waiting for it to finish."""
    return await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


def _spawn_subprocess_sync(args: Sequence[str], **_: Any) -> asyncio.subprocess.Process:
    """Execute a subprocess in the background from synchronous context."""
    return asyncio.run(_spawn_process_async(args))


def _run_subprocess_sync(
    args: Sequence[str],
    *,
    capture_output: bool = True,
    check: bool = False,
) -> _CommandResult:
    """Execute an async subprocess in synchronous context with no shell."""
    result = asyncio.run(_run_process_async(args, capture_output=capture_output))
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed with return code {result.returncode}: {list(args)}"
        )
    return result


def _run_subprocess_command(
    args: Sequence[str],
    *,
    run_fn: Callable[..., _CommandResult] = _run_subprocess_sync,
    capture_output: bool = True,
    check: bool = False,
) -> _CommandResult:
    """Execute a validated local command for r2ai interactions."""
    resolved_args = _resolve_command(list(args))
    _validate_executable(resolved_args)
    return run_fn(
        resolved_args,
        capture_output=capture_output,
        check=check,
    )


def check_r2ai_server_available(
    server_url: str = "http://localhost:8080",
    auto_start: bool = False,
    timeout: int = 2,
    prompt_callback: Callable[[str], str] | None = None
) -> bool:
    """
    Check if r2ai-server is available at the specified URL.

    This function attempts to connect to an r2ai-server instance and optionally
    offers to start one if not running.

    Args:
        server_url: URL where r2ai-server should be running.
        auto_start: If True, automatically attempt to start the server if not running.
                   If False (default), prompt the user interactively.
        timeout: Connection timeout in seconds.
        prompt_callback: Optional function to handle user prompts. If None, uses
                        built-in input(). Useful for testing or non-interactive usage.

    Returns:
        True if r2ai-server is available (or was successfully started),
        False otherwise.

    Examples:
        >>> check_r2ai_server_available("http://localhost:8080")
        True
        >>> check_r2ai_server_available("http://localhost:9999", timeout=1)
        False
    """
    try:
        if _ping_server(server_url, timeout):
            logger.info("r2ai-server detected at %s", server_url)
            _log_available_models(server_url, timeout)
            return True
        logger.warning("r2ai-server is not responding correctly at %s", server_url)
        return False
    except requests.RequestException as e:
        logger.warning("Error connecting to r2ai-server: %s", str(e))
        return _handle_r2ai_server_not_running(server_url, auto_start, prompt_callback)


def get_r2ai_models(server_url: str = "http://localhost:8080", timeout: int = 2) -> list:
    """
    Get the list of available models from r2ai-server.

    Args:
        server_url: URL of the r2ai-server.
        timeout: Request timeout in seconds.

    Returns:
        List of available model names, or empty list if unavailable.

    Examples:
        >>> models = get_r2ai_models("http://localhost:8080")
        >>> isinstance(models, list)
        True
    """
    try:
        response = requests.get(f"{server_url}/models", timeout=timeout)
        if _is_http_ok(response):
            models_data = response.json()
            models: list[Any] = models_data.get("models", [])
            return models
    except (requests.RequestException, json.JSONDecodeError, ValueError, KeyError) as e:
        logger.warning("Error getting models from r2ai-server: %s", str(e))

    return []


def _log_available_models(server_url: str, timeout: int) -> None:
    """
    Log the available models from r2ai-server.

    Args:
        server_url: URL of the r2ai-server.
        timeout: Request timeout in seconds.
    """
    try:
        models = get_r2ai_models(server_url, timeout)
        if models:
            logger.info("Models available in r2ai-server:")
            for model in models[:5]:
                logger.info("    - %s", model)
            if len(models) > 5:
                logger.info(
                    "    ... and %d more",
                    len(models) - 5
                )
        else:
            logger.warning("No available models found in r2ai-server")
    except requests.RequestException as e:
        # Network or HTTP errors
        logger.warning("Error getting the list of models: %s", str(e))
    except (json.JSONDecodeError, ValueError, KeyError) as e:
        # JSON parsing or data structure errors
        logger.warning("Error parsing the list of models: %s", str(e))


def _handle_r2ai_server_not_running(
    server_url: str,
    auto_start: bool,
    prompt_callback: Callable[[str], str] | None = None
) -> bool:
    """
    Handle the case when r2ai-server is not running.

    Args:
        server_url: URL where r2ai-server should be running.
        auto_start: Whether to automatically start the server.
        prompt_callback: Optional function to handle user prompts.

    Returns:
        True if server was successfully started, False otherwise.
    """
    # Check if r2ai-server is installed
    try:
        result = _run_r2ai_server_command(['r2ai-server', '-h'])
        if result.returncode != 0:
            logger.warning("r2ai-server is not installed")
            if not auto_start:
                return _prompt_install_r2ai_server(server_url, prompt_callback)
            return False

        logger.info("r2ai-server is installed but not running")
        if auto_start:
            return _start_r2ai_server(server_url, prompt_callback)
        return _prompt_start_r2ai_server(server_url, prompt_callback)

    except (RuntimeError, OSError, IOError) as e:
        # RuntimeError: Command execution failure
        # OSError/IOError: System-level errors
        logger.error("Error verifying r2ai-server installation: %s", str(e))
        return False
    except (ValueError, TypeError) as e:
        # Data parsing or type errors
        logger.error("Data error verifying r2ai-server installation: %s", str(e))
        return False


def _prompt_start_r2ai_server(
    server_url: str,
    prompt_callback: Callable[[str], str] | None = None
) -> bool:
    """
    Prompt the user to start r2ai-server.

    Args:
        server_url: URL where r2ai-server should be started.
        prompt_callback: Optional function to handle user prompts.

    Returns:
        True if server was successfully started, False otherwise.
    """
    prompt_fn = prompt_callback or input
    start_server = prompt_fn("Do you want to start r2ai-server? (y/n): ")
    if _is_affirmative(start_server):
        return _start_r2ai_server(server_url, prompt_callback)

    logger.info("r2ai-server startup canceled")
    return False


def _build_server_command(model: str) -> list[str]:
    """Build the r2ai-server command with optional model."""
    cmd = _resolve_command(['r2ai-server', '-l', 'r2ai'])
    if model:
        cmd.extend(['-m', model])
    return cmd


def _launch_server_process(
    cmd: list[str],
    *,
    popen: Callable[..., Any] = _spawn_subprocess_sync,
) -> bool:
    """Launch the r2ai-server process in the background."""
    resolved_cmd = _resolve_command(cmd)
    _validate_executable(resolved_cmd)
    popen(
        resolved_cmd,
    )
    logger.info("r2ai-server started in the background")
    return True


def _await_server_ready(server_url: str) -> bool:
    """Wait for the server to become available."""
    logger.info("Waiting for the server to be available...")
    if _wait_for_server(server_url, attempts=10, timeout=1):
        return True
    logger.error("Timeout. r2ai-server is not responding")
    return False


def _start_r2ai_server(
    server_url: str,
    prompt_callback: Callable[[str], str] | None = None,
    *,
    popen: Callable[..., Any] = _spawn_subprocess_sync,
) -> bool:
    """
    Start r2ai-server with user-selected model.

    Returns:
        True if server was successfully started, False otherwise.
    """
    logger.info("Starting r2ai-server...")

    models_lines = _get_models_from_cli()
    if not models_lines:
        logger.error("Could not get available models")
        return False

    _log_model_list(models_lines, "Models available for r2ai-server:")

    prompt_fn = prompt_callback or input
    model = prompt_fn("Which model do you want to use? (leave blank for default): ").strip()

    try:
        cmd = _build_server_command(model)
        _launch_server_process(cmd, popen=popen)
        return _await_server_ready(server_url)
    except (ValueError, TypeError, OSError, IOError, RuntimeError, Exception) as e:
        # Value/Type errors indicate configuration issues, Exception covers
        # subprocess-like failures from injected callbacks in tests.
        logger.error("Error starting r2ai-server: %s", str(e))
        return False


def _prompt_install_r2ai_server(
    server_url: str,
    prompt_callback: Callable[[str], str] | None = None,
    *,
    run: Callable[..., Any] | None = None,
) -> bool:
    """
    Prompt the user to install r2ai-server.

    Args:
        server_url: URL where r2ai-server should be running.
        prompt_callback: Optional function to handle user prompts.
        run: Callable to execute subprocess commands (for testability).

    Returns:
        True if server was successfully installed and started, False otherwise.
    """
    prompt_fn = prompt_callback or input
    install_server = prompt_fn("Do you want to install r2ai-server? (y/n): ")
    if _is_affirmative(install_server):
        logger.info("Installing r2ai-server...")
        try:
            install_cmd = _resolve_command(['r2pm', 'install', 'r2ai-server'])
            _validate_executable(install_cmd)
            runner = run or _run_subprocess_sync
            runner(install_cmd, check=True, capture_output=False)
            logger.info("r2ai-server installed successfully")
            return check_r2ai_server_available(server_url, prompt_callback=prompt_callback)
        except (OSError, IOError) as e:
            # OSError/IOError: System-level errors
            logger.error("Error installing r2ai-server: %s", str(e))
            return False
        except Exception as e:
            logger.error("Error installing r2ai-server: %s", str(e))
            return False

    logger.info("r2ai-server installation canceled")
    return False
