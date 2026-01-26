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
import subprocess  # nosec B404
import time
from collections.abc import Callable
from typing import Any

import requests

# Configure module logger
logger = logging.getLogger(__name__)


# =============================================================================
# R2AI SERVER UTILITIES
# =============================================================================

AFFIRMATIVE_RESPONSES = {'s', 'si', 'yes', 'y'}


def _is_affirmative(response: str) -> bool:
    """Return True if the response is an affirmative answer."""
    return response.strip().lower() in AFFIRMATIVE_RESPONSES


def _ping_server(server_url: str, timeout: int) -> bool:
    """Return True if the server responds with HTTP 200."""
    response = requests.get(f"{server_url}/ping", timeout=timeout)
    return response.status_code == 200


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


def _run_r2ai_server_command(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Run an r2ai-server command and return the completed process."""
    args = _resolve_command(args)
    return subprocess.run(args, capture_output=True, text=True)  # nosec B603


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
        if response.status_code == 200:
            models_data = response.json()
            models: list[Any] = models_data.get("models", [])
            return models
    except requests.RequestException as e:
        # Network or HTTP errors
        logger.warning("Error getting models from r2ai-server: %s", str(e))
    except (json.JSONDecodeError, ValueError, KeyError) as e:
        # JSON parsing or data structure errors
        logger.warning("Error parsing models response from r2ai-server: %s", str(e))

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

    except (subprocess.SubprocessError, OSError, IOError) as e:
        # SubprocessError: Command execution failure
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


def _launch_server_process(cmd: list[str]) -> bool:
    """Launch the r2ai-server process in the background."""
    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # nosec B603
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
    prompt_callback: Callable[[str], str] | None = None
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
        _launch_server_process(cmd)
        return _await_server_ready(server_url)
    except (subprocess.SubprocessError, OSError, IOError) as e:
        logger.error("Error starting r2ai-server: %s", str(e))
        return False
    except (ValueError, TypeError) as e:
        logger.error("Configuration error starting r2ai-server: %s", str(e))
        return False


def _prompt_install_r2ai_server(
    server_url: str,
    prompt_callback: Callable[[str], str] | None = None
) -> bool:
    """
    Prompt the user to install r2ai-server.

    Args:
        server_url: URL where r2ai-server should be running.
        prompt_callback: Optional function to handle user prompts.

    Returns:
        True if server was successfully installed and started, False otherwise.
    """
    prompt_fn = prompt_callback or input
    install_server = prompt_fn("Do you want to install r2ai-server? (y/n): ")
    if _is_affirmative(install_server):
        logger.info("Installing r2ai-server...")
        try:
            subprocess.run(_resolve_command(['r2pm', 'install', 'r2ai-server']), check=True)  # nosec B603
            logger.info("r2ai-server installed successfully")
            return check_r2ai_server_available(server_url, prompt_callback=prompt_callback)
        except subprocess.CalledProcessError as e:
            # Installation command returned non-zero exit code
            logger.error("r2ai-server installation command failed: %s", str(e))
            return False
        except (subprocess.SubprocessError, OSError, IOError) as e:
            # SubprocessError: Command execution failure
            # OSError/IOError: System-level errors
            logger.error("Error installing r2ai-server: %s", str(e))
            return False

    logger.info("r2ai-server installation canceled")
    return False
