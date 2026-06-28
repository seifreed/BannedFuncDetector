"""Optionally open the saved report in the platform's default viewer.

Driven by ``output.open_results``. The launch is fire-and-forget and any
failure is logged rather than raised, so opening a viewer can never break an
otherwise-successful analysis. Kept side-effect-injectable so the behavior is
testable without spawning a real process.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from collections.abc import Callable
from typing import Any

from bannedfuncdetector.application.binary_analyzer.reporting import results_file_path
from bannedfuncdetector.domain.protocols import IConfigRepository

logger = logging.getLogger(__name__)


def results_open_command(path: str, platform: str, os_name: str) -> list[str]:
    """The argv that opens ``path`` with the platform's default handler."""
    if platform == "darwin":
        return ["open", path]
    if os_name == "nt":
        return ["cmd", "/c", "start", "", path]
    return ["xdg-open", path]


def _default_launcher(path: str, *, spawn: Callable[..., Any] = subprocess.Popen) -> None:
    """Spawn the OS opener for ``path`` without waiting on it."""
    spawn(
        results_open_command(path, sys.platform, os.name),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def open_results_if_configured(
    binary_path: str,
    output_dir: str,
    config: IConfigRepository,
    *,
    launcher: Callable[[str], None] = _default_launcher,
) -> bool:
    """Open the saved report when ``output.open_results`` is enabled.

    Returns True when a launch was attempted. A missing report or a launcher
    failure is logged and yields False; it never raises.
    """
    output = config.get("output", {})
    if not isinstance(output, dict) or not output.get("open_results"):
        return False
    path = results_file_path(output_dir, binary_path, output.get("format", "json"))
    if not os.path.isfile(path):
        logger.warning("open_results is enabled but no report was found at %s", path)
        return False
    try:
        launcher(path)
    except (OSError, ValueError) as exc:
        logger.warning("open_results could not open %s: %s", path, exc)
        return False
    return True


__all__ = ["open_results_if_configured", "results_open_command"]
