# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""output.open_results opens the saved report in the OS default viewer.

The launch is gated on config, never raised on failure, and side-effect
injectable so these tests exercise every branch without spawning a process.
"""

from __future__ import annotations

import os

from bannedfuncdetector.application.binary_analyzer.reporting import results_file_path
from bannedfuncdetector.factories import create_config_from_dict
from bannedfuncdetector.presentation.results_opener import (
    _default_launcher,
    open_results_if_configured,
    results_open_command,
)


def test_open_command_per_platform() -> None:
    assert results_open_command("/r.json", "darwin", "posix") == ["open", "/r.json"]
    assert results_open_command("/r.json", "linux", "posix") == ["xdg-open", "/r.json"]
    assert results_open_command("r.json", "win32", "nt") == [
        "cmd",
        "/c",
        "start",
        "",
        "r.json",
    ]


def test_disabled_does_not_launch() -> None:
    config = create_config_from_dict({"output": {"open_results": False}})
    calls: list[str] = []
    assert (
        open_results_if_configured("/bin/ls", "/tmp", config, launcher=calls.append)
        is False
    )
    assert calls == []


def test_enabled_but_missing_report_returns_false(tmp_path) -> None:
    config = create_config_from_dict({"output": {"open_results": True}})
    calls: list[str] = []
    assert (
        open_results_if_configured(
            "/bin/does-not-exist", str(tmp_path), config, launcher=calls.append
        )
        is False
    )
    assert calls == []


def test_enabled_with_report_launches(tmp_path) -> None:
    config = create_config_from_dict(
        {"output": {"open_results": True, "format": "json"}}
    )
    report = results_file_path(str(tmp_path), "/bin/ls", "json")
    with open(report, "w", encoding="utf-8") as handle:
        handle.write("{}")

    launched: list[str] = []
    assert (
        open_results_if_configured(
            "/bin/ls", str(tmp_path), config, launcher=launched.append
        )
        is True
    )
    assert launched == [report]


def test_launcher_failure_is_swallowed(tmp_path) -> None:
    config = create_config_from_dict({"output": {"open_results": True}})
    report = results_file_path(str(tmp_path), "/bin/ls", "json")
    with open(report, "w", encoding="utf-8") as handle:
        handle.write("{}")

    def boom(_path: str) -> None:
        raise OSError("no opener")

    assert (
        open_results_if_configured("/bin/ls", str(tmp_path), config, launcher=boom)
        is False
    )


def test_default_launcher_invokes_spawn_with_command(tmp_path) -> None:
    recorded: list[tuple] = []

    def fake_spawn(args, **kwargs):
        recorded.append((args, kwargs))

    _default_launcher("/tmp/report.json", spawn=fake_spawn)
    assert recorded and recorded[0][0][-1] == "/tmp/report.json"


def test_results_file_path_falls_back_to_json_for_unknown_format() -> None:
    path = results_file_path("/out", "/bin/ls", "xml")
    assert path == os.path.join("/out", "ls_banned_functions.json")
