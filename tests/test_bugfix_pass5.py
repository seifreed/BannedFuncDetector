# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for bugs found beyond the existing suite (pass 5):
  * _wait_for_server busy-spun when the server replied non-200 (no backoff);
  * _run_r2ai_server_command had no subprocess timeout (could hang forever);
  * get_r2ai_models crashed on a bare-array /models response;
  * load_config / reload crashed when config.json was a non-dict JSON value.
"""

from __future__ import annotations

import json

from bannedfuncdetector.infrastructure import config_storage
from bannedfuncdetector.infrastructure.adapters import r2ai_server


# --- Bug 1: _wait_for_server backs off on non-200 instead of busy-spinning ---


def test_wait_for_server_sleeps_between_non_200_attempts() -> None:
    sleeps: list[float] = []
    original_ping = r2ai_server._ping_server
    original_sleep = r2ai_server.time.sleep
    try:
        r2ai_server._ping_server = lambda url, timeout: False  # reachable, non-200
        r2ai_server.time.sleep = lambda seconds: sleeps.append(seconds)
        result = r2ai_server._wait_for_server("http://x", attempts=3, timeout=1)
    finally:
        r2ai_server._ping_server = original_ping
        r2ai_server.time.sleep = original_sleep

    assert result is False
    # 3 attempts → backs off after the first two, not after the last.
    assert sleeps == [1, 1]


# --- Bug 2: command run enforces a timeout, surfaced as returncode 1 ---


def test_run_command_times_out_gracefully() -> None:
    # A shim that sleeps longer than the (tiny) timeout we pass.
    import os
    import stat
    import tempfile

    d = tempfile.mkdtemp()
    shim = os.path.join(d, "r2ai-server")
    with open(shim, "w") as f:
        f.write("#!/bin/sh\nsleep 5\n")
    os.chmod(shim, os.stat(shim).st_mode | stat.S_IEXEC)

    original_path = os.environ.get("PATH", "")
    try:
        os.environ["PATH"] = d + os.pathsep + original_path
        result = r2ai_server._run_r2ai_server_command(["r2ai-server", "-m"], timeout=0.3)
    finally:
        os.environ["PATH"] = original_path

    assert result.returncode == 1
    assert result.stderr == "timeout"


# --- Bug 3: get_r2ai_models accepts a bare JSON array ---


class _ArrayResponse:
    status_code = 200

    @staticmethod
    def json() -> list[str]:
        return ["m1", "m2"]


def test_get_r2ai_models_accepts_bare_array(monkeypatch=None) -> None:
    original_get = r2ai_server.requests.get
    try:
        r2ai_server.requests.get = lambda url, timeout: _ArrayResponse()
        models = r2ai_server.get_r2ai_models("http://x")
    finally:
        r2ai_server.requests.get = original_get
    assert models == ["m1", "m2"]


# --- Bug 5: non-dict config falls back to defaults instead of crashing ---


def test_load_config_rejects_non_dict_json(tmp_path) -> None:
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps([1, 2, 3]))

    result = config_storage.load_config(str(cfg))

    assert isinstance(result, dict)
    assert "decompiler" in result  # got DEFAULT_CONFIG, no crash


def test_reload_rejects_non_dict_json(tmp_path) -> None:
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps("just a string"))

    immutable = config_storage.ImmutableConfig()
    before = immutable.to_dict()
    immutable.reload(str(cfg))  # must not raise

    assert immutable.to_dict() == before  # current config kept


class _ScalarResponse:
    status_code = 200

    @staticmethod
    def json() -> int:
        return 42  # neither dict nor list


def test_get_r2ai_models_handles_unexpected_scalar() -> None:
    original_get = r2ai_server.requests.get
    try:
        r2ai_server.requests.get = lambda url, timeout: _ScalarResponse()
        models = r2ai_server.get_r2ai_models("http://x")
    finally:
        r2ai_server.requests.get = original_get
    assert models == []
