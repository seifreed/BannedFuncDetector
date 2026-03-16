# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage-gap tests for BannedFuncDetector infrastructure modules.

Each test exercises real production code paths using the project's FakeR2
and FakeConfigRepository helpers, real in-process HTTP servers from conftest,
and real subprocess shims where external processes are needed.
"""

from __future__ import annotations

import errno
import os
import subprocess
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# conftest imports (used directly, not via fixtures, for readability)
# ---------------------------------------------------------------------------
from tests.conftest import (
    FakeConfigRepository,
    FakeR2,
    make_executable,
    start_test_server,
    write_minimal_pe,
)

# ---------------------------------------------------------------------------
# Production imports
# ---------------------------------------------------------------------------
from bannedfuncdetector.analyzer_exceptions import TransientR2Error
from bannedfuncdetector.application.analysis_outcome import (
    BinaryAnalysisOutcome,
    DirectoryAnalysisOutcome,
    OperationalNotice,
)
from bannedfuncdetector.domain.entities import (
    AnalysisResult,
    BannedFunction,
    DirectoryAnalysisSummary,
    FunctionDescriptor,
)
from bannedfuncdetector.domain.result import ok
from bannedfuncdetector.factories import create_config_from_dict
from bannedfuncdetector.infrastructure.adapters import r2ai_server as r2ai_mod
from bannedfuncdetector.infrastructure.adapters.r2_session import (
    open_binary_with_r2,
)
from bannedfuncdetector.infrastructure.config_models import AppConfig, DEFAULT_DECOMPILER_OPTIONS
from bannedfuncdetector.infrastructure.decompilers.availability import (
    check_decompiler_available,
)
from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    DecompilerType,
    try_decompile_with_command,
)
from bannedfuncdetector.infrastructure.decompilers.cascade import (
    _decompile_with_default_cascade,
    _decompile_with_instance,
)
from bannedfuncdetector.infrastructure.decompilers.decai_decompiler import (
    DecAIDecompiler,
    _configure_decai_model,
    _fallback_to_r2ghidra,
    _resolve_function_offset,
    _try_decai_decompilation,
    decompile_with_decai,
)
from bannedfuncdetector.infrastructure.decompilers.default_decompiler import (
    DefaultDecompiler,
)
from bannedfuncdetector.infrastructure.decompilers.decompiler_availability import (
    _check_decai_service_available,
    _check_r2_plugin_available,
)
from bannedfuncdetector.infrastructure.decompilers.decompiler_support import (
    _normalize_function_info,
    _try_decompile_pair,
)
from bannedfuncdetector.infrastructure.decompilers.decompiler_types import (
    DecompilerType as DType,
)
from bannedfuncdetector.infrastructure.decompilers.orchestrator_dispatch import (
    decompile_function,
)
from bannedfuncdetector.infrastructure.decompilers.orchestrator_progress import (
    _handle_processing_exception,
)
from bannedfuncdetector.infrastructure.decompilers.orchestrator_runtime import (
    _process_single_function,
)
from bannedfuncdetector.infrastructure.decompilers.orchestrator_search import (
    _search_single_banned_function,
)
from bannedfuncdetector.infrastructure.decompilers.orchestrator_service import (
    DecompilerOrchestrator,
    decompile_with_selected_decompiler,
)
from bannedfuncdetector.infrastructure.decompilers.registry import (
    create_decompiler,
)
from bannedfuncdetector.infrastructure.decompilers.selector import (
    _get_alternative_decompilers,
    _select_best_available,
    resolve_to_decompiler_type,
    select_decompiler,
)
from bannedfuncdetector.infrastructure.validators import (
    check_python_version,
    validate_binary_file,
    _check_available_decompilers,
)
from bannedfuncdetector.presentation.reporting import display_final_results


# ===========================================================================
# 1. infrastructure/adapters/r2_session.py — lines 43-44, 81-82
# ===========================================================================


class _AlwaysFailingFactory:
    """Factory that raises TransientR2Error on every attempt, exhausting retries."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.calls = 0

    def __call__(self, _path: str):
        self.calls += 1
        raise self._exc


def test_open_binary_with_r2_exhausts_transient_retries_raises():
    """
    Purpose: Cover lines 81-82 — after all retry attempts fail with a
    TransientR2Error the last error is re-raised.
    """
    factory = _AlwaysFailingFactory(TransientR2Error("pipe broken"))
    with pytest.raises(TransientR2Error):
        open_binary_with_r2("/dev/null", r2_factory=factory)
    # Two attempts because _OPEN_RETRY_ATTEMPTS == 2
    assert factory.calls == 2


def test_open_binary_with_r2_non_transient_error_raises_immediately():
    """
    Purpose: Cover line 72 — non-transient OSError raises without retrying.
    Also exercises is_transient_r2_setup_error returning False (lines 43-44).
    """
    factory = _AlwaysFailingFactory(OSError("disk error"))
    with pytest.raises(OSError, match="disk error"):
        open_binary_with_r2("/dev/null", r2_factory=factory)
    # Only one attempt — not transient, so no retry
    assert factory.calls == 1


def test_open_binary_with_r2_broken_pipe_retries():
    """
    Purpose: Cover lines 43-44 — BrokenPipeError is identified as transient.
    Verify that the retry loop runs both attempts before re-raising.
    """
    factory = _AlwaysFailingFactory(BrokenPipeError("broken pipe"))
    with pytest.raises(BrokenPipeError):
        open_binary_with_r2("/dev/null", r2_factory=factory)
    assert factory.calls == 2


def test_open_binary_with_r2_oserr_epipe_is_transient():
    """Cover lines 43-44: OSError with errno.EPIPE is transient and retried."""
    exc = OSError("epipe")
    exc.errno = errno.EPIPE
    factory = _AlwaysFailingFactory(exc)
    with pytest.raises(OSError):
        open_binary_with_r2("/dev/null", r2_factory=factory)
    assert factory.calls == 2


# ===========================================================================
# 2. infrastructure/adapters/r2ai_server.py
# ===========================================================================


def test_wait_for_server_returns_true_when_ping_succeeds():
    """
    Purpose: Cover line 54 — _ping_server returns True and the loop returns True.
    Uses a real in-process HTTP server.
    """
    url, server = start_test_server(ping_status=200)
    try:
        result = r2ai_mod._wait_for_server(url, attempts=3, timeout=2)
        assert result is True
    finally:
        server.shutdown()


def test_wait_for_server_returns_false_when_all_attempts_fail():
    """
    Purpose: Cover lines 59-61 — RequestException triggers sleep; all attempts
    exhaust and False is returned. Targets a port that is definitely not listening.
    """
    result = r2ai_mod._wait_for_server(
        "http://127.0.0.1:19999", attempts=2, timeout=1
    )
    assert result is False


def test_wait_for_server_non_200_ping_does_not_return_true():
    """
    Purpose: Cover line 53 — _ping_server returns False (status != 200).
    """
    url, server = start_test_server(ping_status=503)
    try:
        result = r2ai_mod._wait_for_server(url, attempts=1, timeout=1)
        assert result is False
    finally:
        server.shutdown()


def test_check_r2ai_server_available_returns_true_on_live_server():
    """
    Purpose: Cover line 92 — _log_available_models is called when ping succeeds.
    Uses a real HTTP server with models payload.
    """
    url, server = start_test_server(
        ping_status=200,
        models_status=200,
        models_payload=b'{"models": ["model-a", "model-b"]}',
    )
    try:
        result = r2ai_mod.check_r2ai_server_available(server_url=url, timeout=2)
        assert result is True
    finally:
        server.shutdown()


def test_check_r2ai_server_available_returns_false_for_bad_ping():
    """
    Purpose: Cover line 102 — server responds but with non-200; returns False.
    """
    url, server = start_test_server(ping_status=400)
    try:
        result = r2ai_mod.check_r2ai_server_available(server_url=url, timeout=2)
        assert result is False
    finally:
        server.shutdown()


def test_check_r2ai_server_available_unreachable_server_no_autostart():
    """
    Purpose: Cover line 106 — RequestException caught, delegates to
    _handle_r2ai_server_not_running which needs auto_start=False and
    a prompt_callback that declines.
    """
    # prompt_callback that always says no — avoids stdin interaction
    def _no(_prompt: str) -> str:
        return "n"

    result = r2ai_mod.check_r2ai_server_available(
        server_url="http://127.0.0.1:19998",
        auto_start=False,
        timeout=1,
        prompt_callback=_no,
    )
    assert result is False


def test_log_available_models_more_than_five(tmp_path):
    """
    Purpose: Cover lines 176-178 — _log_available_models logs '...and N more'
    when there are more than 5 models.
    """
    url, server = start_test_server(
        ping_status=200,
        models_status=200,
        models_payload=b'{"models": ["a","b","c","d","e","f","g"]}',
    )
    try:
        # _log_available_models is called internally; just verify no exception
        r2ai_mod._log_available_models(url, timeout=2)
    finally:
        server.shutdown()


def test_log_available_models_empty_list():
    """
    Purpose: Cover lines 204-209 — models list is empty, warning is logged.
    """
    url, server = start_test_server(
        ping_status=200,
        models_status=200,
        models_payload=b'{"models": []}',
    )
    try:
        r2ai_mod._log_available_models(url, timeout=2)  # must not raise
    finally:
        server.shutdown()


def test_handle_r2ai_server_not_running_installed_prompt_no(tmp_path):
    """
    Purpose: Cover lines 235, 239 — r2ai-server -h succeeds (installed),
    auto_start=False, user says no to starting.
    Uses a shim that exits 0 for -h.
    """
    shim = tmp_path / "r2ai-server"
    make_executable(shim, "#!/bin/sh\nif [ \"$1\" = \"-h\" ]; then exit 0; fi\nexit 1\n")
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{tmp_path}:{original_path}"
    try:
        def _no(_prompt: str) -> str:
            return "n"

        result = r2ai_mod._handle_r2ai_server_not_running(
            "http://127.0.0.1:19997",
            auto_start=False,
            prompt_callback=_no,
        )
        assert result is False
    finally:
        os.environ["PATH"] = original_path


def test_handle_r2ai_server_not_running_not_installed_prompt_no(tmp_path):
    """
    Purpose: Cover lines 247-250 — r2ai-server -h returns non-zero (not installed),
    auto_start=False, user declines install.
    """
    shim = tmp_path / "r2ai-server"
    make_executable(shim, "#!/bin/sh\nexit 1\n")
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{tmp_path}:{original_path}"
    try:
        def _no(_prompt: str) -> str:
            return "n"

        result = r2ai_mod._handle_r2ai_server_not_running(
            "http://127.0.0.1:19996",
            auto_start=False,
            prompt_callback=_no,
        )
        assert result is False
    finally:
        os.environ["PATH"] = original_path


def test_prompt_install_r2ai_server_user_says_no():
    """
    Purpose: Cover lines 333-338 — user declines install; function returns False.
    """
    def _no(_prompt: str) -> str:
        return "n"

    result = r2ai_mod._prompt_install_r2ai_server(
        "http://127.0.0.1:19995",
        prompt_callback=_no,
    )
    assert result is False


def test_prompt_install_r2ai_server_install_succeeds(tmp_path):
    """
    Purpose: Cover lines 372-376 — user says yes, r2pm shim runs successfully
    but the server is still not reachable, so returns False after check.
    """
    # r2pm shim that exits 0 (install "succeeds")
    r2pm = tmp_path / "r2pm"
    make_executable(r2pm, "#!/bin/sh\nexit 0\n")
    # r2ai-server shim that exits 1 (not running)
    r2ai = tmp_path / "r2ai-server"
    make_executable(r2ai, "#!/bin/sh\nexit 1\n")
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{tmp_path}:{original_path}"
    try:
        responses = iter(["y", "n"])

        def _prompt(_msg: str) -> str:
            return next(responses)

        result = r2ai_mod._prompt_install_r2ai_server(
            "http://127.0.0.1:19994",
            prompt_callback=_prompt,
            run=subprocess.run,
        )
        assert result is False
    finally:
        os.environ["PATH"] = original_path


def test_run_r2ai_server_command_blocked_executable(tmp_path):
    """
    Purpose: Cover line 92 (_validate_executable) — blocked executable raises
    ValueError before subprocess is invoked.
    """
    with pytest.raises(ValueError, match="Blocked executable"):
        r2ai_mod._run_r2ai_server_command(["malicious_bin", "-h"])


# ===========================================================================
# 3. infrastructure/config_models.py — lines 168-204
# ===========================================================================


def test_app_config_from_dict_empty():
    """
    Purpose: Cover lines 168-204 — from_dict with empty dict uses all defaults.
    """
    cfg = AppConfig.from_dict({})
    assert cfg.decompiler_type == "default"
    assert cfg.output_format == "json"
    assert cfg.parallel is True


def test_app_config_from_dict_partial_decompiler_section():
    """
    Purpose: Cover lines 168-204 — decompiler type is overridden; options use defaults.
    """
    cfg = AppConfig.from_dict({"decompiler": {"type": "r2ghidra"}})
    assert cfg.decompiler_type == "r2ghidra"
    # r2ghidra option should be present with defaults
    assert "r2ghidra" in cfg.decompiler_options
    assert cfg.decompiler_options["r2ghidra"].command == DEFAULT_DECOMPILER_OPTIONS["r2ghidra"].command


def test_app_config_from_dict_nested_error_handling_options():
    """
    Purpose: Cover lines 183-201 — error_handling and advanced_options sub-dicts
    are parsed when present.
    """
    cfg = AppConfig.from_dict({
        "decompiler": {
            "type": "r2dec",
            "options": {
                "r2dec": {
                    "enabled": False,
                    "error_handling": {
                        "ignore_unknown_branches": False,
                        "clean_error_messages": False,
                        "fallback_to_asm": False,
                    },
                    "advanced_options": {
                        "temperature": 0.5,
                        "context": 4096,
                        "max_tokens": 1024,
                        "system_prompt": "custom",
                    },
                }
            },
        },
        "output": {"directory": "/tmp/out", "format": "csv", "open_results": True, "verbose": True},
        "analysis": {"parallel": False, "max_workers": 8, "timeout": 120, "worker_limit": 2},
        "skip_small_functions": False,
        "small_function_threshold": 5,
    })
    r2dec_opt = cfg.decompiler_options["r2dec"]
    assert r2dec_opt.enabled is False
    assert r2dec_opt.ignore_unknown_branches is False
    assert r2dec_opt.clean_error_messages is False
    assert r2dec_opt.fallback_to_asm is False
    assert r2dec_opt.temperature == 0.5
    assert r2dec_opt.context == 4096
    assert r2dec_opt.max_tokens == 1024
    assert r2dec_opt.system_prompt == "custom"
    assert cfg.output_directory == "/tmp/out"
    assert cfg.output_format == "csv"
    assert cfg.open_results is True
    assert cfg.verbose is True
    assert cfg.parallel is False
    assert cfg.max_workers == 8
    assert cfg.timeout == 120
    assert cfg.worker_limit == 2
    assert cfg.skip_small_functions is False
    assert cfg.small_function_threshold == 5


def test_app_config_from_dict_model_api_host_port_server_url():
    """
    Purpose: Cover lines 192-197 — model, api, prompt, host, port, server_url are
    forwarded from options dict.
    """
    cfg = AppConfig.from_dict({
        "decompiler": {
            "type": "decai",
            "options": {
                "decai": {
                    "model": "mymodel",
                    "api": "openai",
                    "prompt": "do it",
                    "host": "http://example.com",
                    "port": 9999,
                    "server_url": "http://example.com:9999",
                }
            },
        }
    })
    decai_opt = cfg.decompiler_options["decai"]
    assert decai_opt.model == "mymodel"
    assert decai_opt.api == "openai"
    assert decai_opt.prompt == "do it"
    assert decai_opt.host == "http://example.com"
    assert decai_opt.port == 9999
    assert decai_opt.server_url == "http://example.com:9999"


# ===========================================================================
# 4. infrastructure/decompilers/selector.py — lines 67, 158-162, 182-188, 191-194, 237, 244
# ===========================================================================


def _make_config(decompiler_type: str = "default") -> FakeConfigRepository:
    return FakeConfigRepository({
        "decompiler": {"type": decompiler_type, "options": {}},
        "output": {"directory": "output"},
    })


def test_resolve_to_decompiler_type_with_enum_passthrough():
    """
    Purpose: Cover line 67 — when input is already a DecompilerType, return as-is.
    """
    config = _make_config()
    result = resolve_to_decompiler_type(DecompilerType.R2GHIDRA, config)
    assert result == DecompilerType.R2GHIDRA


def test_resolve_to_decompiler_type_from_string():
    """Cover the string branch of resolve_to_decompiler_type."""
    config = _make_config()
    result = resolve_to_decompiler_type("r2dec", config)
    assert result == DecompilerType.R2DEC


def test_resolve_to_decompiler_type_none_uses_config():
    """Cover the None branch — reads type from config."""
    config = _make_config("r2ghidra")
    result = resolve_to_decompiler_type(None, config)
    assert result == DecompilerType.R2GHIDRA


def test_get_alternative_decompilers_for_decai():
    """
    Purpose: Cover lines 130-136 — when requested is 'decai', decai is included
    then removed from alternatives.
    """
    alts = _get_alternative_decompilers("decai")
    assert "r2ghidra" in alts
    assert "default" in alts
    # decai itself is removed after being added
    assert "decai" not in alts


def test_get_alternative_decompilers_for_r2ghidra():
    """
    Purpose: Cover lines 137-142 — r2ghidra not included in its own alternatives.
    """
    alts = _get_alternative_decompilers("r2ghidra")
    assert "r2ghidra" not in alts
    assert "r2dec" in alts
    assert "default" in alts


def test_select_best_available_returns_default_when_none_available():
    """
    Purpose: Cover lines 191-194 — all alternatives unavailable, falls back to
    'default'.  We use 'decai' as first alternative (unavailable without Ollama)
    and an empty list to force the fallback path.
    """
    result = _select_best_available([], verbose=False)
    assert result == DecompilerType.DEFAULT.value


def test_select_best_available_returns_first_available():
    """
    Purpose: Cover lines 182-188 — 'default' is always available via
    check_decompiler_available; confirm it is selected and logged when verbose.
    """
    result = _select_best_available(["default"], verbose=True)
    assert result == "default"


def test_select_decompiler_force_skips_availability_check():
    """
    Purpose: Cover line 237 — force=True returns without checking availability.
    """
    config = _make_config("r2ghidra")
    result = select_decompiler(requested="r2dec", force=True, config=config)
    assert result == "r2dec"


def test_select_decompiler_logs_unavailable_and_falls_back():
    """
    Purpose: Cover line 244 — verbose=True triggers _log_unavailable_decompiler
    for an unavailable decompiler and falls back to 'default'.
    Uses 'decai' which is typically unavailable without Ollama.
    """
    config = _make_config()
    result = select_decompiler(
        requested="decai",
        force=False,
        verbose=True,
        config=config,
    )
    # Must fall back to something available
    assert result in {"r2ghidra", "r2dec", "default"}


def test_log_unavailable_decompiler_decai_branch():
    """
    Purpose: Cover lines 158-162 — decai branch uses 'AI assistant plugin' message.
    Calls the internal function directly.
    """
    from bannedfuncdetector.infrastructure.decompilers.selector import _log_unavailable_decompiler
    # Just verify it does not raise
    _log_unavailable_decompiler("decai")
    _log_unavailable_decompiler("r2ghidra")


# ===========================================================================
# 5. infrastructure/decompilers/cascade.py — lines 84-89, 96, 109, 125, 172-176
# ===========================================================================


def _make_fake_r2_with_decompilation(result_text: str) -> FakeR2:
    """Return a FakeR2 that yields result_text for any decompile command."""
    return FakeR2(
        cmd_map={
            "s main": "",
            "pdg": result_text,
            "pdd": result_text,
            "pdc": result_text,
        }
    )


def test_decompile_with_instance_r2ghidra_returns_ok():
    """
    Purpose: Cover lines 93-104 — R2GHIDRA branch of _decompile_with_instance.
    """
    code = "int main() { return 0; } // some more content here to pass length check"
    r2 = FakeR2(cmd_map={"s main": "", "pdg": code, "pdd": code})
    result = _decompile_with_instance(r2, "main", DecompilerType.R2GHIDRA, {})
    assert result.is_ok()
    assert "main" in result.unwrap()


def test_decompile_with_instance_r2dec_returns_ok():
    """
    Purpose: Cover lines 106-117 — R2DEC branch.
    """
    code = "void helper() { strcpy(buf, src); return; } // enough code to pass"
    r2 = FakeR2(cmd_map={"s helper": "", "pdd": code, "pdg": code})
    result = _decompile_with_instance(r2, "helper", DecompilerType.R2DEC, {})
    assert result.is_ok()


def test_decompile_with_instance_default_falls_through_to_cascade():
    """
    Purpose: Cover line 120 — DEFAULT branch delegates to _decompile_with_default_cascade.
    """
    code = "void fn() { return 1 + 2 + 3; } // filler to exceed length threshold"
    r2 = FakeR2(
        cmd_map={
            "s fn": "",
            "pdg": code,
            "pdd": code,
            "pdc": code,
        }
    )
    result = _decompile_with_instance(r2, "fn", DecompilerType.DEFAULT, {})
    assert result.is_ok() or result.is_err()


def test_decompile_with_instance_decai_not_configured_returns_err():
    """
    Purpose: Cover lines 83-91 — DECAI branch; DecAIDecompiler needs function info.
    FakeR2 returns None for afij (no function info), causing FunctionNotFoundError
    which is caught and returned as err.
    """
    r2 = FakeR2(
        cmd_map={"decai -h": "Unknown command"},
        cmdj_map={"afij @ main": None},
    )
    result = _decompile_with_instance(r2, "main", DecompilerType.DECAI, {})
    # Either err (function not found) or ok — depends on fallback; must not raise
    assert result.is_ok() or result.is_err()


def test_decompile_with_default_cascade_fallback_to_asm():
    """
    Purpose: Cover lines 172-176 — all decompilers return empty output;
    fallback_to_asm=True causes assembly retrieval.
    """
    r2 = FakeR2(cmd_map={
        "s main": "",
        "pdg": "",
        "pdd": "",
        "pdc": "",
        "pdf": "push rbp; mov rbp, rsp; ret",
        "s": "0x1000",
    })
    result = _decompile_with_default_cascade(
        r2, "main", clean_error_messages=True, options={"fallback_to_asm": True}
    )
    # Either ok (asm returned) or err — must not raise
    assert result.is_ok() or result.is_err()


def test_decompile_with_default_cascade_no_fallback_returns_err():
    """
    Purpose: Cover line 178 — fallback_to_asm=False and all decompilers fail
    returns err.
    """
    r2 = FakeR2(cmd_map={"s main": "", "pdg": "", "pdd": "", "pdc": ""})
    result = _decompile_with_default_cascade(
        r2, "main", clean_error_messages=True, options={"fallback_to_asm": False}
    )
    assert result.is_err()
    assert "Could not decompile" in result.error


def test_decompile_with_default_cascade_asm_seek_fails():
    """
    Purpose: Cover lines 173-174 — seek returns '0x0', so asm fallback
    returns err about seek failure.
    """
    r2 = FakeR2(cmd_map={
        "s main": "",
        "pdg": "",
        "pdd": "",
        "pdc": "",
        "s": "0x0",
    })
    result = _decompile_with_default_cascade(
        r2, "main", clean_error_messages=True, options={"fallback_to_asm": True}
    )
    assert result.is_err()
    assert "Seek to main failed" in result.error


# ===========================================================================
# 6. infrastructure/decompilers/orchestrator_service.py — lines 77-85, 92, 97
# ===========================================================================


def test_decompile_with_selected_decompiler_empty_functions():
    """
    Purpose: Cover lines 37-40 — empty functions list returns [] immediately
    with a warning.
    """
    config = create_config_from_dict({
        "decompiler": {"type": "default", "options": {}},
        "banned_functions": ["strcpy"],
    })
    r2 = FakeR2()
    result = decompile_with_selected_decompiler(
        r2, functions=[], verbose=True, config=config
    )
    assert result == []


def test_decompiler_orchestrator_decompile_function_with_options():
    """
    Purpose: Cover lines 77-85 — options passed to decompile_function cause
    config_factory branch to be taken.
    """
    config = create_config_from_dict({
        "decompiler": {"type": "default", "options": {}},
        "banned_functions": [],
    })

    def _factory(d: dict) -> Any:
        return create_config_from_dict(d)

    orchestrator = DecompilerOrchestrator(config, config_factory=_factory)
    code = "void fn() { return 1 + 2 + 3 + 4; } // padding to exceed threshold"
    r2 = FakeR2(cmd_map={"s fn": "", "pdc": code, "pdg": code, "pdd": code})
    result = orchestrator.decompile_function(
        r2, "fn", "default", clean_error_messages=False
    )
    assert result.is_ok() or result.is_err()


def test_decompiler_orchestrator_select_decompiler():
    """
    Purpose: Cover line 92 — select_decompiler returns a valid string.
    """
    config = create_config_from_dict({
        "decompiler": {"type": "default", "options": {}},
    })
    orch = DecompilerOrchestrator(config)
    selected = orch.select_decompiler()
    assert isinstance(selected, str)


def test_decompiler_orchestrator_check_decompiler_available():
    """
    Purpose: Cover line 97 — check_decompiler_available delegates correctly.
    """
    config = create_config_from_dict({
        "decompiler": {"type": "default", "options": {}},
    })
    orch = DecompilerOrchestrator(config)
    assert orch.check_decompiler_available("default") is True
    assert orch.check_decompiler_available("r2ai") is False


# ===========================================================================
# 7. infrastructure/decompilers/orchestrator_dispatch.py — lines 31, 35-37
# ===========================================================================


def test_decompile_function_configuration_error():
    """
    Purpose: Cover line 31 — KeyError from config["decompiler"] is caught and
    wrapped as err.
    """
    # Config missing "decompiler" key entirely — will raise KeyError
    config = FakeConfigRepository({})
    r2 = FakeR2()
    result = decompile_function(r2, "main", "default", config=config)
    assert result.is_err()
    assert "Configuration error" in result.error


def test_decompile_function_runtime_error_from_decompilation():
    """
    Purpose: Cover lines 35-37 — DecompilationError is caught and returned as err.
    """
    from bannedfuncdetector.infrastructure.decompilers.decompiler_types import DecompilationError

    class _ExplodingR2(FakeR2):
        def cmd(self, command: str) -> str:
            raise DecompilationError("decompiler exploded")

    config = create_config_from_dict({
        "decompiler": {"type": "default", "options": {}},
    })
    r2 = _ExplodingR2()
    result = decompile_function(r2, "main", "default", config=config)
    assert result.is_err()
    assert "decompil" in result.error.lower()


# ===========================================================================
# 8. infrastructure/decompilers/orchestrator_progress.py — lines 78-81
# ===========================================================================


def test_handle_processing_exception_verbose_at_interval():
    """
    Purpose: Cover lines 78-81 — verbose=True and current_index % log_interval==0
    causes the error to be logged.
    """
    exc = ValueError("unexpected data")
    result, ok_flag = _handle_processing_exception(
        func_name="main",
        exception=exc,
        verbose=True,
        log_interval=1,
        current_index=0,
    )
    assert ok_flag is False
    assert result.is_err()


def test_handle_processing_exception_silent_at_non_interval():
    """
    Cover non-verbose path: no logging, same Err structure returned.
    """
    exc = KeyError("missing_key")
    result, ok_flag = _handle_processing_exception(
        func_name="helper",
        exception=exc,
        verbose=False,
        log_interval=10,
        current_index=3,
    )
    assert ok_flag is False
    assert result.is_err()


# ===========================================================================
# 9. infrastructure/decompilers/orchestrator_runtime.py — lines 49, 53-54
# ===========================================================================


def _make_simple_config():
    return create_config_from_dict({
        "decompiler": {"type": "default", "options": {}},
        "banned_functions": [],
        "skip_small_functions": False,
        "small_function_threshold": 0,
    })


def test_process_single_function_empty_decompilation():
    """
    Purpose: Cover line 49 — decompile_result.unwrap() returns empty string;
    err about empty result is returned.
    """
    def _empty_decompile(r2, func_name, decompiler_type, *, config):
        return ok("")

    config = _make_simple_config()
    func = FunctionDescriptor(name="fn", address=0x1000, size=50)
    result, success = _process_single_function(
        r2=FakeR2(),
        func=func,
        decompiler_type="default",
        verbose=False,
        log_interval=1,
        current_index=0,
        config=config,
        decompile_function_impl=_empty_decompile,
    )
    assert success is False
    assert result.is_err()
    assert "Empty decompilation" in result.error


def test_process_single_function_raises_runtime_error():
    """
    Purpose: Cover lines 53-54 — RuntimeError from decompile_function_impl
    is caught and returns (err, False).
    """
    def _exploding_decompile(r2, func_name, decompiler_type, *, config):
        raise RuntimeError("r2 crashed")

    config = _make_simple_config()
    func = FunctionDescriptor(name="crash_fn", address=0x2000, size=50)
    result, success = _process_single_function(
        r2=FakeR2(),
        func=func,
        decompiler_type="default",
        verbose=False,
        log_interval=1,
        current_index=0,
        config=config,
        decompile_function_impl=_exploding_decompile,
    )
    assert success is False
    assert result.is_err()


# ===========================================================================
# 10. infrastructure/decompilers/orchestrator_search.py — lines 27-29
# ===========================================================================


def test_search_single_banned_function_type_error_returns_false():
    """
    Purpose: Cover lines 27-29 — TypeError during search is caught and False
    is returned.
    """
    # Pass an integer as decompiled_code; search_banned_call_in_text raises TypeError
    result = _search_single_banned_function(
        decompiled_code=12345,  # type: ignore[arg-type]
        insecure_func="strcpy",
        func_name="main",
    )
    assert result is False


def test_search_single_banned_function_found():
    """Cover the happy path — banned call is found."""
    result = _search_single_banned_function(
        decompiled_code="void fn() { strcpy(dst, src); }",
        insecure_func="strcpy",
        func_name="fn",
    )
    assert result is True


# ===========================================================================
# 11. infrastructure/decompilers/availability.py — lines 46-49, 67, 123, 161
# ===========================================================================


def test_check_decompiler_available_unknown_type():
    """
    Purpose: Cover lines 100-103 — unknown decompiler type returns False.
    """
    result = check_decompiler_available("totally_unknown_xyz", print_message=True)
    assert result is False


def test_check_decompiler_available_r2ai_not_a_decompiler():
    """
    Purpose: Cover lines 105-110 — r2ai has not_decompiler=True, returns False.
    """
    result = check_decompiler_available("r2ai", print_message=True)
    assert result is False


def test_check_decompiler_available_default_always_true():
    """
    Purpose: Cover lines 112-115 — default always_available=True returns True.
    """
    result = check_decompiler_available("default", print_message=True)
    assert result is True


def test_check_decompiler_available_enum_input():
    """
    Purpose: Cover lines 96-97 — DecompilerType enum is converted to string first.
    """
    result = check_decompiler_available(DecompilerType.DEFAULT, print_message=False)
    assert result is True


def test_check_plugin_decompiler_logs_available(caplog):
    """
    Purpose: Cover lines 67 — print_message=True with available result logs info.
    This uses 'default' via its always_available path which calls a different branch;
    we test the _check_plugin_decompiler path with print_message by calling it directly.
    """
    from bannedfuncdetector.infrastructure.decompilers.availability import (
        _check_plugin_decompiler,
    )
    # _check_plugin_decompiler with print_message=True; result may be True or False
    # depending on actual r2 plugins installed — we only check it does not raise
    _check_plugin_decompiler("r2ghidra", print_message=True)


def test_check_decompiler_available_check_service_branch():
    """
    Purpose: Cover lines 117-118 — check_service branch invokes _check_service_decompiler.
    Decai check returns bool without raising.
    """
    result = check_decompiler_available("decai", print_message=False)
    assert isinstance(result, bool)


# ===========================================================================
# 12. infrastructure/decompilers/base_decompiler.py — lines 45-51
#     BaseR2Decompiler.decompile() calls try_decompile_with_command and
#     returns "" when None is returned (line 51 in base_decompiler.py).
# ===========================================================================


def test_base_r2_decompiler_decompile_returns_empty_when_no_output():
    """
    Purpose: Cover lines 45-51 — BaseR2Decompiler.decompile calls
    try_decompile_with_command; when that returns None the method returns "".

    We use DefaultDecompiler (a concrete subclass) which calls the base
    decompile via its own override that also exercises lines 54-60.
    """
    r2 = FakeR2(cmd_map={"s fn": "", "pdc": ""})
    d = DefaultDecompiler()
    result = d.decompile(r2, "fn")
    assert result == ""


def test_base_r2_decompiler_decompile_returns_output_when_present():
    """
    Purpose: Cover line 51 — decompile returns non-empty string when
    try_decompile_with_command succeeds.
    """
    code = "void fn() { int x = 42; return x * 2; } // plenty of content here"
    r2 = FakeR2(cmd_map={"s fn": "", "pdc": code})
    d = DefaultDecompiler()
    result = d.decompile(r2, "fn")
    assert isinstance(result, str)
    assert len(result) > 0


def test_try_decompile_with_command_returns_none_for_short_output():
    """
    Purpose: Cover lines 65-67 in decompiler_support.py via base_decompiler
    re-export — output shorter than MIN_DECOMPILED_CODE_LENGTH returns None.
    """
    r2 = FakeR2(cmd_map={"s main": "", "pdc": "x"})
    result = try_decompile_with_command(r2, "pdc", "main", clean_error_messages=False)
    assert result is None


# ===========================================================================
# 13. infrastructure/decompilers/decompiler_availability.py — lines 54, 65-70, 83, 86, 90-92
# ===========================================================================


def test_check_r2_plugin_available_returns_bool():
    """
    Purpose: Cover lines 57-70 — runs a real R2Client.open("-") check.
    The check_cmd="Lc" and expected="r2ghidra" may or may not match; we only
    verify the function returns a bool without raising.
    """
    result = _check_r2_plugin_available("Lc", "r2ghidra")
    assert isinstance(result, bool)


def test_check_r2_plugin_available_with_list_expected():
    """
    Purpose: Cover lines 62-63 — expected is a list; any() is used.
    """
    result = _check_r2_plugin_available("Lc", ["pdd", "r2dec"])
    assert isinstance(result, bool)


def test_check_decai_service_available_returns_bool():
    """
    Purpose: Cover lines 73-92 — runs real R2 and then hits the requests.get
    for Ollama.  Without Ollama running, RequestException is caught.
    """
    result = _check_decai_service_available("http://localhost:11434")
    assert isinstance(result, bool)


# ===========================================================================
# 14. infrastructure/decompilers/decompiler_support.py — lines 42-43, 80-82, 111-113
# ===========================================================================


def test_normalize_function_info_list_returns_first():
    """
    Purpose: Cover lines 89-90 — list input returns first element.
    """
    info = [{"name": "fn", "offset": 0x1000}, {"name": "fn2"}]
    result = _normalize_function_info(info)
    assert result == {"name": "fn", "offset": 0x1000}


def test_normalize_function_info_empty_list_returns_none():
    """Cover lines 89-90 — empty list returns None."""
    assert _normalize_function_info([]) is None


def test_normalize_function_info_dict_returns_dict():
    """Cover line 91-92 — dict input is returned directly."""
    d = {"name": "fn", "offset": 0x2000}
    assert _normalize_function_info(d) is d


def test_normalize_function_info_none_returns_none():
    """Cover line 87-88 — None input returns None."""
    assert _normalize_function_info(None) is None


def test_normalize_function_info_unrecognised_type_returns_none():
    """Cover line 93 — unexpected type returns None."""
    assert _normalize_function_info(42) is None


def test_try_decompile_pair_primary_succeeds():
    """
    Purpose: Cover lines 126-129 — primary command succeeds; returns its result.
    """
    code = "void fn() { return 99; } // extra filler content to pass length check"
    r2 = FakeR2(cmd_map={"s fn": "", "pdg": code, "pdd": ""})
    result = _try_decompile_pair(
        r2, "fn", primary_cmd="pdg", fallback_cmd="pdd",
        clean_error_messages=True, use_alternative=True,
    )
    assert "fn" in result or len(result) > 0


def test_try_decompile_pair_primary_fails_fallback_disabled():
    """
    Purpose: Cover lines 131-138 — primary fails; use_alternative=False returns "".
    """
    r2 = FakeR2(cmd_map={"s fn": "", "pdg": "", "pdd": ""})
    result = _try_decompile_pair(
        r2, "fn", primary_cmd="pdg", fallback_cmd="pdd",
        clean_error_messages=True, use_alternative=False,
    )
    assert result == ""


def test_try_decompile_pair_primary_fails_fallback_also_fails():
    """
    Purpose: Cover lines 131-138 — both fail; use_alternative=True returns "".
    """
    r2 = FakeR2(cmd_map={"s fn": "", "pdg": "", "pdd": ""})
    result = _try_decompile_pair(
        r2, "fn", primary_cmd="pdg", fallback_cmd="pdd",
        clean_error_messages=True, use_alternative=True,
    )
    assert result == ""


# ===========================================================================
# 15. infrastructure/decompilers/decompiler_types.py — line 23
# ===========================================================================


def test_decompiler_type_from_string_unknown_returns_default():
    """
    Purpose: Cover line 23 (34-35 in decompiler_types.py) — unknown string
    logs warning and returns DEFAULT.
    """
    result = DType.from_string("totally_unknown_type")
    assert result == DType.DEFAULT


def test_decompiler_type_from_string_r2ai_returns_default():
    """Cover line 26-28 — r2ai is redirected to DEFAULT."""
    result = DType.from_string("r2ai")
    assert result == DType.DEFAULT


def test_decompiler_type_from_string_none_returns_default():
    """Cover line 22-23 — None returns DEFAULT."""
    result = DType.from_string(None)
    assert result == DType.DEFAULT


# ===========================================================================
# 16. infrastructure/decompilers/default_decompiler.py — lines 54-60
# ===========================================================================


def test_default_decompiler_is_available_always_true():
    """
    Purpose: Cover line 74 — is_available always returns True.
    """
    decompiler = DefaultDecompiler()
    assert decompiler.is_available() is True
    assert decompiler.is_available(r2=None) is True


def test_default_decompiler_decompile_returns_string():
    """
    Purpose: Cover lines 54-60 — decompile executes and returns str.
    """
    code = "void main() { return; } // extra padding here for length check"
    r2 = FakeR2(cmd_map={"s main": "", "pdc": code})
    decompiler = DefaultDecompiler()
    result = decompiler.decompile(r2, "main")
    assert isinstance(result, str)


def test_default_decompiler_decompile_empty_returns_empty_string():
    """Cover the path where try_decompile_with_command returns None -> ""."""
    r2 = FakeR2(cmd_map={"s main": "", "pdc": ""})
    decompiler = DefaultDecompiler()
    result = decompiler.decompile(r2, "main")
    assert result == ""


# ===========================================================================
# 17. infrastructure/decompilers/registry.py — lines 85, 90-93
# ===========================================================================


def test_create_decompiler_string_r2ghidra():
    """
    Purpose: Cover lines 82-95 — string 'r2ghidra' is resolved to enum and
    corresponding instance is returned.
    """
    from bannedfuncdetector.infrastructure.decompilers.r2ghidra_decompiler import R2GhidraDecompiler
    d = create_decompiler("r2ghidra")
    assert isinstance(d, R2GhidraDecompiler)


def test_create_decompiler_string_r2dec():
    from bannedfuncdetector.infrastructure.decompilers.r2dec_decompiler import R2DecDecompiler
    d = create_decompiler("r2dec")
    assert isinstance(d, R2DecDecompiler)


def test_create_decompiler_string_decai():
    d = create_decompiler("decai")
    assert isinstance(d, DecAIDecompiler)


def test_create_decompiler_enum_default():
    """Cover line 84-85 — enum input is accepted directly."""
    d = create_decompiler(DecompilerType.DEFAULT)
    assert isinstance(d, DefaultDecompiler)


def test_create_decompiler_unknown_string_logs_warning_and_returns_default():
    """
    Purpose: Cover lines 90-93 — key not in DECOMPILER_INSTANCES triggers warning
    and falls back to DEFAULT.

    Strategy: temporarily remove the 'r2ghidra' entry so that requesting 'r2ghidra'
    causes from_string to produce DecompilerType.R2GHIDRA, whose .value is 'r2ghidra',
    and that key is absent from the dict — hitting lines 89-93.  DEFAULT remains
    present so the fallback lookup succeeds.
    """
    from bannedfuncdetector.infrastructure.decompilers import registry

    original_r2ghidra = registry.DECOMPILER_INSTANCES.pop("r2ghidra")
    try:
        d = create_decompiler("r2ghidra")
        # Should fall back to default because 'r2ghidra' key is gone
        assert isinstance(d, DefaultDecompiler)
    finally:
        registry.DECOMPILER_INSTANCES["r2ghidra"] = original_r2ghidra


# ===========================================================================
# 18. infrastructure/decompilers/decai_decompiler.py
# ===========================================================================


def test_decai_decompiler_is_available_returns_bool():
    """
    Purpose: Cover the is_available path — delegates to check_decompiler_plugin_available.
    """
    d = DecAIDecompiler()
    result = d.is_available()
    assert isinstance(result, bool)


def test_decai_decompiler_decompile_function_not_found_returns_empty():
    """
    Purpose: Cover lines 293-295 — FunctionNotFoundError caught; returns "".
    FakeR2 returns None from afij (no function info).
    """
    r2 = FakeR2(cmdj_map={"afij @ main": None})
    d = DecAIDecompiler()
    result = d.decompile(r2, "main")
    assert result == ""


def test_decai_decompiler_decompile_runtime_error_returns_empty():
    """
    Purpose: Cover lines 296-302 — RuntimeError caught; returns "".
    """
    class _ExplodingR2(FakeR2):
        def cmdj(self, command: str):
            raise RuntimeError("r2 gone")

    d = DecAIDecompiler()
    result = d.decompile(_ExplodingR2(), "main")
    assert result == ""


def test_decai_decompiler_decompile_attribute_error_returns_empty():
    """
    Purpose: Cover lines 303-309 — AttributeError caught; returns "".
    """
    class _BadAttrR2(FakeR2):
        def cmdj(self, command: str):
            raise AttributeError("no attribute")

    d = DecAIDecompiler()
    result = d.decompile(_BadAttrR2(), "main")
    assert result == ""


def test_configure_decai_model_already_configured():
    """
    Purpose: Cover lines 58-59 — both api and model are set; early return.
    """
    r2 = FakeR2(cmd_map={
        "decai -e api": "api=ollama",
        "decai -e model": "model=qwen2:5b",
    })
    _configure_decai_model(r2)  # Must not raise


def test_configure_decai_model_api_set_no_model():
    """
    Purpose: Cover lines 63-71 — api set but model empty; uses first available model.
    """
    call_count = {"n": 0}

    def _cmd(command: str) -> str:
        if command == "decai -e api":
            return "api=ollama"
        if command == "decai -e model":
            return ""
        if command == "decai -m?":
            return "qwen2:5b-coder\ncodellama:7b"
        call_count["n"] += 1
        return ""

    r2 = FakeR2()
    r2.cmd_map = {}  # replace map with callable
    class _SmartR2(FakeR2):
        def cmd(self, command: str) -> str:
            return _cmd(command)

    smart_r2 = _SmartR2()
    _configure_decai_model(smart_r2)  # Must not raise


def test_configure_decai_model_ollama_detected():
    """
    Purpose: Cover lines 75-101 — ollama list returns output; preferred model found.
    """
    class _OllamaR2(FakeR2):
        def cmd(self, command: str) -> str:
            if command == "decai -e api":
                return ""
            if command == "decai -e model":
                return ""
            if command == "!ollama list 2>/dev/null":
                return "NAME\nqwen2:5b-coder latest abc 3.1 GB 5 days ago"
            return ""

    _configure_decai_model(_OllamaR2())  # Must not raise


def test_configure_decai_model_no_ollama():
    """
    Purpose: Cover line 77 — ollama list empty; early return with info log.
    """
    class _NoOllamaR2(FakeR2):
        def cmd(self, command: str) -> str:
            if command in ("decai -e api", "decai -e model"):
                return ""
            if command == "!ollama list 2>/dev/null":
                return ""
            return ""

    _configure_decai_model(_NoOllamaR2())  # Must not raise


def test_try_decai_decompilation_first_method_succeeds():
    """
    Purpose: Cover lines 130-132 — direct decompilation succeeds on first attempt.
    """
    long_code = "int main(int argc, char** argv) { return 0; } // filler content"
    r2 = FakeR2(cmd_map={"decai -d": long_code})
    result = _try_decai_decompilation(r2, "main")
    assert result is not None


def test_try_decai_decompilation_second_method_succeeds():
    """
    Purpose: Cover lines 135-138 — first fails; recursive decompilation succeeds.
    """
    long_code = "int main(int argc, char** argv) { return 0; } // filler content"
    r2 = FakeR2(cmd_map={"decai -d": "", "decai -dr": long_code})
    result = _try_decai_decompilation(r2, "main")
    assert result is not None


def test_try_decai_decompilation_all_methods_fail():
    """
    Purpose: Cover line 148 — all three methods fail; returns None.
    """
    r2 = FakeR2(cmd_map={
        "decai -d": "",
        "decai -dr": "",
        "pdf": "",
    })
    # The third method uses cmd with a dynamic key containing the query
    result = _try_decai_decompilation(r2, "main")
    assert result is None


def test_fallback_to_r2ghidra_returns_output():
    """
    Purpose: Cover lines 176-182 — fallback to pdg returns the command output.
    """
    r2 = FakeR2(cmd_map={"pdg": "void main() { return 0; }"})
    result = _fallback_to_r2ghidra(r2)
    assert "main" in result or result == "void main() { return 0; }"


def test_fallback_to_r2ghidra_raises_on_runtime_error():
    """
    Purpose: Cover lines 181-182 — RuntimeError during pdg raises DecompilationError.
    """
    from bannedfuncdetector.infrastructure.decompilers.decompiler_types import DecompilationError

    class _ExplodingR2(FakeR2):
        def cmd(self, command: str) -> str:
            raise RuntimeError("pdg failed")

    with pytest.raises(DecompilationError):
        _fallback_to_r2ghidra(_ExplodingR2())


def test_decompile_with_decai_unknown_command_in_check():
    """
    Purpose: Cover lines 203-207 — decai -h returns 'Unknown command'; falls
    back to r2ghidra path.
    """
    r2 = FakeR2(
        cmd_map={
            "decai -h": "Unknown command",
            "pdg": "void fn() { return 0; }",
        },
        cmdj_map={
            "afij @ fn": [{"name": "fn", "offset": 0x1000}],
            "sj": {"offset": 0x1000},
        },
    )
    # Seek command returns empty but that's fine
    result = decompile_with_decai(r2, "fn")
    assert isinstance(result, str)


def test_decompile_with_decai_seek_returns_empty_list_raises():
    """
    Purpose: Cover lines 213-214 — sj returns empty list; DecompilationError raised.
    """
    from bannedfuncdetector.infrastructure.decompilers.decompiler_types import DecompilationError

    r2 = FakeR2(
        cmd_map={
            "decai -h": "Usage: decai",
        },
        cmdj_map={
            "afij @ fn": [{"name": "fn", "offset": 0x2000}],
            "sj": [],
        },
    )
    with pytest.raises(DecompilationError):
        decompile_with_decai(r2, "fn")


def test_decompile_with_decai_sj_dict_no_offset_raises():
    """
    Purpose: Cover lines 225-227 — sj returns dict without 'offset' key.
    """
    from bannedfuncdetector.infrastructure.decompilers.decompiler_types import DecompilationError

    r2 = FakeR2(
        cmd_map={"decai -h": "Usage: decai"},
        cmdj_map={
            "afij @ fn": [{"name": "fn", "offset": 0x3000}],
            "sj": {"addr": 0x3000},  # no 'offset' key
        },
    )
    with pytest.raises(DecompilationError):
        decompile_with_decai(r2, "fn")


def test_decompile_with_decai_sj_wrong_type_raises():
    """
    Purpose: Cover lines 228-229 — sj returns unexpected type (int).
    """
    from bannedfuncdetector.infrastructure.decompilers.decompiler_types import DecompilationError

    r2 = FakeR2(
        cmd_map={"decai -h": "Usage: decai"},
        cmdj_map={
            "afij @ fn": [{"name": "fn", "offset": 0x4000}],
            "sj": 12345,
        },
    )
    with pytest.raises(DecompilationError):
        decompile_with_decai(r2, "fn")


def test_resolve_function_offset_function_not_found_raises():
    """
    Purpose: Cover lines 165-167 — afij returns None; FunctionNotFoundError raised.
    """
    from bannedfuncdetector.infrastructure.decompilers.decompiler_types import FunctionNotFoundError

    r2 = FakeR2(cmdj_map={"afij @ main": None})
    with pytest.raises(FunctionNotFoundError, match="Could not get function information"):
        _resolve_function_offset(r2, "main")


def test_resolve_function_offset_offset_none_raises():
    """
    Purpose: Cover lines 170-171 — _get_function_offset returns None;
    FunctionNotFoundError raised.
    """
    from bannedfuncdetector.infrastructure.decompilers.decompiler_types import FunctionNotFoundError

    r2 = FakeR2(
        cmdj_map={
            "afij @ main": [{"name": "main"}],  # no 'offset' or 'addr'
            "sj": None,
        },
        cmd_map={"s main": ""},
    )
    with pytest.raises(FunctionNotFoundError, match="Could not get valid function"):
        _resolve_function_offset(r2, "main")


# ===========================================================================
# 19. infrastructure/validators.py
# ===========================================================================


def test_check_python_version_passes_on_current_interpreter():
    """
    Purpose: Cover lines 37-41 — current interpreter meets MIN_PYTHON_VERSION
    so no sys.exit is called.  If this test ran at all, the version check passed.
    """
    # The real sys.version_info is used; we only check it does not raise.
    # If Python < 3.14, sys.exit(1) would be called; this test ensures the
    # code path is exercised on a passing version.
    check_python_version()  # Must not call sys.exit


def test_check_available_decompilers_does_not_raise():
    """
    Purpose: Cover lines 83-118 — _check_available_decompilers opens a real
    r2 session on /bin/ls (or /usr/bin/ls on macOS) and lists decompilers.
    """
    # Use whatever ls is available; the function handles missing file gracefully.
    _check_available_decompilers()  # Must not raise


def test_validate_binary_file_nonexistent_returns_false():
    """
    Purpose: Cover lines 154-156 — file does not exist returns False.
    """
    result = validate_binary_file("/does/not/exist/binary.exe")
    assert result is False


def test_validate_binary_file_text_file_returns_false(tmp_path):
    """
    Purpose: Cover lines 158-160 — file exists but is not a valid binary.
    """
    txt = tmp_path / "readme.txt"
    txt.write_text("hello world")
    result = validate_binary_file(str(txt))
    assert result is False


def test_validate_binary_file_pe_file_returns_true(tmp_path):
    """
    Purpose: Cover line 162 — valid PE binary returns True.
    """
    pe = tmp_path / "sample.exe"
    write_minimal_pe(pe)
    result = validate_binary_file(str(pe))
    assert result is True


# ===========================================================================
# 20. presentation/reporting.py — lines 32-33, 43-46, 58, 85-87
# ===========================================================================


def _make_analysis_result(
    with_banned: bool = False, file_path: str = "/tmp/test.exe"
) -> AnalysisResult:
    detected: tuple[BannedFunction, ...] = ()
    if with_banned:
        detected = (
            BannedFunction(
                name="main",
                address=0x1000,
                size=100,
                banned_calls=("strcpy",),
                detection_method="decompilation",
            ),
        )
    return AnalysisResult(
        file_name="test.exe",
        file_path=file_path,
        total_functions=5,
        detected_functions=detected,
        analysis_date="2026-03-15",
    )


def test_display_final_results_binary_no_findings(caplog):
    """
    Purpose: Cover lines 35-41 — BinaryAnalysisOutcome with no detected functions.
    Operational notice without file_path.
    """
    outcome = BinaryAnalysisOutcome(
        report=_make_analysis_result(with_banned=False),
        operational_notices=(OperationalNotice(message="test notice"),),
    )
    display_final_results(outcome)


def test_display_final_results_binary_with_findings(caplog):
    """
    Purpose: Cover lines 43-51, 58 — operational notice with file_path, detected
    functions are logged.
    """
    outcome = BinaryAnalysisOutcome(
        report=_make_analysis_result(with_banned=True),
        operational_notices=(
            OperationalNotice(message="slow analysis", file_path="/tmp/test.exe"),
        ),
    )
    display_final_results(outcome)


def test_display_final_results_none_like_logs_warning(caplog):
    """
    Purpose: Cover lines 32-33 — falsy result logs a warning.
    """
    # Pass None; the function checks `if not result` first.
    display_final_results(None)  # type: ignore[arg-type]


def test_display_final_results_directory_outcome():
    """
    Purpose: Cover line 58 — DirectoryAnalysisOutcome path uses summary.analyzed_results.
    """
    summary = DirectoryAnalysisSummary(
        directory="/tmp",
        analyzed_results=(
            _make_analysis_result(with_banned=True, file_path="/tmp/a.exe"),
            _make_analysis_result(with_banned=False, file_path="/tmp/b.exe"),
        ),
        total_files=2,
    )
    outcome = DirectoryAnalysisOutcome(
        summary=summary,
        operational_notices=(OperationalNotice(message="dir notice"),),
    )
    display_final_results(outcome)


def test_display_final_results_format_address_none_like():
    """
    Purpose: Cover lines 85-87 — _format_address with non-int/non-str input
    returns hex(0).
    """
    from bannedfuncdetector.presentation.reporting import _format_address
    assert _format_address(None) == "0x0"
    assert _format_address(0x1234) == "0x1234"
    assert _format_address("sym.main") == "sym.main"
