# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for config-value handling:
  * AppConfig from_dict -> to_dict -> from_dict preserved nested AI/error fields;
  * the per-binary worker limit is read from config["analysis"], not top-level;
  * decai port accepts a numeric string instead of silently dropping it.
"""

from __future__ import annotations

from bannedfuncdetector.factories import create_config_from_dict
from bannedfuncdetector.infrastructure.config_models import AppConfig
from bannedfuncdetector.application.internal.directory_workers import (
    _resolve_worker_limit,
)
from bannedfuncdetector.infrastructure.decompilers.decai_decompiler import (
    apply_decai_backend_config,
)


class _RecordingR2:
    def __init__(self) -> None:
        self.cmds: list[str] = []

    def cmd(self, command: str) -> str:
        self.cmds.append(command)
        return ""


def test_appconfig_roundtrip_preserves_nested_fields() -> None:
    data = {
        "decompiler": {
            "type": "decai",
            "options": {
                "decai": {
                    "advanced_options": {
                        "temperature": 0.0,
                        "max_tokens": 100,
                        "context": 2048,
                        "system_prompt": "custom prompt",
                    },
                    "error_handling": {
                        "ignore_unknown_branches": False,
                        "clean_error_messages": False,
                        "fallback_to_asm": False,
                    },
                }
            },
        }
    }
    rebuilt = AppConfig.from_dict(AppConfig.from_dict(data).to_dict())
    opt = rebuilt.decompiler_options["decai"]

    assert opt.temperature == 0.0
    assert opt.max_tokens == 100
    assert opt.context == 2048
    assert opt.system_prompt == "custom prompt"
    assert opt.ignore_unknown_branches is False
    assert opt.clean_error_messages is False
    assert opt.fallback_to_asm is False


def test_worker_limit_read_from_analysis_section() -> None:
    config = create_config_from_dict({"analysis": {"worker_limit": 50}})
    assert _resolve_worker_limit(config) == 50


def test_worker_limit_defaults_to_none_when_unset() -> None:
    config = create_config_from_dict({})  # analysis.worker_limit is null
    assert _resolve_worker_limit(config) is None


def test_decai_port_accepts_numeric_string() -> None:
    r2 = _RecordingR2()
    apply_decai_backend_config(
        r2, {"api": "ollama", "host": "http://localhost", "port": "11434"}
    )
    assert "decai -e baseurl=http://localhost:11434" in r2.cmds


def test_coerce_port_branches() -> None:
    from bannedfuncdetector.infrastructure.decompilers.decai_decompiler import (
        _coerce_port,
    )

    assert _coerce_port(11434) == 11434
    assert _coerce_port("11434") == 11434
    assert _coerce_port(True) is None      # bool is not a valid port
    assert _coerce_port(0) is None         # non-positive
    assert _coerce_port(-1) is None
    assert _coerce_port("0") is None       # numeric but non-positive
    assert _coerce_port("abc") is None
    assert _coerce_port(None) is None


def test_worker_limit_none_when_analysis_not_a_dict() -> None:
    class _BadConfig:
        def get(self, key: str, default: object = None) -> object:
            return "not-a-dict"  # analysis section is malformed

    assert _resolve_worker_limit(_BadConfig()) is None
