# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Tests for config-driven decai backend wiring.

config.json is the source of truth for which AI backend decai uses; these
tests verify the configured api/model/base-URL are applied to the plugin via
`decai -e`, using a recording fake r2 client (no mocks, no live plugin/key).
"""

from __future__ import annotations

import bannedfuncdetector.infrastructure.decompilers.selector as selector_mod
from bannedfuncdetector.factories import create_config_from_dict
from bannedfuncdetector.infrastructure.decompilers.decai_decompiler import (
    _safe_decai_value,
    apply_decai_backend_config,
)
from bannedfuncdetector.infrastructure.decompilers.orchestrator import (
    _apply_decai_config_from,
    decompile_with_selected_decompiler,
)


class _RecordingR2:
    def __init__(self) -> None:
        self.cmds: list[str] = []

    def cmd(self, command: str) -> str:
        self.cmds.append(command)
        return ""


class _RaisingR2:
    def cmd(self, command: str) -> str:
        raise RuntimeError("r2 unavailable")


class _EmptyConfig:
    def __getitem__(self, key: str) -> dict:
        return {}


def test_safe_decai_value_accepts_plain_tokens() -> None:
    assert _safe_decai_value("gemini") == "gemini"
    assert _safe_decai_value("  gemini-2.0-flash  ") == "gemini-2.0-flash"


def test_safe_decai_value_rejects_empty_and_metacharacters() -> None:
    assert _safe_decai_value("") is None
    assert _safe_decai_value("   ") is None
    assert _safe_decai_value("gemini;!id") is None
    assert _safe_decai_value("model\nname") is None


def test_apply_cloud_backend_sets_api_and_model_only() -> None:
    r2 = _RecordingR2()
    apply_decai_backend_config(r2, {"api": "gemini", "model": "gemini-2.0-flash"})
    assert r2.cmds == ["decai -e api=gemini", "decai -e model=gemini-2.0-flash"]


def test_apply_self_hosted_backend_derives_base_url() -> None:
    r2 = _RecordingR2()
    apply_decai_backend_config(
        r2,
        {"api": "ollama", "model": "qwen2:5b-coder", "host": "http://localhost", "port": 11434},
    )
    assert "decai -e baseurl=http://localhost:11434" in r2.cmds


def test_apply_host_without_port_uses_bare_host() -> None:
    r2 = _RecordingR2()
    apply_decai_backend_config(r2, {"api": "openai", "host": "http://gw.local"})
    assert "decai -e baseurl=http://gw.local" in r2.cmds


def test_apply_skips_unsafe_and_empty_values() -> None:
    r2 = _RecordingR2()
    apply_decai_backend_config(r2, {"api": "gem;ini", "model": "", "host": ""})
    assert r2.cmds == []


def test_apply_swallows_r2_errors() -> None:
    # Must not raise even if the plugin command fails.
    apply_decai_backend_config(_RaisingR2(), {"api": "gemini"})


def test_orchestrator_applies_decai_config_when_selected() -> None:
    config = create_config_from_dict({})  # decai default is gemini
    r2 = _RecordingR2()

    original = selector_mod.check_decompiler_available
    try:
        selector_mod.check_decompiler_available = (
            lambda name, print_message=False: name == "decai"
        )
        result = decompile_with_selected_decompiler(
            r2, [], decompiler_type="decai", config=config
        )
    finally:
        selector_mod.check_decompiler_available = original

    assert result == []
    assert "decai -e api=gemini" in r2.cmds


def test_apply_decai_config_from_noop_without_decai_options() -> None:
    r2 = _RecordingR2()
    _apply_decai_config_from(_EmptyConfig(), r2)
    assert r2.cmds == []


def test_config_to_dict_serializes_self_hosted_host_and_port() -> None:
    """A self-hosted decai backend (host+port) round-trips through to_dict.

    The default backend is cloud (no host/port), so this guards the host/port
    serialization branches that an Ollama user relies on.
    """
    from bannedfuncdetector.infrastructure.config_models import (
        AppConfig,
        DecompilerOption,
    )

    config = AppConfig(
        decompiler_options={
            "decai": DecompilerOption(
                api="ollama",
                model="qwen2:5b-coder",
                host="http://localhost",
                port=11434,
            )
        }
    )

    decai = config.to_dict()["decompiler"]["options"]["decai"]

    assert decai["host"] == "http://localhost"
    assert decai["port"] == 11434
