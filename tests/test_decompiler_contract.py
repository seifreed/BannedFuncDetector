"""Protocol-contract tests shared by every decompiler backend.

Every backend must satisfy the same IDecompiler contract: expose its name and
command, return a bool from is_available (with or without an r2 instance), and
provide the decompile/is_available/get_name methods. Backend-specific behaviour
(decai model configuration, r2dec/r2ghidra fallbacks, etc.) lives in the
per-decompiler test modules; this module covers only the shared contract, once,
across all four backends.
"""

import pytest
import logging

import bannedfuncdetector.infrastructure.decompilers.decai_decompiler as decai_module
from bannedfuncdetector.infrastructure.decompilers.decai_decompiler import (
    DecAIDecompiler,
)
from bannedfuncdetector.infrastructure.decompilers.default_decompiler import (
    DefaultDecompiler,
)
from bannedfuncdetector.infrastructure.decompilers.r2dec_decompiler import (
    R2DecDecompiler,
)
from bannedfuncdetector.infrastructure.decompilers.r2ghidra_decompiler import (
    R2GhidraDecompiler,
)

DECOMPILERS = [
    pytest.param(DefaultDecompiler, "default", "pdc", id="default"),
    pytest.param(R2GhidraDecompiler, "r2ghidra", "pdg", id="r2ghidra"),
    pytest.param(R2DecDecompiler, "r2dec", "pdd", id="r2dec"),
    pytest.param(DecAIDecompiler, "decai", "decai -d", id="decai"),
]


def test_decai_optional_fallback_does_not_emit_info_or_warning(monkeypatch, caplog):
    class R2Unavailable:
        def cmd(self, command):
            if command == "decai -h":
                return "Unknown command"
            if command == "pdg":
                return "decompiled"
            return ""

    monkeypatch.setattr(decai_module, "_resolve_function_offset", lambda *_args: 0)
    caplog.set_level(logging.DEBUG, logger=decai_module.__name__)

    assert decai_module.decompile_with_decai(R2Unavailable(), "entry") == "decompiled"
    fallback_logs = [
        record for record in caplog.records if record.name == decai_module.__name__
    ]
    assert fallback_logs
    assert all(record.levelno == logging.DEBUG for record in fallback_logs)


@pytest.mark.parametrize("cls, name, command", DECOMPILERS)
class TestDecompilerContract:
    """The IDecompiler contract that holds for every backend."""

    def test_init_sets_name_and_command(self, cls, name, command):
        decompiler = cls()
        assert decompiler.name == name
        assert decompiler.command == command
        assert decompiler.get_name() == name

    def test_is_available_returns_bool(self, cls, name, command):
        # Result depends on system configuration; the contract is the bool type.
        assert isinstance(cls().is_available(), bool)

    def test_is_available_with_r2_returns_bool(self, cls, name, command, fake_r2):
        # The r2 argument is accepted for interface compatibility (unused).
        assert isinstance(cls().is_available(fake_r2), bool)

    def test_get_name_returns_nonempty_string(self, cls, name, command):
        result = cls().get_name()
        assert isinstance(result, str)
        assert result == name

    def test_protocol_methods_present(self, cls, name, command):
        decompiler = cls()
        for method in ("decompile", "is_available", "get_name"):
            assert callable(getattr(decompiler, method))

    def test_decompile_missing_function_returns_empty(
        self, cls, name, command, fake_r2_factory
    ):
        fake = fake_r2_factory(cmdj_map={"afij @ missing": None})
        assert cls().decompile(fake, "missing") == ""
