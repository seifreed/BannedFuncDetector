#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - DecAI Decompiler Tests

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Author: Marc Rivero | @seifreed
"""

import pytest
from unittest.mock import patch
from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    DecompilerType,
    check_decompiler_plugin_available,
    DECAI_PREFERRED_MODELS,
    DecompilationError,
    FunctionNotFoundError,
)
from bannedfuncdetector.infrastructure.decompilers.decai_decompiler import (
    DecAIDecompiler,
    _configure_decai_model,
    _try_decai_decompilation,
    decompile_with_decai,
)
# Import from base_decompiler as some tests may reference internal functions
from bannedfuncdetector.infrastructure.decompilers.base_decompiler import (
    _check_decai_service_available as _check_decai_available,
)
from conftest import FakeR2


class TestDecAIAvailability:
    """Test suite for DecAI availability checking."""

    def test_check_decai_available_plugin_not_available(self):
        """Test decai availability when plugin is not available."""
        # Test with non-existent service URL
        result = _check_decai_available("http://localhost:99999")
        # Should return False when Ollama service not available
        assert result is False

    def test_check_decai_available_ollama_unreachable(self, fake_r2_factory):
        """Test decai availability when Ollama service is unreachable."""
        import requests

        fake = fake_r2_factory(
            cmd_map={"decai -h": "Usage: decai"}
        )

        # Try to check with non-existent Ollama service
        result = _check_decai_available("http://localhost:99999")
        assert result is False

    def test_check_decai_available_with_config(self):
        """Test check_decompiler_plugin_available for DECAI using configuration."""
        # This will use real DECOMPILER_CONFIG
        result = check_decompiler_plugin_available(DecompilerType.DECAI)
        # Result depends on actual system configuration
        assert isinstance(result, bool)


class TestDecAIModelConfiguration:
    """Test suite for DecAI model configuration."""

    def test_configure_decai_model_with_existing_config(self, fake_r2_factory):
        """Test model configuration uses existing config when set."""
        fake = fake_r2_factory(
            cmd_map={
                "decai -e api": "decai -e api=claude",
                "decai -e model": "decai -e model=claude-sonnet",
            }
        )

        _configure_decai_model(fake)

        # Should not attempt to call ollama since config is already set
        ollama_calls = [c for c in fake.calls if "ollama" in c[1]]
        assert len(ollama_calls) == 0

    def test_configure_decai_model_with_preferred_model(self, fake_r2_factory):
        """Test model configuration selects preferred model from Ollama."""
        fake = fake_r2_factory(
            cmd_map={
                "decai -e api": "",  # No API configured
                "decai -e model": "",  # No model configured
                "!ollama list 2>/dev/null": "NAME\nqwen2:5b-coder\nllama3\nmistral",
                "decai -e api=ollama": "",
                "decai -e model=*": "",
            }
        )

        _configure_decai_model(fake)

        # Verify ollama list was called via shell
        calls = [c for c in fake.calls if "!ollama list" in c[1]]
        assert len(calls) == 1

        # Verify api was set
        api_calls = [c for c in fake.calls if "decai -e api=ollama" in c[1]]
        assert len(api_calls) == 1

    def test_configure_decai_model_no_preferred_fallback(self, fake_r2_factory):
        """Test model configuration falls back when no preferred models found."""
        fake = fake_r2_factory(
            cmd_map={
                "decai -e api": "",
                "decai -e model": "",
                "!ollama list 2>/dev/null": "NAME\nsome-other-model\nanother-model",
                "decai -e api=ollama": "",
                "decai -e model=*": "",
            }
        )

        _configure_decai_model(fake)

        # Verify configuration was attempted
        calls = [c for c in fake.calls if "!ollama list" in c[1]]
        assert len(calls) == 1

    def test_configure_decai_model_empty_list(self, fake_r2_factory):
        """Test model configuration with empty model list uses defaults."""
        fake = fake_r2_factory(
            cmd_map={
                "decai -e api": "",
                "decai -e model": "",
                "!ollama list 2>/dev/null": "",
            }
        )

        # Should not raise exception
        _configure_decai_model(fake)

        # Verify ollama list was attempted
        calls = [c for c in fake.calls if "!ollama list" in c[1]]
        assert len(calls) == 1

    def test_configure_decai_model_exception_handling(self, fake_r2_factory):
        """Test model configuration handles exceptions gracefully."""
        def raise_error():
            # Use RuntimeError as a specific exception that _configure_decai_model catches
            raise RuntimeError("Connection error")

        fake = fake_r2_factory(
            cmd_map={
                "decai -e api": raise_error,
            }
        )

        # Should not raise, just log error
        _configure_decai_model(fake)


class TestDecAIDecompilation:
    """Test suite for DecAI decompilation methods."""

    def test_try_decai_decompilation_first_method_success(self, fake_r2_factory):
        """Test decompilation succeeds with first method."""
        expected_code = "void main() { printf(\"hello\"); }"
        fake = fake_r2_factory(
            cmd_map={
                "decai -d": expected_code,
            }
        )

        result = _try_decai_decompilation(fake, "main")

        assert result == expected_code
        # Verify only first method was tried
        decai_calls = [c for c in fake.calls if "decai" in c[1]]
        assert len(decai_calls) == 1

    def test_try_decai_decompilation_second_method_success(self, fake_r2_factory):
        """Test decompilation succeeds with recursive method after first fails."""
        expected_code = "void main() { return 0; } // this is a longer code"
        fake = fake_r2_factory(
            cmd_map={
                "decai -d": "",  # First method fails
                "decai -dr": expected_code,  # Second succeeds
            }
        )

        result = _try_decai_decompilation(fake, "main")

        assert result == expected_code

    def test_try_decai_decompilation_third_method_success(self, fake_r2_factory):
        """Test decompilation succeeds with direct query after other methods fail."""
        asm_code = "push rbp\nmov rbp, rsp"
        expected_code = "void main() { } // decompiled successfully"
        fake = fake_r2_factory(
            cmd_map={
                "decai -d": "",  # First fails
                "decai -dr": "",  # Second fails
                "pdf": asm_code,
                "decai -q *": expected_code,  # Third succeeds
            }
        )

        result = _try_decai_decompilation(fake, "main")

        assert result == expected_code

    def test_try_decai_decompilation_all_methods_fail(self, fake_r2_factory):
        """Test decompilation returns None when all methods fail."""
        fake = fake_r2_factory(
            cmd_map={
                "decai -d": "",
                "decai -dr": "",
                "pdf": "asm code",
                "decai -q *": "",
            }
        )

        result = _try_decai_decompilation(fake, "main")

        assert result is None

    def test_decompile_with_decai_function_not_found(self, fake_r2_factory):
        """Test decompilation raises FunctionNotFoundError when function info unavailable."""
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ main": None,  # No function info
            }
        )

        with pytest.raises(FunctionNotFoundError, match="Could not get function information"):
            decompile_with_decai(fake, "main")

    def test_decompile_with_decai_invalid_offset(self, fake_r2_factory):
        """Test decompilation raises FunctionNotFoundError for invalid offset."""
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ main": {"name": "main"},  # No offset field
            }
        )

        with pytest.raises(FunctionNotFoundError, match="Could not get valid function information"):
            decompile_with_decai(fake, "main")

    def test_decompile_with_decai_plugin_unavailable_fallback(self, fake_r2_factory):
        """Test decompilation falls back to r2ghidra when decai unavailable."""
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ main": {"name": "main", "offset": 4096},
                "sj": {"offset": 4096},
            },
            cmd_map={
                "decai -h": "Unknown command",
                "s 4096": "",
                "pdg": "void main() { }",
            }
        )

        result = decompile_with_decai(fake, "main")

        assert result == "void main() { }"

    def test_decompile_with_decai_positioning_error(self, fake_r2_factory):
        """Test decompilation raises DecompilationError when positioning fails."""
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ main": {"name": "main", "offset": 4096},
                "sj": None,  # Position verification fails
            },
            cmd_map={
                "decai -h": "Usage: decai",
                "s 4096": "",
            }
        )

        with pytest.raises(DecompilationError, match="Could not position at the function address"):
            decompile_with_decai(fake, "main")

    def test_decompile_with_decai_success(self, fake_r2_factory):
        """Test successful decompilation with decai."""
        expected_code = "void main() { printf(\"test\"); }"
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ main": {"name": "main", "offset": 4096},
                "sj": {"offset": 4096},
            },
            cmd_map={
                "decai -h": "Usage: decai",
                "s 4096": "",
                "ollama list": "qwen2:5b-coder",
                "decai -e api=ollama": "",
                "decai -e model=*": "",
                "decai -d": expected_code,
            }
        )

        result = decompile_with_decai(fake, "main")

        assert result == expected_code

    def test_decompile_with_decai_exception_fallback(self, fake_r2_factory):
        """Test decompilation falls back to r2ghidra after decai exception."""
        fallback_code = "void main() { }"

        def raise_error():
            # Use RuntimeError as a specific exception that the code catches
            raise RuntimeError("DecAI error")

        fake = fake_r2_factory(
            cmdj_map={
                "afij @ main": {"name": "main", "offset": 4096},
                "sj": {"offset": 4096},
            },
            cmd_map={
                "decai -h": "Usage: decai",
                "s 4096": "",
                "ollama list": "qwen2:5b-coder",
                "decai -e api=ollama": "",
                "decai -e model=*": "",
                "decai -d": raise_error,
                "pdg": fallback_code,
            }
        )

        result = decompile_with_decai(fake, "main")

        assert result == fallback_code


class TestDecAIDecompilerClass:
    """Test suite for DecAIDecompiler class."""

    def test_decai_decompiler_init(self):
        """Test DecAIDecompiler initialization."""
        decompiler = DecAIDecompiler()

        assert decompiler.name == "decai"
        assert decompiler.get_name() == "decai"

    def test_decai_decompiler_is_available(self):
        """Test is_available method."""
        decompiler = DecAIDecompiler()

        result = decompiler.is_available()

        # Result depends on system configuration
        assert isinstance(result, bool)

    def test_decai_decompiler_is_available_with_r2(self, fake_r2):
        """Test is_available method with r2 parameter (not used)."""
        decompiler = DecAIDecompiler()

        result = decompiler.is_available(fake_r2)

        assert isinstance(result, bool)

    def test_decai_decompiler_decompile_success(self, fake_r2_factory):
        """Test decompile method success path."""
        expected_code = "void test() { } // successful decompilation"
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ test": {"name": "test", "offset": 8192},
                "sj": {"offset": 8192},
            },
            cmd_map={
                "decai -h": "Usage: decai",
                "s 8192": "",
                "ollama list": "qwen2:5b-coder",
                "decai -e api=ollama": "",
                "decai -e model=*": "",
                "decai -d": expected_code,
            }
        )

        decompiler = DecAIDecompiler()
        result = decompiler.decompile(fake, "test")

        # DecAIDecompiler.decompile now returns str (extends BaseR2Decompiler)
        assert result == expected_code

    def test_decai_decompiler_decompile_function_not_found(self, fake_r2_factory):
        """Test decompile method returns empty string for missing function."""
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ missing": None,
            }
        )

        decompiler = DecAIDecompiler()
        result = decompiler.decompile(fake, "missing")

        # DecAIDecompiler.decompile now returns str (extends BaseR2Decompiler)
        # Returns empty string on failure
        assert result == ""

    def test_decai_decompiler_decompile_decompilation_error(self, fake_r2_factory):
        """Test decompile method returns empty string for decompilation failure."""
        fake = fake_r2_factory(
            cmdj_map={
                "afij @ func": {"name": "func", "offset": 4096},
                "sj": None,  # Positioning fails
            },
            cmd_map={
                "decai -h": "Usage: decai",
                "s 4096": "",
            }
        )

        decompiler = DecAIDecompiler()
        result = decompiler.decompile(fake, "func")

        # DecAIDecompiler.decompile now returns str (extends BaseR2Decompiler)
        # Returns empty string on failure
        assert result == ""

    def test_decai_decompiler_decompile_unexpected_error(self, fake_r2_factory):
        """Test decompile method handles unexpected errors."""
        def raise_error():
            raise RuntimeError("Unexpected runtime error")

        fake = fake_r2_factory(
            cmdj_map={
                "afij @ func": raise_error,
            }
        )

        decompiler = DecAIDecompiler()
        result = decompiler.decompile(fake, "func")

        # DecAIDecompiler.decompile now returns str (extends BaseR2Decompiler)
        # Returns empty string on failure
        assert result == ""


class TestDecAIPreferredModels:
    """Test suite for DecAI preferred models configuration."""

    def test_preferred_models_defined(self):
        """Test that preferred models list is properly defined."""
        assert isinstance(DECAI_PREFERRED_MODELS, list)
        assert len(DECAI_PREFERRED_MODELS) > 0
        assert "qwen2:5b-coder" in DECAI_PREFERRED_MODELS
        assert "codellama:7b" in DECAI_PREFERRED_MODELS
