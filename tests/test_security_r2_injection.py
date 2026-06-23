# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Security tests: r2 command injection via crafted function names.

Function names come from the analyzed (untrusted) binary via `aflj`. radare2
treats ';' and newlines as command separators and '!' as a shell escape, so a
crafted name like ``foo;!touch /tmp/pwn`` must never reach an r2 command
string. These tests exercise the real validation helper and the decompiler
helpers that consume it, using a recording fake r2 client (no mocks).
"""

from __future__ import annotations

import pytest

from bannedfuncdetector.infrastructure.decompilers.decompiler_support import (
    get_function_info,
    is_safe_r2_name,
    try_decompile_with_command,
)


class _RecordingR2:
    """Records every command sent to r2 so we can assert nothing dangerous ran."""

    def __init__(self) -> None:
        self.commands: list[str] = []

    def cmd(self, command: str) -> str:
        self.commands.append(command)
        return ""

    def cmdj(self, command: str):
        self.commands.append(command)
        return None


SAFE_NAMES = [
    "main",
    "sym.imp.strcpy",
    "fcn.00401000",
    "sub.bytes_4012a0",
    "loc.foo",
    "sym.std::vector",
    "entry0",
    "0x401000",
]

INJECTION_NAMES = [
    "foo;!touch /tmp/pwn",
    "foo\n!id",
    "foo;i~system",
    "`id`",
    "foo|!sh",
    "foo > /tmp/x",
    "$(id)",
    "foo && rm -rf /",
    "foo @ 0;!id",
    "",
]


@pytest.mark.parametrize("name", SAFE_NAMES)
def test_legitimate_r2_names_are_accepted(name: str) -> None:
    assert is_safe_r2_name(name) is True


@pytest.mark.parametrize("name", INJECTION_NAMES)
def test_injection_names_are_rejected(name: str) -> None:
    assert is_safe_r2_name(name) is False


@pytest.mark.parametrize("name", INJECTION_NAMES)
def test_try_decompile_refuses_unsafe_name(name: str) -> None:
    r2 = _RecordingR2()
    result = try_decompile_with_command(r2, "pdc", name)
    assert result is None
    # The dangerous name was never interpolated into any r2 command.
    assert all(name not in command for command in r2.commands)
    assert r2.commands == []


@pytest.mark.parametrize("name", INJECTION_NAMES)
def test_get_function_info_refuses_unsafe_name(name: str) -> None:
    r2 = _RecordingR2()
    result = get_function_info(r2, name)
    assert result is None
    assert r2.commands == []


def test_safe_name_still_reaches_r2() -> None:
    """A legitimate name is still seeked normally (no over-blocking)."""
    r2 = _RecordingR2()
    try_decompile_with_command(r2, "pdc", "sym.imp.strcpy")
    assert "s sym.imp.strcpy" in r2.commands


def test_get_function_offset_refuses_unsafe_name_fallback() -> None:
    """When function_info lacks an offset, the name-seek fallback must still
    refuse an unsafe name instead of seeking it."""
    from bannedfuncdetector.infrastructure.decompilers.decompiler_support import (
        _get_function_offset,
    )

    r2 = _RecordingR2()
    # function_info has no 'offset'/'addr', forcing the name-seek fallback path.
    result = _get_function_offset(r2, "foo;!id", {"name": "foo;!id"})
    assert result is None
    assert r2.commands == []


def test_default_cascade_asm_fallback_refuses_unsafe_name() -> None:
    """The assembly fallback in the default cascade must refuse unsafe names."""
    from bannedfuncdetector.domain.result import Err
    from bannedfuncdetector.infrastructure.decompilers.cascade import (
        _decompile_with_default_cascade,
    )

    r2 = _RecordingR2()
    result = _decompile_with_default_cascade(
        r2, "foo;!id", clean_error_messages=True, options={"fallback_to_asm": True}
    )
    assert isinstance(result, Err)
    assert all("foo;!id" not in command for command in r2.commands)


class TestSanitizeR2QueryText:
    """sanitize_r2_query_text neutralizes injection in `decai -q` query text."""

    def test_newlines_are_flattened(self) -> None:
        from bannedfuncdetector.infrastructure.decompilers.decompiler_support import (
            sanitize_r2_query_text,
        )

        out = sanitize_r2_query_text("line1\nline2\r\nline3")
        assert "\n" not in out and "\r" not in out
        assert out == "line1 line2 line3"

    def test_r2_and_shell_metacharacters_are_removed(self) -> None:
        from bannedfuncdetector.infrastructure.decompilers.decompiler_support import (
            sanitize_r2_query_text,
        )

        payload = "mov eax, 1\n!touch /tmp/pwn; i~system | `id` $(whoami) > /tmp/x"
        out = sanitize_r2_query_text(payload)

        for forbidden in "\n\r;@~|`'\"!$><(){}#&":
            assert forbidden not in out

    def test_query_is_safe_to_embed_in_decai_command(self) -> None:
        """The exact command built in _try_decai_decompilation is single-line
        and quote-safe for any disassembly content."""
        from bannedfuncdetector.infrastructure.decompilers.decompiler_support import (
            sanitize_r2_query_text,
        )

        malicious_asm = "push rbp\n'; !id #\nmov rax, `whoami`"
        query = sanitize_r2_query_text(
            f"Decompile this assembly code to C: {malicious_asm}"
        )
        command = f"decai -q '{query}'"

        # Single r2pipe command (no embedded newline) and the wrapping quotes
        # cannot be broken (no inner single quote survives).
        assert "\n" not in command
        assert command.count("'") == 2
        assert command.startswith("decai -q '") and command.endswith("'")

    def test_legitimate_asm_text_is_preserved(self) -> None:
        from bannedfuncdetector.infrastructure.decompilers.decompiler_support import (
            sanitize_r2_query_text,
        )

        out = sanitize_r2_query_text("mov eax, dword [rbp-0x8]")
        # Operand punctuation that is not r2-special stays intact.
        assert out == "mov eax, dword [rbp-0x8]"
