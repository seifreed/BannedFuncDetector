import bannedfuncdetector.infrastructure.decompilers.base_decompiler as decompilers
import bannedfuncdetector.infrastructure.decompilers.base_decompiler as decompiler_base
import bannedfuncdetector.infrastructure.decompilers.orchestrator as decompiler_orchestrator

# decompiler_registry was merged into decompiler_orchestrator
import bannedfuncdetector.infrastructure.decompilers.orchestrator as decompiler_registry
from bannedfuncdetector.infrastructure.config_repository import DEFAULT_CONFIG
from bannedfuncdetector.factories import create_config_from_dict
from bannedfuncdetector.domain import FunctionDescriptor
from bannedfuncdetector.application.dto_mappers import function_descriptor_from_dto
from conftest import FakeR2, open_r2pipe_with_retry


def make_config():
    return create_config_from_dict(DEFAULT_CONFIG)


def make_function(
    name: str = "f", offset: int = 1, size: int = 100
) -> FunctionDescriptor:
    return function_descriptor_from_dto({"name": name, "offset": offset, "size": size})


def test_check_decompiler_available_variants():
    assert (
        decompiler_registry.check_decompiler_available("default", print_message=False)
        is True
    )
    assert (
        decompiler_registry.check_decompiler_available("r2ai", print_message=False)
        is False
    )
    assert (
        decompiler_registry.check_decompiler_available("unknown", print_message=False)
        is False
    )
    # r2ghidra/r2dec availability depends on local installation; just ensure it returns bool
    assert isinstance(
        decompiler_registry.check_decompiler_available("r2ghidra", print_message=False),
        bool,
    )
    assert isinstance(
        decompiler_registry.check_decompiler_available("r2dec", print_message=False),
        bool,
    )


def test_check_decompiler_available_messages():
    """Test check_decompiler_available with print_message=True for types that don't need r2."""
    # These types don't open r2pipe, so we can test them directly
    assert (
        decompiler_registry.check_decompiler_available("r2ai", print_message=True)
        is False
    )
    assert (
        decompiler_registry.check_decompiler_available("default", print_message=True)
        is True
    )
    assert (
        decompiler_registry.check_decompiler_available("unknown", print_message=True)
        is False
    )


def test_check_decompiler_available_r2ghidra_returns_bool():
    """Test that r2ghidra availability check returns a bool (actual result depends on installation)."""
    result = decompiler_registry.check_decompiler_available(
        "r2ghidra", print_message=False
    )
    assert isinstance(result, bool)


def test_check_decompiler_available_r2ghidra_print_returns_bool():
    """Test that r2ghidra availability check with print_message returns a bool."""
    result = decompiler_registry.check_decompiler_available(
        "r2ghidra", print_message=True
    )
    assert isinstance(result, bool)


def test_check_decompiler_available_r2dec_returns_bool():
    """Test that r2dec availability check returns a bool (actual result depends on installation)."""
    result = decompiler_registry.check_decompiler_available(
        "r2dec", print_message=False
    )
    assert isinstance(result, bool)


def test_check_decompiler_available_r2dec_print_returns_bool():
    """Test that r2dec availability check with print_message returns a bool."""
    result = decompiler_registry.check_decompiler_available("r2dec", print_message=True)
    assert isinstance(result, bool)


def test_check_decompiler_plugin_available_default():
    """Default decompiler is always available without needing r2."""
    assert decompiler_base.check_decompiler_plugin_available("default") is True


def test_check_decompiler_plugin_available_r2ai():
    """r2ai is flagged as not_decompiler, so it's never available."""
    assert decompiler_base.check_decompiler_plugin_available("r2ai") is False


def test_check_decompiler_plugin_available_unknown():
    """Unknown decompiler types return False."""
    assert decompiler_base.check_decompiler_plugin_available("unknown") is False


def test_decompile_function_r2ghidra_cleaned_output():
    config = create_config_from_dict(
        {
            "decompiler": {
                "options": {
                    "max_retries": 1,
                    "ignore_unknown_branches": True,
                    "fallback_to_asm": True,
                    "clean_error_messages": True,
                    "use_alternative_decompiler": True,
                }
            }
        }
    )
    fake = FakeR2(
        cmd_map={
            "s func": "",
            "pdg": "warning: bad\nint abcdefghij;\n",
            "pdd": "int b;\n",
        }
    )
    result = decompiler_orchestrator.decompile_function(
        fake, "func", decompiler_type="r2ghidra", config=config
    )
    assert result.is_ok()
    decompiled = result.unwrap()
    assert "warning" not in decompiled
    assert "int a" in decompiled


def test_decompile_function_r2dec_fallback():
    fake = FakeR2(cmd_map={"s func": "", "pdd": "", "pdg": "int alt(){ return 1; }"})
    result = decompiler_orchestrator.decompile_function(
        fake, "func", decompiler_type="r2dec", config=make_config()
    )
    assert result.is_ok()
    assert "int alt" in result.unwrap()


def test_decompile_function_default_no_fallback_to_asm():
    config = create_config_from_dict(
        {"decompiler": {"options": {"fallback_to_asm": False}}}
    )
    fake = FakeR2(cmd_map={"s func": "", "pdg": "", "pdd": "", "pdc": ""})
    result = decompiler_orchestrator.decompile_function(
        fake, "func", decompiler_type="default", config=config
    )
    assert result.is_err()
    assert "Could not decompile function" in result.error


def test_decompile_function_clean_error_messages_false():
    config = create_config_from_dict(
        {"decompiler": {"options": {"clean_error_messages": False}}}
    )
    fake = FakeR2(cmd_map={"s func": "", "pdg": "warning: bad\nint abcdefghij;\n"})
    result = decompiler_orchestrator.decompile_function(
        fake, "func", decompiler_type="r2ghidra", config=config
    )
    assert result.is_ok()
    assert "warning" in result.unwrap()


def test_decompile_function_default_fallback_to_asm(compiled_binary):
    r2 = open_r2pipe_with_retry(compiled_binary, flags=["-2"])
    try:
        # Analysis is required to identify the "main" function
        r2.cmd("aa")
        result = decompiler_orchestrator.decompile_function(
            r2, "main", decompiler_type="default", config=make_config()
        )
        assert result.is_ok()
        assert isinstance(result.unwrap(), str)
    finally:
        r2.quit()


def test_decompile_function_unknown_type():
    fake = FakeR2(cmd_map={"s func": "", "pdc": "int main(){}"})
    result = decompiler_orchestrator.decompile_function(
        fake, "func", decompiler_type="unknown", config=make_config()
    )
    assert result.is_ok()
    assert "int main" in result.unwrap()


def test_decompile_with_selected_decompiler(compiled_binary):
    r2 = open_r2pipe_with_retry(compiled_binary, flags=["-2"])
    try:
        r2.cmd("aaa")
        functions = [function_descriptor_from_dto(func) for func in r2.cmdj("aflj")]
        results = decompiler_orchestrator.decompile_with_selected_decompiler(
            r2,
            functions,
            verbose=False,
            decompiler_type="r2ghidra",
            config=make_config(),
        )
        assert isinstance(results, list)
    finally:
        r2.quit()


def test_decompile_with_selected_decompiler_alternative():
    """Test decompilation with alternative decompiler using FakeR2 that returns banned function code."""
    # FakeR2 configured so that decompile_function returns code containing strcpy
    # The "default" decompiler type uses pdc command
    fake = FakeR2(
        cmd_map={
            "s f": "",
            "s *": "",
            "pdg": "",
            "pdd": "strcpy(dest, src); int abcdefghij_padding;",
            "pdc": "strcpy(dest, src); int abcdefghij_padding;",
        }
    )
    functions = [make_function()]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(
        fake, functions, verbose=True, decompiler_type="default", config=make_config()
    )
    assert result and result[0].detection_method == "decompilation"


def test_decompile_with_selected_decompiler_no_alternative():
    """Test decompilation when no alternative decompiler is available, using default pdc."""
    fake = FakeR2(
        cmd_map={
            "s f": "",
            "s *": "",
            "pdc": "gets(buffer); int abcdefghij_padding_text;",
            "pdg": "",
            "pdd": "",
        }
    )
    functions = [make_function()]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(
        fake, functions, verbose=True, decompiler_type="default", config=make_config()
    )
    assert result and result[0].detection_method == "decompilation"


def test_decompile_with_selected_decompiler_skip_small():
    fake = FakeR2()
    config = create_config_from_dict(
        {"skip_small_functions": True, "small_function_threshold": 200}
    )
    functions = [make_function(size=10)]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(
        fake, functions, verbose=False, decompiler_type="default", config=config
    )
    assert result == []


def test_decompile_with_selected_decompiler_invalid_text():
    """Test decompilation when decompiler returns empty/invalid text via FakeR2."""
    fake = FakeR2(
        cmd_map={
            "s f": "",
            "s *": "",
            "pdg": "",
            "pdd": "",
            "pdc": "",
            "s": "0x0",
            "pdf": "",
        }
    )
    config = create_config_from_dict(
        {"decompiler": {"options": {"fallback_to_asm": False}}}
    )
    functions = [make_function()]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(
        fake, functions, verbose=False, decompiler_type="default", config=config
    )
    assert result == []


def test_decompile_with_selected_decompiler_empty_functions():
    fake = FakeR2()
    result = decompiler_orchestrator.decompile_with_selected_decompiler(
        fake, [], verbose=True, decompiler_type="default", config=make_config()
    )
    assert result == []


def test_decompile_with_selected_decompiler_non_string():
    """Test decompilation when decompiler returns empty output for all commands."""
    fake = FakeR2(
        cmd_map={
            "s f": "",
            "s *": "",
            "pdg": "",
            "pdd": "",
            "pdc": "",
            "s": "0x0",
            "pdf": "",
        }
    )
    config = create_config_from_dict(
        {"decompiler": {"options": {"fallback_to_asm": False}}}
    )
    functions = [make_function()]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(
        fake, functions, verbose=True, decompiler_type="default", config=config
    )
    assert result == []


def test_decompile_with_selected_decompiler_error():
    """Test decompilation when FakeR2 raises an exception for all commands."""

    class ErrorR2(FakeR2):
        def cmd(self, command):
            raise RuntimeError("boom")

    fake = ErrorR2()
    functions = [make_function()]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(
        fake, functions, verbose=True, decompiler_type="default", config=make_config()
    )
    assert result == []


def test_get_function_info(compiled_binary):
    r2 = open_r2pipe_with_retry(compiled_binary, flags=["-2"])
    try:
        r2.cmd("aaa")
        info = decompilers.get_function_info(r2, "main")
        assert isinstance(info, dict)
        missing = decompilers.get_function_info(r2, "does_not_exist")
        assert missing is None or missing == {}
    finally:
        r2.quit()


def test_get_function_info_list_and_dict():
    fake = FakeR2(
        cmdj_map={"afij @ func": [{"offset": 1}], "afij @ dict": {"offset": 2}}
    )
    assert decompilers.get_function_info(fake, "func")["offset"] == 1
    assert decompilers.get_function_info(fake, "dict")["offset"] == 2


def test_get_function_info_unexpected_type():
    fake = FakeR2(cmdj_map={"afij @ weird": "nope"})
    assert decompilers.get_function_info(fake, "weird") is None


def test_get_function_info_exception():
    class ErrorR2(FakeR2):
        def cmdj(self, _command):
            raise RuntimeError("boom")

    fake = ErrorR2()
    assert decompilers.get_function_info(fake, "func") is None


def test_decompile_function_r2ghidra_alternative():
    fake = FakeR2(cmd_map={"s func": "", "pdg": "", "pdd": "int alt(){ return 1; }"})
    result = decompiler_orchestrator.decompile_function(
        fake, "func", decompiler_type="r2ghidra", config=make_config()
    )
    assert result.is_ok()
    assert "int alt" in result.unwrap()


def test_decompile_function_with_r2ai():
    fake = FakeR2(cmd_map={"s func": "", "pdc": "int main(){ return 0; }"})
    result = decompiler_orchestrator.decompile_function(
        fake, "func", decompiler_type="r2ai", config=make_config()
    )
    assert result.is_ok()
    assert "int main" in result.unwrap()


def test_decompile_function_try_command_exception():
    class ErrorR2(FakeR2):
        def cmd(self, command):
            if command == "pdg":
                raise RuntimeError("boom")
            return super().cmd(command)

    fake = ErrorR2(cmd_map={"s func": ""})
    result = decompiler_orchestrator.decompile_function(
        fake, "func", decompiler_type="r2ghidra", config=make_config()
    )
    # When decompilation fails, returns an error result
    assert result.is_err()


def test_decompile_function_default_uses_cascade():
    """Test default decompiler cascade: tries decompilers in order, falls back to asm."""
    # pdc (default) returns valid output, so cascade should succeed with it
    fake = FakeR2(
        cmd_map={
            "s func": "",
            "pdg": "",
            "pdd": "",
            "pdc": "int alt(){ return 0; }",
        }
    )
    result = decompiler_orchestrator.decompile_function(
        fake, "func", decompiler_type="default", config=make_config()
    )
    assert result.is_ok()
    assert "int alt" in result.unwrap()


def test_decompile_function_exception():
    class ErrorR2(FakeR2):
        def cmd(self, _command):
            raise RuntimeError("boom")

    fake = ErrorR2()
    result = decompiler_orchestrator.decompile_function(
        fake, "func", decompiler_type="default", config=make_config()
    )
    assert result.is_err()
    assert "decompiling" in result.error.lower() or "error" in result.error.lower()


def test_decompile_with_selected_decompiler_detects_insecure():
    """Test that real decompile_with_selected_decompiler detects banned functions via FakeR2."""
    fake = FakeR2(
        cmd_map={
            "s f": "",
            "s *": "",
            "pdc": "strcpy(dest, src); int abcdefghij_padding;",
            "pdg": "",
            "pdd": "",
        }
    )
    functions = [make_function()]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(
        fake, functions, verbose=True, decompiler_type="default", config=make_config()
    )
    assert result and result[0].detection_method == "decompilation"


def test_decompile_with_selected_decompiler_no_banned_found():
    """Test decompilation of code that contains no banned functions returns empty list."""
    fake = FakeR2(
        cmd_map={
            "s f": "",
            "s *": "",
            "pdc": "int safe_function(int x) { return x + 1; }",
            "pdg": "",
            "pdd": "",
        }
    )
    functions = [make_function()]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(
        fake, functions, verbose=True, decompiler_type="default", config=make_config()
    )
    assert result == []


def test_get_function_info_empty_list():
    fake = FakeR2(cmdj_map={"afij @ func": []})
    assert decompilers.get_function_info(fake, "func") is None


def test_decompile_function_decompiler_type_none():
    config = create_config_from_dict({"decompiler": {"type": "default"}})
    fake = FakeR2(cmd_map={"s func": "", "pdc": "int main(){ return 0; }"})
    result = decompiler_orchestrator.decompile_function(
        fake, "func", decompiler_type=None, config=config
    )
    assert result.is_ok()
    assert "int main" in result.unwrap()


def test_decompile_with_selected_decompiler_type_none():
    """Test decompile_with_selected_decompiler with decompiler_type=None uses config default."""
    fake = FakeR2(
        cmd_map={
            "s f": "",
            "s *": "",
            "pdc": "sprintf(buf, fmt); int abcdefghij_padding;",
            "pdg": "",
            "pdd": "",
        }
    )
    result = decompiler_orchestrator.decompile_with_selected_decompiler(
        fake,
        [make_function()],
        verbose=False,
        decompiler_type=None,
        config=make_config(),
    )
    assert result and result[0].detection_method == "decompilation"


def test_fake_r2_cmdj_callable():
    fake = FakeR2(cmdj_map={"x": lambda: {"ok": True}})
    assert fake.cmdj("x")["ok"] is True
