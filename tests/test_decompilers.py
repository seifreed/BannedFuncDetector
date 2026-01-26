import r2pipe

import bannedfuncdetector.infrastructure.decompilers.base_decompiler as decompilers
import bannedfuncdetector.infrastructure.decompilers.base_decompiler as decompiler_base
import bannedfuncdetector.infrastructure.decompilers.orchestrator as decompiler_orchestrator
# decompiler_registry was merged into decompiler_orchestrator
import bannedfuncdetector.infrastructure.decompilers.orchestrator as decompiler_registry
import bannedfuncdetector.infrastructure.decompilers.cascade as decompiler_cascade
from bannedfuncdetector.infrastructure.config_repository import CONFIG
from bannedfuncdetector.domain.result import ok, err
from conftest import FakeR2


def test_check_decompiler_available_variants():
    assert decompiler_registry.check_decompiler_available("default", print_message=False) is True
    assert decompiler_registry.check_decompiler_available("r2ai", print_message=False) is False
    assert decompiler_registry.check_decompiler_available("unknown", print_message=False) is False
    # r2ghidra/r2dec availability depends on local installation; just ensure it returns bool
    assert isinstance(decompiler_registry.check_decompiler_available("r2ghidra", print_message=False), bool)
    assert isinstance(decompiler_registry.check_decompiler_available("r2dec", print_message=False), bool)


def test_check_decompiler_available_messages(monkeypatch):
    class DummyR2:
        def cmd(self, _):
            return ""
        def quit(self):
            return None
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(decompiler_base.R2Client, "open", lambda *_args, **_kwargs: DummyR2())
    assert decompiler_registry.check_decompiler_available("r2ghidra", print_message=True) is False
    assert decompiler_registry.check_decompiler_available("r2dec", print_message=True) is False
    assert decompiler_registry.check_decompiler_available("r2ai", print_message=True) is False
    assert decompiler_registry.check_decompiler_available("default", print_message=True) is True
    assert decompiler_registry.check_decompiler_available("unknown", print_message=True) is False


def test_check_decompiler_available_r2ghidra_available(monkeypatch):
    class DummyR2:
        def cmd(self, _):
            return "r2ghidra"
        def quit(self):
            return None
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(decompiler_base.R2Client, "open", lambda *_args, **_kwargs: DummyR2())
    assert decompiler_registry.check_decompiler_available("r2ghidra", print_message=False) is True


def test_check_decompiler_available_r2ghidra_available_print(monkeypatch):
    class DummyR2:
        def cmd(self, _):
            return "r2ghidra"
        def quit(self):
            return None
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(decompiler_base.R2Client, "open", lambda *_args, **_kwargs: DummyR2())
    assert decompiler_registry.check_decompiler_available("r2ghidra", print_message=True) is True


def test_check_decompiler_available_r2dec_available(monkeypatch):
    class DummyR2:
        def cmd(self, _):
            return "pdd"
        def quit(self):
            return None
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(decompiler_base.R2Client, "open", lambda *_args, **_kwargs: DummyR2())
    assert decompiler_registry.check_decompiler_available("r2dec", print_message=False) is True


def test_check_decompiler_available_r2dec_available_print(monkeypatch):
    class DummyR2:
        def cmd(self, _):
            return "pdd"
        def quit(self):
            return None
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(decompiler_base.R2Client, "open", lambda *_args, **_kwargs: DummyR2())
    assert decompiler_registry.check_decompiler_available("r2dec", print_message=True) is True


def test_check_decompiler_available_exception(monkeypatch):
    def raise_error(_):
        raise RuntimeError("boom")

    monkeypatch.setattr(decompiler_base.R2Client, "open", raise_error)
    assert decompiler_registry.check_decompiler_available("r2ghidra", print_message=False) is False
    assert decompiler_registry.check_decompiler_available("r2ghidra", print_message=True) is False


def test_decompile_function_r2ghidra_cleaned_output():
    original = CONFIG["decompiler"]["options"].copy()
    CONFIG["decompiler"]["options"].update(
        {
            "max_retries": 1,
            "ignore_unknown_branches": True,
            "fallback_to_asm": True,
            "clean_error_messages": True,
            "use_alternative_decompiler": True,
        }
    )
    fake = FakeR2(
        cmd_map={
            "s func": "",
            "pdg": "warning: bad\nint abcdefghij;\n",
            "pdd": "int b;\n",
        }
    )
    try:
        result = decompiler_orchestrator.decompile_function(fake, "func", decompiler_type="r2ghidra")
        assert result.is_ok()
        decompiled = result.unwrap()
        assert "warning" not in decompiled
        assert "int a" in decompiled
    finally:
        CONFIG["decompiler"]["options"] = original


def test_decompile_function_r2dec_fallback():
    fake = FakeR2(cmd_map={"s func": "", "pdd": "", "pdg": "int alt(){ return 1; }"})
    result = decompiler_orchestrator.decompile_function(fake, "func", decompiler_type="r2dec")
    assert result.is_ok()
    assert "int alt" in result.unwrap()


def test_decompile_function_default_no_fallback_to_asm(monkeypatch):
    # Modify the internal config to disable fallback_to_asm
    import bannedfuncdetector.infrastructure.config_repository as config_module
    original = config_module.CONFIG._config["decompiler"]["options"]["fallback_to_asm"]
    config_module.CONFIG._config["decompiler"]["options"]["fallback_to_asm"] = False
    fake = FakeR2(cmd_map={"s func": "", "pdg": "", "pdd": "", "pdc": ""})
    try:
        result = decompiler_orchestrator.decompile_function(fake, "func", decompiler_type="default")
        assert result.is_err()
        assert "Could not decompile function" in result.error
    finally:
        config_module.CONFIG._config["decompiler"]["options"]["fallback_to_asm"] = original


def test_decompile_function_clean_error_messages_false(monkeypatch):
    # Modify the internal config to disable clean_error_messages
    import bannedfuncdetector.infrastructure.config_repository as config_module
    original = config_module.CONFIG._config["decompiler"]["options"]["clean_error_messages"]
    config_module.CONFIG._config["decompiler"]["options"]["clean_error_messages"] = False
    fake = FakeR2(cmd_map={"s func": "", "pdg": "warning: bad\nint abcdefghij;\n"})
    try:
        result = decompiler_orchestrator.decompile_function(fake, "func", decompiler_type="r2ghidra")
        assert result.is_ok()
        assert "warning" in result.unwrap()
    finally:
        config_module.CONFIG._config["decompiler"]["options"]["clean_error_messages"] = original


def test_decompile_function_default_fallback_to_asm(compiled_binary):
    r2 = r2pipe.open(compiled_binary, flags=["-2"])
    try:
        # Analysis is required to identify the "main" function
        r2.cmd("aa")
        result = decompiler_orchestrator.decompile_function(r2, "main", decompiler_type="default")
        assert result.is_ok()
        assert isinstance(result.unwrap(), str)
    finally:
        r2.quit()


def test_decompile_function_unknown_type():
    fake = FakeR2(cmd_map={"s func": "", "pdc": "int main(){}"})
    result = decompiler_orchestrator.decompile_function(fake, "func", decompiler_type="unknown")
    assert result.is_ok()
    assert "int main" in result.unwrap()


def test_decompile_with_selected_decompiler(compiled_binary):
    r2 = r2pipe.open(compiled_binary, flags=["-2"])
    try:
        r2.cmd("aaa")
        functions = r2.cmdj("aflj")
        results = decompiler_orchestrator.decompile_with_selected_decompiler(
            r2, functions, verbose=False, decompiler_type="r2ghidra"
        )
        assert isinstance(results, list)
    finally:
        r2.quit()


def test_decompile_with_selected_decompiler_alternative(monkeypatch):
    fake = FakeR2(cmd_map={"s f": "", "pdd": "strcpy(dest, src);"})

    def fake_check(name, print_message=True):
        return name == "r2dec"

    monkeypatch.setattr(decompiler_orchestrator, "check_decompiler_available", fake_check)
    # Mock decompile_function to return code with a banned function (as Result)
    monkeypatch.setattr(decompiler_orchestrator, "decompile_function", lambda *_args, **_kwargs: ok("strcpy(dest, src);"))
    functions = [{"name": "f", "offset": 1, "size": 100}]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(fake, functions, verbose=True, decompiler_type="r2ghidra")
    assert result and result[0]["match_type"] == "decompilation"


def test_decompile_with_selected_decompiler_no_alternative(monkeypatch):
    fake = FakeR2(cmd_map={"s f": "", "pdc": "gets(buffer);"})

    # Patch the actual modules where the functions are defined
    monkeypatch.setattr(decompiler_registry, "check_decompiler_available", lambda *_args, **_kwargs: False)
    # Mock decompile_function to return code with a banned function (as Result)
    monkeypatch.setattr(decompiler_orchestrator, "decompile_function", lambda *_args, **_kwargs: ok("gets(buffer);"))
    functions = [{"name": "f", "offset": 1, "size": 100}]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(fake, functions, verbose=True, decompiler_type="r2ghidra")
    assert result and result[0]["match_type"] == "decompilation"


def test_decompile_with_selected_decompiler_skip_small(monkeypatch):
    fake = FakeR2()
    # Modify the internal config to set skip_small_functions and threshold
    import bannedfuncdetector.infrastructure.config_repository as config_module
    original_skip = config_module.CONFIG._config.get("skip_small_functions", True)
    original_threshold = config_module.CONFIG._config.get("small_function_threshold", 20)
    config_module.CONFIG._config["skip_small_functions"] = True
    config_module.CONFIG._config["small_function_threshold"] = 200
    try:
        functions = [{"name": "f", "offset": 1, "size": 10}]
        result = decompiler_orchestrator.decompile_with_selected_decompiler(fake, functions, verbose=False, decompiler_type="default")
        assert result == []
    finally:
        config_module.CONFIG._config["skip_small_functions"] = original_skip
        config_module.CONFIG._config["small_function_threshold"] = original_threshold


def test_decompile_with_selected_decompiler_invalid_text(monkeypatch):
    fake = FakeR2()
    monkeypatch.setattr(decompiler_orchestrator, "check_decompiler_available", lambda *_args, **_kwargs: True)
    # Return an error result when decompilation fails
    monkeypatch.setattr(decompiler_orchestrator, "decompile_function", lambda *_args, **_kwargs: err("Decompilation failed"))
    functions = [{"name": "f", "offset": 1, "size": 100}]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(fake, functions, verbose=False, decompiler_type="default")
    assert result == []


def test_decompile_with_selected_decompiler_empty_functions():
    fake = FakeR2()
    result = decompiler_orchestrator.decompile_with_selected_decompiler(fake, [], verbose=True, decompiler_type="default")
    assert result == []


def test_decompile_with_selected_decompiler_non_string(monkeypatch):
    fake = FakeR2()
    monkeypatch.setattr(decompiler_orchestrator, "check_decompiler_available", lambda *_args, **_kwargs: True)
    # Return an empty result (decompilation returned nothing usable)
    monkeypatch.setattr(decompiler_orchestrator, "decompile_function", lambda *_args, **_kwargs: ok(""))
    functions = [{"name": "f", "offset": 1, "size": 100}]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(fake, functions, verbose=True, decompiler_type="default")
    assert result == []


def test_decompile_with_selected_decompiler_error(monkeypatch):
    fake = FakeR2()
    monkeypatch.setattr(decompiler_orchestrator, "check_decompiler_available", lambda *_args, **_kwargs: True)

    def boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(decompiler_orchestrator, "decompile_function", boom)
    functions = [{"name": "f", "offset": 1, "size": 100}]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(fake, functions, verbose=True, decompiler_type="default")
    assert result == []


def test_get_function_info(compiled_binary):
    r2 = r2pipe.open(compiled_binary, flags=["-2"])
    try:
        r2.cmd("aaa")
        info = decompilers.get_function_info(r2, "main")
        assert isinstance(info, dict)
        missing = decompilers.get_function_info(r2, "does_not_exist")
        assert missing is None or missing == {}
    finally:
        r2.quit()


def test_get_function_info_list_and_dict():
    fake = FakeR2(cmdj_map={"afij @ func": [{"offset": 1}], "afij @ dict": {"offset": 2}})
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
    result = decompiler_orchestrator.decompile_function(fake, "func", decompiler_type="r2ghidra")
    assert result.is_ok()
    assert "int alt" in result.unwrap()


def test_decompile_function_with_r2ai(monkeypatch):
    fake = FakeR2(cmd_map={"s func": "", "pdc": "int main(){ return 0; }"})
    result = decompiler_orchestrator.decompile_function(fake, "func", decompiler_type="r2ai")
    assert result.is_ok()
    assert "int main" in result.unwrap()


def test_decompile_function_try_command_exception():
    class ErrorR2(FakeR2):
        def cmd(self, command):
            if command == "pdg":
                raise RuntimeError("boom")
            return super().cmd(command)

    fake = ErrorR2(cmd_map={"s func": ""})
    result = decompiler_orchestrator.decompile_function(fake, "func", decompiler_type="r2ghidra")
    # When decompilation fails, returns an error result
    assert result.is_err()


def test_decompile_function_default_uses_r2ghidra(monkeypatch):
    fake = FakeR2(cmd_map={"s func": "", "pdg": "int alt(){ return 0; }"})

    def fake_check(name):
        # check_decompiler_plugin_available takes only the name argument
        return name == "r2ghidra"

    # The cascade module uses check_decompiler_plugin_available from base_decompiler
    monkeypatch.setattr(decompiler_cascade, "check_decompiler_plugin_available", fake_check)
    result = decompiler_orchestrator.decompile_function(fake, "func", decompiler_type="default")
    assert result.is_ok()
    assert "int alt" in result.unwrap()


def test_decompile_function_exception():
    class ErrorR2(FakeR2):
        def cmd(self, _command):
            raise RuntimeError("boom")

    fake = ErrorR2()
    result = decompiler_orchestrator.decompile_function(fake, "func", decompiler_type="default")
    assert result.is_err()
    assert "decompiling" in result.error.lower()


def test_decompile_with_selected_decompiler_detects_insecure(monkeypatch):
    fake = FakeR2()
    # Patch the actual modules where the functions are defined
    monkeypatch.setattr(decompiler_registry, "check_decompiler_available", lambda *_args, **_kwargs: True)
    # Use a real banned function name (strcpy is in INSECURE_FUNCTIONS) - as Result
    monkeypatch.setattr(decompiler_orchestrator, "decompile_function", lambda *_args, **_kwargs: ok("strcpy(dest, src);"))
    functions = [{"name": "f", "offset": 1, "size": 100}]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(fake, functions, verbose=True, decompiler_type="default")
    assert result and result[0]["match_type"] == "decompilation"


def test_decompile_with_selected_decompiler_regex_error(monkeypatch):
    import re
    fake = FakeR2()
    monkeypatch.setattr(decompiler_orchestrator, "check_decompiler_available", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(decompiler_orchestrator, "decompile_function", lambda *_args, **_kwargs: ok("string("))

    def raise_search(*_args, **_kwargs):
        raise RuntimeError("boom")

    # Patch re.search in decompiler_orchestrator where it's actually used
    monkeypatch.setattr(re, "search", raise_search)
    functions = [{"name": "f", "offset": 1, "size": 100}]
    result = decompiler_orchestrator.decompile_with_selected_decompiler(fake, functions, verbose=True, decompiler_type="default")
    assert result == []


def test_get_function_info_empty_list():
    fake = FakeR2(cmdj_map={"afij @ func": []})
    assert decompilers.get_function_info(fake, "func") is None


def test_decompile_function_decompiler_type_none():
    original = CONFIG["decompiler"]["type"]
    CONFIG["decompiler"]["type"] = "default"
    try:
        fake = FakeR2(cmd_map={"s func": "", "pdc": "int main(){ return 0; }"})
        result = decompiler_orchestrator.decompile_function(fake, "func", decompiler_type=None)
        assert result.is_ok()
        assert "int main" in result.unwrap()
    finally:
        CONFIG["decompiler"]["type"] = original


def test_decompile_with_selected_decompiler_type_none(monkeypatch):
    fake = FakeR2()
    # Patch the actual modules where the functions are defined
    monkeypatch.setattr(decompiler_registry, "check_decompiler_available", lambda *_args, **_kwargs: True)
    # Use a real banned function name (sprintf is in INSECURE_FUNCTIONS) - as Result
    monkeypatch.setattr(decompiler_orchestrator, "decompile_function", lambda *_args, **_kwargs: ok("sprintf(buf, fmt);"))
    result = decompiler_orchestrator.decompile_with_selected_decompiler(fake, [{"name": "f", "offset": 1, "size": 100}], verbose=False, decompiler_type=None)
    assert result and result[0]["match_type"] == "decompilation"


def test_fake_r2_cmdj_callable():
    fake = FakeR2(cmdj_map={"x": lambda: {"ok": True}})
    assert fake.cmdj("x")["ok"] is True
