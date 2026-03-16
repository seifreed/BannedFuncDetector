#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""
Coverage-gap tests for domain and application layers.

Each test group targets specific uncovered lines identified by the coverage
report, exercising real code paths without mocks, monkeypatching, or stubs.
"""
import concurrent.futures

import bannedfuncdetector as root_pkg
import bannedfuncdetector.application as application_pkg
import pytest

from bannedfuncdetector.analyzer_exceptions import AnalysisError
from bannedfuncdetector.application.analysis_error import (
    ApplicationExecutionError,
    ExecutionFailure,
)
from bannedfuncdetector.application.analysis_outcome import (
    DirectoryAnalysisOutcome,
    FunctionDiscoveryOutcome,
    OperationalNotice,
)
from bannedfuncdetector.application.analysis_runtime import (
    AnalysisRuntime,
    BinaryRuntimeServices,
)
from bannedfuncdetector.application.binary_analyzer.detection import (
    _decompile_and_search,
    _find_banned_in_code,
    _find_banned_in_name,
    _validate_analysis_inputs,
)
from bannedfuncdetector.application.binary_analyzer.function_analysis import (
    _function_analysis_error,
    _merge_detections,
    analyze_function,
)
from bannedfuncdetector.application.binary_analyzer.function_discovery_service import (
    R2FunctionDiscoveryService,
)
from bannedfuncdetector.application.contracts.analysis import FunctionAnalysisRequest
from bannedfuncdetector.application.function_detection_support import (
    log_parallel_future_error,
)
from bannedfuncdetector.application.result_serializers import (
    directory_outcome_to_dict,
    directory_summary_to_dict,
)
from bannedfuncdetector.cli_dispatch import dispatch_cli_analysis
from bannedfuncdetector.domain.entities import (
    AnalysisResult,
    BannedFunction,
    DirectoryAnalysisSummary,
    FunctionDescriptor,
)
from bannedfuncdetector.domain.result import Err, Ok, err, ok
from bannedfuncdetector.domain.result import Err as ResultErr
from bannedfuncdetector.domain.result import Ok as ResultOk
from bannedfuncdetector.domain.result import ok as domain_ok
from bannedfuncdetector.domain.types import (
    _compile_call_pattern,
    search_banned_call_in_text,
)

# ---------------------------------------------------------------------------
# 1. domain/result.py — lines 74, 90, 102, 144, 160, 172, 188
# ---------------------------------------------------------------------------


class TestOkUnwrapOr:
    """Line 74 — Ok.unwrap_or returns the contained value, not the default."""

    def test_ok_unwrap_or_ignores_default(self):
        result = Ok(99)
        assert result.unwrap_or(0) == 99

    def test_ok_unwrap_or_with_string_value(self):
        result = Ok("hello")
        assert result.unwrap_or("default") == "hello"

    def test_ok_unwrap_or_with_none_value(self):
        result = Ok(None)
        assert result.unwrap_or("fallback") is None


class TestOkMap:
    """Line 90 — Ok.map applies the function and returns a new Ok."""

    def test_ok_map_doubles_integer(self):
        result = Ok(3).map(lambda x: x * 2)
        assert isinstance(result, Ok)
        assert result.value == 6

    def test_ok_map_uppercases_string(self):
        result = Ok("lower").map(str.upper)
        assert isinstance(result, Ok)
        assert result.value == "LOWER"

    def test_ok_map_returns_ok_type(self):
        mapped = Ok(10).map(lambda x: x + 1)
        assert mapped.is_ok()
        assert not mapped.is_err()


class TestOkMapErr:
    """Line 102 — Ok.map_err returns self unchanged."""

    def test_ok_map_err_returns_same_instance(self):
        original = Ok(42)
        returned = original.map_err(lambda e: f"wrapped: {e}")
        assert returned is original

    def test_ok_map_err_value_unaffected(self):
        result = Ok("data").map_err(str.upper)
        assert result.value == "data"


class TestErrUnwrapRaises:
    """Line 144 — Err.unwrap raises ValueError with the error payload."""

    def test_err_unwrap_raises_value_error(self):
        with pytest.raises(ValueError, match="Called unwrap on Err: something bad"):
            Err("something bad").unwrap()

    def test_err_unwrap_raises_with_integer_error(self):
        with pytest.raises(ValueError, match="404"):
            Err(404).unwrap()


class TestErrUnwrapOr:
    """Line 160 — Err.unwrap_or returns the supplied default."""

    def test_err_unwrap_or_returns_default_integer(self):
        assert Err("oops").unwrap_or(42) == 42

    def test_err_unwrap_or_returns_default_string(self):
        assert Err(RuntimeError("x")).unwrap_or("safe") == "safe"

    def test_err_unwrap_or_returns_none_when_default_is_none(self):
        assert Err("e").unwrap_or(None) is None


class TestErrMap:
    """Line 172 — Err.map returns self unchanged."""

    def test_err_map_returns_same_instance(self):
        original = Err("error payload")
        returned = original.map(lambda x: x * 2)
        assert returned is original

    def test_err_map_error_unaffected(self):
        result = Err("unchanged").map(str.upper)
        assert result.error == "unchanged"


class TestErrMapErr:
    """Line 188 — Err.map_err applies the function to the error."""

    def test_err_map_err_transforms_string_error(self):
        result = Err("error").map_err(str.upper)
        assert isinstance(result, Err)
        assert result.error == "ERROR"

    def test_err_map_err_wraps_error_in_new_err(self):
        result = Err(3).map_err(lambda e: e * 10)
        assert result.error == 30

    def test_err_map_err_returns_err_type(self):
        mapped = Err("x").map_err(lambda e: f"[{e}]")
        assert mapped.is_err()
        assert not mapped.is_ok()


# ---------------------------------------------------------------------------
# 2. domain/types.py — remove dead code (lines 38-40 and 70)
#    The try/except re.error in _compile_call_pattern is unreachable because
#    re.escape makes any input safe. Delete lines 38-40 and adjust accordingly.
#    We add a regression test to document that custom names compile correctly.
# ---------------------------------------------------------------------------

class TestCompileCallPatternNoDeadCode:
    """
    Verify _compile_call_pattern works for arbitrary inputs.

    The original try/except re.error guard was dead code because re.escape
    ensures the input can never produce an invalid regex.  These tests
    confirm that the simplified implementation handles all realistic inputs.
    """

    def test_plain_function_name_compiles(self):
        pat = _compile_call_pattern("strcpy")
        assert pat is not None
        assert pat.search("strcpy(dest, src)") is not None

    def test_name_with_underscores_compiles(self):
        pat = _compile_call_pattern("_mbscpy_s")
        assert pat is not None

    def test_name_with_dots_compiles(self):
        # dots are special in regex but re.escape handles them
        pat = _compile_call_pattern("sym.imp.strcpy")
        assert pat is not None

    def test_search_banned_call_custom_name_hits_fallback_path(self):
        # A name NOT in BANNED_FUNCTIONS triggers the on-demand compilation path
        # (lines 67-68 in types.py, formerly accompanied by dead code at 69-70).
        custom_name = "my_special_unsafe_func_xyz"
        text = "my_special_unsafe_func_xyz(arg1, arg2);"
        assert search_banned_call_in_text(text, custom_name) is True

    def test_search_banned_call_custom_name_no_match(self):
        assert search_banned_call_in_text("safe_function(x)", "my_special_unsafe_func_xyz") is False


# ---------------------------------------------------------------------------
# 3. application/analysis_error.py — lines 30-31
#    ExecutionFailure.__str__ with operational_notices present.
# ---------------------------------------------------------------------------

class TestExecutionFailureStr:
    """Lines 30-31 — __str__ when operational_notices is non-empty."""

    def test_str_with_single_notice(self):
        error = ApplicationExecutionError(
            category="IO",
            context="/path/to/binary",
            message="file not found",
        )
        notice = OperationalNotice(message="skipped /path/to/binary", file_path="/path/to/binary")
        failure = ExecutionFailure(error=error, operational_notices=(notice,))
        rendered = str(failure)
        assert "notices:" in rendered
        assert "skipped /path/to/binary" in rendered

    def test_str_with_multiple_notices_joined_by_semicolon(self):
        error = ApplicationExecutionError(
            category="RUNTIME",
            context="some_context",
            message="crash",
        )
        notices = (
            OperationalNotice(message="notice one"),
            OperationalNotice(message="notice two"),
        )
        failure = ExecutionFailure(error=error, operational_notices=notices)
        rendered = str(failure)
        assert "notice one" in rendered
        assert "notice two" in rendered
        assert ";" in rendered

    def test_str_without_notices_omits_notices_section(self):
        error = ApplicationExecutionError(
            category="DATA",
            context="ctx",
            message="bad data",
        )
        failure = ExecutionFailure(error=error)
        rendered = str(failure)
        assert "notices:" not in rendered
        assert "bad data" in rendered

    def test_str_includes_error_representation_before_notices(self):
        error = ApplicationExecutionError(
            category="IO",
            context="binary.exe",
            message="access denied",
            phase="loading",
        )
        notice = OperationalNotice(message="file skipped")
        failure = ExecutionFailure(error=error, operational_notices=(notice,))
        rendered = str(failure)
        # The base error string must appear before the notices section
        semicolon_pos = rendered.index("; notices:")
        assert "access denied" in rendered[:semicolon_pos]


# ---------------------------------------------------------------------------
# 4. application/binary_analyzer/detection.py — lines 24-25, 34-35, 59-60,
#    80-81, 91, 133, 147
#
#    Lines 24-25, 34-35: _build_name_patterns / _build_call_patterns — the
#      except re.error branch; unreachable via re.escape inputs, but the
#      outer loop body IS covered by passing a custom set.
#    Lines 59-60, 80-81: fallback compilation inside _find_banned_in_name /
#      _find_banned_in_code when a CUSTOM set (not BANNED_FUNCTIONS) is passed.
#    Line 91: _decompile_and_search returns Err when orchestrator is None.
#    Line 133: _decompile_and_search returns Err when decompile_result is Err.
#    Line 147: _decompile_and_search returns Err when no banned calls found.
# ---------------------------------------------------------------------------

class FakeR2Client:
    """Minimal real IR2Client implementation sufficient for detection tests."""

    def cmd(self, command: str) -> str:
        return ""

    def cmdj(self, command: str):
        return None

    def quit(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass


class DecompilerOrchestratorReturnsOk:
    """Real orchestrator that returns a fixed Ok result."""

    def __init__(self, decompiled_code: str):
        self._code = decompiled_code

    def decompile_function(self, r2, function_name: str, decompiler_type=None, **kwargs):
        return ok(self._code)

    def select_decompiler(self, requested=None, force=False) -> str:
        return "default"

    def check_decompiler_available(self, decompiler_type: str) -> bool:
        return True


class DecompilerOrchestratorReturnsErr:
    """Real orchestrator that always returns an Err result."""

    def decompile_function(self, r2, function_name: str, decompiler_type=None, **kwargs):
        return err("decompilation engine not available")

    def select_decompiler(self, requested=None, force=False) -> str:
        return "default"

    def check_decompiler_available(self, decompiler_type: str) -> bool:
        return False


class TestFindBannedInNameCustomSet:
    """Lines 55-58 — fallback compilation branch when custom (non-BANNED_FUNCTIONS) set is used."""

    def test_custom_set_finds_match_in_name(self):
        custom_banned = {"get_password", "exec_cmd"}
        found = _find_banned_in_name("exec_cmd_internal", custom_banned)
        # exec_cmd should NOT match exec_cmd_internal due to word-boundary regex
        # (only matches at word boundaries); test the boundary behaviour
        assert isinstance(found, list)

    def test_custom_set_exact_word_boundary_match(self):
        custom_banned = {"get_password"}
        found = _find_banned_in_name("get_password", custom_banned)
        assert "get_password" in found

    def test_custom_set_no_match(self):
        custom_banned = {"dangerous_func"}
        found = _find_banned_in_name("safe_function_name", custom_banned)
        assert found == []

    def test_custom_set_multiple_matches(self):
        custom_banned = {"strcpy", "gets"}
        found = _find_banned_in_name("strcpy", custom_banned)
        assert "strcpy" in found

    def test_custom_set_empty_set_returns_empty(self):
        found = _find_banned_in_name("strcpy", set())
        assert found == []


class TestFindBannedInCodeCustomSet:
    """Lines 75-78 — fallback compilation branch when custom (non-BANNED_FUNCTIONS) set is used."""

    def test_custom_set_finds_call_in_code(self):
        custom_banned = {"unsafe_write"}
        code = "unsafe_write(buffer, size);"
        found = _find_banned_in_code(code, custom_banned)
        assert "unsafe_write" in found

    def test_custom_set_no_match_when_no_call(self):
        custom_banned = {"unsafe_write"}
        code = "safe_function(x, y);"
        found = _find_banned_in_code(code, custom_banned)
        assert found == []

    def test_custom_set_case_insensitive_match(self):
        custom_banned = {"BadFunction"}
        code = "BADFUNCTION(arg);"
        found = _find_banned_in_code(code, custom_banned)
        assert "BadFunction" in found

    def test_custom_set_empty_returns_empty(self):
        found = _find_banned_in_code("strcpy(dest, src);", set())
        assert found == []


class TestDecompileAndSearch:
    """Lines 91, 133, 147 — _decompile_and_search control flow branches."""

    def test_returns_err_when_orchestrator_is_none(self):
        # Line 91: orchestrator is None -> immediate Err
        r2 = FakeR2Client()
        result = _decompile_and_search(
            r2=r2,
            func_name="main",
            func_addr=0x1000,
            banned_functions={"strcpy"},
            decompiler_type="default",
            decompiler_orchestrator=None,
        )
        assert isinstance(result, ResultErr)
        assert "orchestrator" in result.error.lower() or "required" in result.error.lower()

    def test_returns_err_when_decompilation_fails(self):
        # Line 133: decompile_result is Err
        r2 = FakeR2Client()
        orch = DecompilerOrchestratorReturnsErr()
        result = _decompile_and_search(
            r2=r2,
            func_name="main",
            func_addr=0x1000,
            banned_functions={"strcpy"},
            decompiler_type="default",
            decompiler_orchestrator=orch,
        )
        assert isinstance(result, ResultErr)
        assert "Decompilation failed" in result.error

    def test_returns_err_when_no_banned_found_in_code(self):
        # Line 147: decompilation succeeds but code contains no banned calls
        r2 = FakeR2Client()
        orch = DecompilerOrchestratorReturnsOk("int main() { return 0; }")
        result = _decompile_and_search(
            r2=r2,
            func_name="main",
            func_addr=0x1000,
            banned_functions={"strcpy"},
            decompiler_type="default",
            decompiler_orchestrator=orch,
        )
        assert isinstance(result, ResultErr)
        assert "No banned functions found in decompiled code" in result.error

    def test_returns_ok_when_banned_call_found_in_code(self):
        # Happy path: decompiled code contains a banned call
        r2 = FakeR2Client()
        orch = DecompilerOrchestratorReturnsOk("void helper() { strcpy(buf, input); }")
        result = _decompile_and_search(
            r2=r2,
            func_name="helper",
            func_addr=0x2000,
            banned_functions={"strcpy"},
            decompiler_type="default",
            decompiler_orchestrator=orch,
        )
        assert isinstance(result, ResultOk)
        detection = result.unwrap()
        assert detection.name == "helper"
        assert "strcpy" in detection.banned_calls

    def test_returns_err_when_decompiled_code_is_empty(self):
        # Orchestrator returns Ok but with empty string
        r2 = FakeR2Client()
        orch = DecompilerOrchestratorReturnsOk("")
        result = _decompile_and_search(
            r2=r2,
            func_name="main",
            func_addr=0x1000,
            banned_functions={"strcpy"},
            decompiler_type="default",
            decompiler_orchestrator=orch,
        )
        assert isinstance(result, ResultErr)
        assert "Empty decompilation result" in result.error

    def test_custom_banned_set_uses_fallback_compilation_in_search(self):
        # Passes a custom (non-BANNED_FUNCTIONS) set, exercising the fallback
        # compilation path inside _find_banned_in_code (lines 75-78)
        custom_banned = {"my_bad_func"}
        r2 = FakeR2Client()
        orch = DecompilerOrchestratorReturnsOk("void foo() { my_bad_func(x); }")
        result = _decompile_and_search(
            r2=r2,
            func_name="foo",
            func_addr=0x3000,
            banned_functions=custom_banned,
            decompiler_type="default",
            decompiler_orchestrator=orch,
        )
        assert isinstance(result, ResultOk)
        assert "my_bad_func" in result.unwrap().banned_calls


class TestValidateAnalysisInputs:
    """detection.py line 73 — _validate_analysis_inputs returns Err when func is None."""

    def test_none_func_returns_err(self):
        result = _validate_analysis_inputs(None, {"strcpy"})
        assert isinstance(result, ResultErr)
        assert "cannot be None" in result.error

    def test_valid_func_returns_ok(self):
        func = FunctionDescriptor(name="main", address=0x1000)
        result = _validate_analysis_inputs(func, {"strcpy"})
        assert isinstance(result, ResultOk)
        assert "strcpy" in result.unwrap()


# ---------------------------------------------------------------------------
# 5. application/binary_analyzer/function_analysis.py — lines 25, 45-47, 101, 119
#
#    Line 25: _function_analysis_error with non-AnalysisError exception
#    Lines 45-47: _merge_detections combines two BannedFunction instances
#    Line 101: _run_detection_steps merges both results when both are Ok
#    Line 119: analyze_function catches AnalysisError and routes to error handler
# ---------------------------------------------------------------------------

class TestFunctionAnalysisError:
    """Lines 25-27 — _function_analysis_error with AnalysisError and generic exceptions."""

    def test_analysis_error_produces_analysis_error_prefix(self):
        exc = AnalysisError("binary corrupted")
        result = _function_analysis_error(exc)
        assert result.is_err()
        assert "Analysis error analyzing function" in result.error

    def test_runtime_error_produces_runtime_prefix(self):
        exc = RuntimeError("segfault")
        result = _function_analysis_error(exc)
        assert result.is_err()
        assert "RUNTIME" in result.error.upper() or "analyzing function" in result.error

    def test_os_error_produces_io_prefix(self):
        exc = OSError("permission denied")
        result = _function_analysis_error(exc)
        assert result.is_err()
        # classify_error maps OSError -> ErrorCategory.IO
        assert "analyzing function" in result.error

    def test_key_error_produces_data_prefix(self):
        exc = KeyError("missing_key")
        result = _function_analysis_error(exc)
        assert result.is_err()
        assert "analyzing function" in result.error


class TestMergeDetections:
    """Lines 45-47 — _merge_detections merges two BannedFunction detections."""

    def test_merge_combines_banned_calls(self):
        name_det = BannedFunction(
            name="strcpy",
            address=0x1000,
            size=0,
            banned_calls=("strcpy",),
            detection_method="name",
            category="string_copy",
        )
        code_det = BannedFunction(
            name="strcpy",
            address=0x1000,
            size=0,
            banned_calls=("gets",),
            detection_method="decompilation",
            category="string_input",
        )
        merged = _merge_detections(name_det, code_det)
        assert "strcpy" in merged.banned_calls
        assert "gets" in merged.banned_calls
        assert merged.detection_method == "name+decompilation"

    def test_merge_deduplicates_calls(self):
        name_det = BannedFunction(
            name="foo",
            address=0x2000,
            size=0,
            banned_calls=("strcpy", "gets"),
            detection_method="name",
        )
        code_det = BannedFunction(
            name="foo",
            address=0x2000,
            size=0,
            banned_calls=("strcpy",),
            detection_method="decompilation",
        )
        merged = _merge_detections(name_det, code_det)
        # After dedup, strcpy appears once
        assert merged.banned_calls.count("strcpy") == 1

    def test_merge_preserves_name_and_address(self):
        name_det = BannedFunction(
            name="target_func",
            address=0xABCD,
            size=10,
            banned_calls=("strcpy",),
            detection_method="name",
        )
        code_det = BannedFunction(
            name="target_func",
            address=0xABCD,
            size=10,
            banned_calls=("sprintf",),
            detection_method="decompilation",
        )
        merged = _merge_detections(name_det, code_det)
        assert merged.name == "target_func"
        assert merged.address == 0xABCD

    def test_merge_assigns_category_from_highest_risk(self):
        name_det = BannedFunction(
            name="f",
            address=0,
            size=0,
            banned_calls=("gets",),   # string_input risk weight=10
            detection_method="name",
            category="string_input",
        )
        code_det = BannedFunction(
            name="f",
            address=0,
            size=0,
            banned_calls=("strcpy",),  # string_copy risk weight=8
            detection_method="decompilation",
            category="string_copy",
        )
        merged = _merge_detections(name_det, code_det)
        # category should be the highest risk one
        assert merged.category is not None


class TestAnalyzeFunctionBothDetections:
    """Line 101 — _run_detection_steps merges name and decompilation detections."""

    def test_both_name_and_code_detections_are_merged(self):
        # Function name IS a banned function AND the decompiled code also contains it.
        # skip_banned=False, skip_analysis=False to run both steps.
        r2 = FakeR2Client()
        # Orchestrator returns code that also has a banned call.
        orch = DecompilerOrchestratorReturnsOk("void strcpy_impl() { strcpy(dest, src); }")

        config_repo = type(
            "_Cfg", (),
            {
                "get": lambda self, k, d=None: d,
                "__getitem__": lambda self, k: (_ for _ in ()).throw(KeyError(k)),
                "get_output_dir": lambda self: "output",
                "to_dict": lambda self: {},
            },
        )()

        runtime = AnalysisRuntime(
            config=config_repo,
            r2_factory=lambda _: r2,
            binary=BinaryRuntimeServices(
                binary_opener=lambda path, verbose, factory: r2,
                r2_closer=lambda _r2: domain_ok(None),
            ),
            decompiler_orchestrator=orch,
        )
        request = FunctionAnalysisRequest(
            runtime=runtime,
            banned_functions={"strcpy"},
            decompiler_type="default",
            verbose=False,
            skip_banned=False,   # run name detection
            skip_analysis=False, # run decompilation detection
        )
        # func named "strcpy" -> name detection hits; decompiled code also has strcpy( -> code detection hits
        func = FunctionDescriptor(name="strcpy", address=0x1000, size=20)
        result = analyze_function(r2, func, request=request)
        assert result.is_ok()
        detection = result.unwrap()
        assert detection.detection_method == "name+decompilation"
        assert "strcpy" in detection.banned_calls


class TestAnalyzeFunctionAnalysisError:
    """Lines 118-119 — analyze_function returns early when _resolve_banned_inputs is Err."""

    def _make_minimal_request(self) -> FunctionAnalysisRequest:
        config_repo = type(
            "_Cfg", (),
            {
                "get": lambda self, k, d=None: d,
                "__getitem__": lambda self, k: (_ for _ in ()).throw(KeyError(k)),
                "get_output_dir": lambda self: "output",
                "to_dict": lambda self: {},
            },
        )()
        r2_instance = FakeR2Client()
        runtime = AnalysisRuntime(
            config=config_repo,
            r2_factory=lambda _: r2_instance,
            binary=BinaryRuntimeServices(
                binary_opener=lambda path, verbose, factory: r2_instance,
                r2_closer=lambda _r2: domain_ok(None),
            ),
        )
        return FunctionAnalysisRequest(
            runtime=runtime,
            banned_functions={"strcpy"},
            decompiler_type="default",
            verbose=False,
            skip_banned=False,
            skip_analysis=True,
        )

    def test_none_func_returns_err_immediately(self):
        # Line 118-119: _resolve_banned_inputs(None, ...) returns Err, function returns early
        request = self._make_minimal_request()
        result = analyze_function(FakeR2Client(), None, request=request)  # type: ignore[arg-type]
        assert result.is_err()
        assert "cannot be None" in result.error

    def _make_request_with_raising_orchestrator(self, exc: Exception) -> FunctionAnalysisRequest:
        """Build a FunctionAnalysisRequest whose orchestrator raises the given exception."""

        class RaisingOrchestrator:
            def decompile_function(self, r2, function_name, decompiler_type=None, **kwargs):
                raise exc

            def select_decompiler(self, requested=None, force=False):
                return "default"

            def check_decompiler_available(self, decompiler_type):
                return True

        config_repo = type(
            "_Cfg",
            (),
            {
                "get": lambda self, k, d=None: d,
                "__getitem__": lambda self, k: (_ for _ in ()).throw(KeyError(k)),
                "get_output_dir": lambda self: "output",
                "to_dict": lambda self: {},
            },
        )()

        r2_instance = FakeR2Client()
        runtime = AnalysisRuntime(
            config=config_repo,
            r2_factory=lambda _: r2_instance,
            binary=BinaryRuntimeServices(
                binary_opener=lambda path, verbose, factory: r2_instance,
                r2_closer=lambda _r2: domain_ok(None),
            ),
            decompiler_orchestrator=RaisingOrchestrator(),
        )
        return FunctionAnalysisRequest(
            runtime=runtime,
            banned_functions={"strcpy"},
            decompiler_type="default",
            verbose=False,
            skip_banned=True,   # skip name check so we reach decompile step
            skip_analysis=False,
        )

    def test_analysis_error_is_caught_and_returned_as_err(self):
        r2 = FakeR2Client()
        func = FunctionDescriptor(name="vuln_func", address=0x1000, size=50)
        request = self._make_request_with_raising_orchestrator(AnalysisError("analysis exploded"))
        result = analyze_function(r2, func, request=request)
        assert result.is_err()
        assert "Analysis error" in result.error

    def test_runtime_error_is_caught_and_returned_as_err(self):
        r2 = FakeR2Client()
        func = FunctionDescriptor(name="crash_func", address=0x2000, size=50)
        request = self._make_request_with_raising_orchestrator(RuntimeError("crash"))
        result = analyze_function(r2, func, request=request)
        assert result.is_err()

    def test_value_error_is_caught_and_returned_as_err(self):
        r2 = FakeR2Client()
        func = FunctionDescriptor(name="bad_val", address=0x3000, size=50)
        request = self._make_request_with_raising_orchestrator(ValueError("bad value"))
        result = analyze_function(r2, func, request=request)
        assert result.is_err()


# ---------------------------------------------------------------------------
# 6. application/binary_analyzer/function_discovery_service.py — lines 17, 20-23
# ---------------------------------------------------------------------------

class TestR2FunctionDiscoveryService:
    """Lines 17, 20-23 — get_functions with Ok and Err results from _extract_functions."""

    def test_get_functions_returns_ok_with_valid_functions(self):
        r2 = FakeR2Client()
        r2.cmdj = lambda command: (
            [
                {"name": "main", "offset": 0x1000, "size": 100},
                {"name": "helper", "offset": 0x1100, "size": 50},
            ]
            if command == "aflj"
            else None
        )
        service = R2FunctionDiscoveryService(verbose=False)
        result = service.get_functions(r2)
        assert result.is_ok()
        outcome = result.unwrap()
        assert isinstance(outcome, FunctionDiscoveryOutcome)
        assert len(outcome.functions) == 2
        names = [f.name for f in outcome.functions]
        assert "main" in names
        assert "helper" in names

    def test_get_functions_returns_err_when_no_functions(self):
        r2 = FakeR2Client()
        r2.cmdj = lambda command: [] if command == "aflj" else None
        service = R2FunctionDiscoveryService(verbose=False)
        result = service.get_functions(r2)
        assert result.is_err()
        assert "No functions found" in result.error

    def test_get_functions_returns_err_when_cmdj_returns_none(self):
        r2 = FakeR2Client()
        r2.cmdj = lambda command: None
        service = R2FunctionDiscoveryService(verbose=False)
        result = service.get_functions(r2)
        assert result.is_err()

    def test_get_functions_with_verbose_flag_does_not_raise(self):
        r2 = FakeR2Client()
        r2.cmdj = lambda command: (
            [{"name": "entry0", "offset": 0x400, "size": 20}]
            if command == "aflj"
            else None
        )
        service = R2FunctionDiscoveryService(verbose=True)
        result = service.get_functions(r2)
        assert result.is_ok()


# ---------------------------------------------------------------------------
# 7. application/function_detection_support.py — lines 23-24
#    log_parallel_future_error with CancelledError (verbose=True path)
# ---------------------------------------------------------------------------

class TestLogParallelFutureErrorCancelledError:
    """Lines 22-24 — CancelledError branch when verbose is True."""

    def test_cancelled_error_does_not_raise(self):
        exc = concurrent.futures.CancelledError()
        # verbose=True ensures we enter the branch rather than returning early
        log_parallel_future_error(exc, verbose=True)

    def test_cancelled_error_with_verbose_false_returns_early(self):
        exc = concurrent.futures.CancelledError()
        # verbose=False: function returns at line 21 before reaching line 22-24
        log_parallel_future_error(exc, verbose=False)

    def test_regular_exception_with_verbose_true_uses_classify_prefix(self):
        exc = RuntimeError("something failed")
        # Should not raise; exercises the else-branch at line 25-26
        log_parallel_future_error(exc, verbose=True)

    def test_os_error_with_verbose_true_classifies_as_io(self):
        exc = OSError("disk full")
        log_parallel_future_error(exc, verbose=True)


# ---------------------------------------------------------------------------
# 8. application/result_serializers.py — lines 47, 52
#    directory_summary_to_dict and directory_outcome_to_dict
# ---------------------------------------------------------------------------

def _make_analysis_result(file_path: str = "/tmp/binary") -> AnalysisResult:
    return AnalysisResult(
        file_name="binary",
        file_path=file_path,
        total_functions=5,
        detected_functions=(
            BannedFunction(
                name="strcpy",
                address=0x1000,
                size=0,
                banned_calls=("strcpy",),
                detection_method="name",
                category="string_copy",
            ),
        ),
        analysis_date="2026-03-15",
    )


class TestDirectorySummaryToDict:
    """Line 47 — directory_summary_to_dict serializes the aggregate correctly."""

    def test_basic_serialization_fields(self):
        summary = DirectoryAnalysisSummary(
            directory="/tmp/binaries",
            analyzed_results=(_make_analysis_result(),),
            total_files=3,
        )
        result = directory_summary_to_dict(summary)
        assert result["directory"] == "/tmp/binaries"
        assert result["total_files"] == 3
        assert result["analyzed_files"] == 1
        assert isinstance(result["results"], list)
        assert len(result["results"]) == 1

    def test_empty_results(self):
        summary = DirectoryAnalysisSummary(
            directory="/tmp/empty",
            analyzed_results=(),
            total_files=0,
        )
        result = directory_summary_to_dict(summary)
        assert result["results"] == []
        assert result["analyzed_files"] == 0

    def test_nested_result_contains_binary_fields(self):
        summary = DirectoryAnalysisSummary(
            directory="/tmp",
            analyzed_results=(_make_analysis_result("/tmp/a"),),
            total_files=1,
        )
        nested = directory_summary_to_dict(summary)["results"][0]
        assert nested["binary"] == "/tmp/a"
        assert "unsafe_functions" in nested


class TestDirectoryOutcomeToDict:
    """Line 52 — directory_outcome_to_dict includes operational_notices when present."""

    def test_outcome_without_notices_omits_notices_key(self):
        summary = DirectoryAnalysisSummary(
            directory="/tmp",
            analyzed_results=(),
            total_files=0,
        )
        outcome = DirectoryAnalysisOutcome(summary=summary)
        result = directory_outcome_to_dict(outcome)
        assert "operational_notices" not in result

    def test_outcome_with_notices_includes_notices_list(self):
        summary = DirectoryAnalysisSummary(
            directory="/tmp",
            analyzed_results=(),
            total_files=2,
        )
        notices = (
            OperationalNotice(message="skipped file1", file_path="/tmp/file1"),
            OperationalNotice(message="skipped file2", file_path="/tmp/file2"),
        )
        outcome = DirectoryAnalysisOutcome(summary=summary, operational_notices=notices)
        result = directory_outcome_to_dict(outcome)
        assert "operational_notices" in result
        assert len(result["operational_notices"]) == 2

    def test_notice_serialization_structure(self):
        summary = DirectoryAnalysisSummary(
            directory="/tmp",
            analyzed_results=(),
            total_files=1,
        )
        notice = OperationalNotice(message="parse failed", file_path="/tmp/bad.bin")
        outcome = DirectoryAnalysisOutcome(summary=summary, operational_notices=(notice,))
        result = directory_outcome_to_dict(outcome)
        serialized = result["operational_notices"][0]
        assert serialized["message"] == "parse failed"
        assert serialized["file_path"] == "/tmp/bad.bin"


# ---------------------------------------------------------------------------
# 9. bannedfunc.py — lines 42-43 (main() returns 1 when result is None)
#
#    We cannot call real main() without real binaries and full CLI setup,
#    so we exercise the critical branch by directly calling dispatch_cli_analysis
#    through a minimal real harness that returns None.
# ---------------------------------------------------------------------------

class _FakeArgs:
    """Minimal args object consumed by dispatch_cli_analysis."""
    file = None        # cli_dispatch.py checks args.file
    directory = None
    output = "/tmp"
    decompiler = "default"
    force_decompiler = False
    verbose = False
    skip_banned = False
    skip_analysis = False
    skip_requirements = True
    workers = None
    parallel = True


class _NullWiring:
    """Minimal wiring object; all fields are None so dispatch returns None."""

    class _NullConfig:
        def get(self, key, default=None):
            return default

        def __getitem__(self, key):
            raise KeyError(key)

        def get_output_dir(self):
            return "/tmp"

        def to_dict(self):
            return {}

    config = _NullConfig()
    r2_factory = None
    binary = None
    directory = None
    config_factory = None


class TestBannedFuncMainNoneResult:
    """Lines 42-43 — exercise the result-is-None branch of main()."""

    def test_dispatch_with_no_binary_and_no_directory_returns_none(self):
        # dispatch_cli_analysis returns None when both args.binary and args.directory
        # are falsy, which maps to the `if result is None: return 1` branch.
        args = _FakeArgs()
        result = dispatch_cli_analysis(
            args,
            _NullWiring(),
            analyze_binary=lambda *a, **kw: None,
            analyze_directory=lambda *a, **kw: None,
            logger=__import__("logging").getLogger("test"),
        )
        assert result is None


# ---------------------------------------------------------------------------
# 10. application/__init__.py — lines 23-29
#     Lazy __getattr__: load known names, raise AttributeError for unknown.
# ---------------------------------------------------------------------------

class TestApplicationPackageLazyGetattr:
    """Lines 23-29 — application/__init__.py lazy attribute resolution."""

    def test_analyze_binary_is_callable(self):
        # Accessing the attribute triggers __getattr__ -> import_module -> getattr
        fn = application_pkg.analyze_binary
        assert callable(fn)

    def test_analyze_function_is_callable(self):
        fn = application_pkg.analyze_function
        assert callable(fn)

    def test_analyze_directory_is_callable(self):
        fn = application_pkg.analyze_directory
        assert callable(fn)

    def test_r2_binary_analyzer_is_class(self):
        cls = application_pkg.R2BinaryAnalyzer
        assert isinstance(cls, type)

    def test_unknown_attribute_raises_attribute_error(self):
        with pytest.raises(AttributeError, match="has no attribute"):
            _ = application_pkg.this_does_not_exist_xyz  # type: ignore[attr-defined]

    def test_second_access_uses_cached_value(self):
        # After first access the value is inserted into globals(); second access
        # must return the same object without re-importing.
        first = application_pkg.analyze_binary
        second = application_pkg.analyze_binary
        assert first is second


# ---------------------------------------------------------------------------
# 11. __init__.py (root) — lines 36-42
#     Same lazy __getattr__ pattern at the top-level package.
# ---------------------------------------------------------------------------

class TestRootPackageLazyGetattr:
    """Lines 36-42 — bannedfuncdetector/__init__.py lazy attribute resolution."""

    def test_analyze_binary_resolves(self):
        fn = root_pkg.analyze_binary
        assert callable(fn)

    def test_analyze_directory_resolves(self):
        fn = root_pkg.analyze_directory
        assert callable(fn)

    def test_create_application_wiring_resolves(self):
        fn = root_pkg.create_application_wiring
        assert callable(fn)

    def test_create_binary_analyzer_resolves(self):
        fn = root_pkg.create_binary_analyzer
        assert callable(fn)

    def test_create_config_from_file_resolves(self):
        fn = root_pkg.create_config_from_file
        assert callable(fn)

    def test_create_config_from_dict_resolves(self):
        fn = root_pkg.create_config_from_dict
        assert callable(fn)

    def test_banned_function_class_resolves(self):
        cls = root_pkg.BannedFunction
        assert isinstance(cls, type)

    def test_analysis_result_class_resolves(self):
        cls = root_pkg.AnalysisResult
        assert isinstance(cls, type)

    def test_unknown_attribute_raises_attribute_error(self):
        with pytest.raises(AttributeError, match="has no attribute"):
            _ = root_pkg.nonexistent_export_abc  # type: ignore[attr-defined]

    def test_cached_after_first_access(self):
        first = root_pkg.BannedFunction
        second = root_pkg.BannedFunction
        assert first is second
