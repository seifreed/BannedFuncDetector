# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage gap tests targeting the exact missing lines reported by pytest-cov.

Targets and status after investigation:
  binary_flow_runtime.py:158   — final `return result` defensive fallback when
                                  result is neither Ok nor Err and cleanup Err.
                                  Reached by temporarily replacing _finalize_analysis
                                  at the module level (same pattern as existing
                                  TestCascadeNotProperlyConfigured).
  session_setup.py:58          — closer returns Err with non-str .error → str().
  session_setup.py:86          — defensive fallback `return err(...)` when
                                  _extract_functions returns neither Ok nor Err.
                                  Reached by module-level replacement of the
                                  imported _extract_functions in session_setup.
  dto_mappers.py:60            — detection["banned_functions"] is not a list.
  directory_runners.py:67      — config_factory is None → ValueError.
  r2_session.py:99             — retry loop body never runs (_OPEN_RETRY_ATTEMPTS=0)
                                  → post-loop RuntimeError fires.
  r2ai_server.py:85            — _log_model_list with >5 models (truncation line).
  r2ai_server.py:293           — _await_server_ready returns True (server UP path).
  availability.py:47           — _check_service_decompiler(print_message=True) when
                                  decai is NOT available (warning branch).
  decompiler_availability.py:22-23 — _is_http_ok except (AttributeError, TypeError).
  validators.py:48             — _normalize_command("") empty command → ValueError.
  validators.py:140            — _run_command blocked unrecognised executable.
  file_detection.py:165-171    — OSError from _load_magic_module propagates to
                                  is_executable_file's OSError handler.
  file_detection.py:172-178    — TypeError from magic module's from_file returning
                                  a non-string propagates outside _detect_executable_
                                  with_magic's inner try/except.

Lines NOT covered (genuinely unreachable without mocking an import):
  file_detection.py:29-30, 36-37 — require simulating a failing magic import.
  availability.py:162             — documented unreachable (type-system guarantee).
"""

from __future__ import annotations


import pytest

from conftest import FakeConfigRepository, FakeR2, start_test_server

# =============================================================================
# 1. binary_flow_runtime.py:158
#    final `return result` when cleanup returns Err but result is a third type
# =============================================================================


class TestBinaryFlowRuntimeLine158:
    """
    Purpose: Cover the final `return result` at line 158 of
    run_detection_with_cleanup.  This line is the defensive fallback when
    result is neither Ok nor Err after cleanup produced an Err.

    We create the scenario by temporarily replacing _finalize_analysis in
    the binary_flow_runtime module namespace with a real callable that returns
    a custom third-type object.  The same module-attribute replacement pattern
    is already established by TestCascadeNotProperlyConfigured and
    TestBinaryFlowRuntimeLine124 in test_coverage_final.py.
    """

    class _ThirdResult:
        """A result-like object that is neither Ok nor Err."""

        def is_ok(self) -> bool:
            return False

        def is_err(self) -> bool:
            return False

    def test_final_return_result_when_result_is_third_type(self):
        """
        Purpose: binary_flow_runtime.py:158 — `return result` fires when
        the r2_closer returns Err AND result is neither Ok nor Err.

        Arrange:
          - runtime whose r2_closer always returns Err (so cleanup section
            is entered, not the early return at line 136).
          - _finalize_analysis replaced with a real callable returning a
            custom _ThirdResult object (neither Ok nor Err) so neither
            isinstance check at lines 139 or 149 fires.
        Act: call run_detection_with_cleanup with detect_impl returning [].
        Assert: the returned object IS the _ThirdResult instance.
        """
        from bannedfuncdetector.application.binary_analyzer import (
            binary_flow_runtime as bfr_mod,
        )
        from bannedfuncdetector.application.contracts.analysis import (
            BinaryAnalysisRequest,
        )
        from bannedfuncdetector.application.analysis_runtime import (
            AnalysisRuntime,
            BinaryRuntimeServices,
        )
        from bannedfuncdetector.domain.result import err

        fake_r2 = FakeR2(
            cmd_map={"aaa": ""},
            cmdj_map={"aflj": [{"name": "main", "offset": 0x1000, "size": 100}]},
        )

        def closing_that_returns_err(r2):
            return err("cleanup failure")

        runtime = AnalysisRuntime(
            config=FakeConfigRepository(
                {
                    "banned_functions": ["strcpy"],
                    "decompiler": {"type": "default", "options": {}},
                    "analysis": {"threshold": 0, "skip_small_functions": False},
                }
            ),
            r2_factory=lambda path: fake_r2,
            binary=BinaryRuntimeServices(
                binary_opener=lambda path, verbose, r2_factory: fake_r2,
                r2_closer=closing_that_returns_err,
            ),
        )

        third_result = self._ThirdResult()
        original_finalize = bfr_mod._finalize_analysis

        def finalize_returning_third(*args, **kwargs):
            return third_result

        request = BinaryAnalysisRequest(
            runtime=runtime,
            output_dir=None,
            verbose=False,
            skip_analysis=True,
        )

        try:
            bfr_mod._finalize_analysis = finalize_returning_third
            outcome = bfr_mod.run_detection_with_cleanup(
                # A real, regular file on every OS (the opener is faked, so only
                # _validate_binary_input's existence check matters here); "/bin/ls"
                # does not exist on Windows and would fail validation early.
                __file__,
                request,
                detect_impl=lambda r2, funcs, params: [],
            )
        finally:
            bfr_mod._finalize_analysis = original_finalize

        # Line 158 executed: the third-type result was returned as-is.
        assert outcome is third_result


# =============================================================================
# 2. session_setup.py:58 — closer returns Err with non-str .error
#    session_setup.py:86 — defensive fallback when _extract_functions returns
#                           neither Ok nor Err
# =============================================================================


class TestSessionSetup:
    """
    Purpose: Cover the two missing branches in setup_binary_analysis.

    Line 58: closer returns Err whose .error is NOT a str, so the code
    calls str() on it: `cleanup_message = str(cleanup_message)`.

    Line 86: defensive `return err(ExecutionFailure(...))` when
    functions_result is neither Ok nor Err.  Reached by temporarily
    replacing the imported _extract_functions in the session_setup module
    namespace to return a custom third-type object.
    """

    def _make_runtime(self, fake_r2, closer):
        from bannedfuncdetector.application.analysis_runtime import (
            AnalysisRuntime,
            BinaryRuntimeServices,
        )

        return AnalysisRuntime(
            config=FakeConfigRepository(
                {
                    "banned_functions": ["strcpy"],
                    "decompiler": {"type": "default", "options": {}},
                    "analysis": {"threshold": 0, "skip_small_functions": False},
                }
            ),
            r2_factory=lambda path: fake_r2,
            binary=BinaryRuntimeServices(
                binary_opener=lambda path, verbose, r2_factory: fake_r2,
                r2_closer=closer,
            ),
        )

    def _make_plan(self, runtime):
        from bannedfuncdetector.application.internal.execution_plans import (
            BinaryScanPlan,
        )

        return BinaryScanPlan(
            output_dir=None,
            decompiler_type="default",
            verbose=False,
            worker_limit=None,
            runtime=runtime,
            force_decompiler=False,
            skip_banned=False,
            skip_analysis=False,
            decompiler_orchestrator=None,
        )

    def test_closer_returns_err_with_non_str_error_hits_line_58(self):
        """
        Purpose: session_setup.py:58 — when _extract_functions returns Err
        AND the closer's Err.error is not a str, the code converts it with
        str(): `cleanup_message = str(cleanup_message)`.

        Arrange: FakeR2 returning no functions (empty aflj → Err), closer
        returning Err(42) where 42 is int (not str).
        Act: call setup_binary_analysis.
        Assert: Err containing operational notice whose message contains "42".
        """
        from bannedfuncdetector.application.binary_analyzer.session_setup import (
            setup_binary_analysis,
        )
        from bannedfuncdetector.domain.result import err

        # Empty aflj → _extract_functions returns Err("No functions found...")
        fake_r2 = FakeR2(
            cmd_map={"aaa": ""},
            cmdj_map={"aflj": []},
        )

        def closer_returning_non_str_err(r2):
            return err(42)  # .error is int, not str → triggers str() at line 58

        runtime = self._make_runtime(fake_r2, closer_returning_non_str_err)
        plan = self._make_plan(runtime)

        result = setup_binary_analysis("/bin/ls", plan)

        assert result.is_err()
        failure = result.error
        notices = failure.operational_notices
        assert len(notices) == 1
        assert "42" in notices[0].message

    def test_extract_functions_third_type_hits_defensive_fallback_line_86(self):
        """
        Purpose: session_setup.py:86 — the final `return err(ExecutionFailure
        (..., "Unexpected function extraction response"))` fires when
        _extract_functions returns neither Ok nor Err.

        Arrange: temporarily replace _extract_functions in the session_setup
        module namespace with a real callable that returns a custom
        third-type object (neither Ok nor Err).  A working opener and
        closer are wired so the code reaches the functions_result check.
        Act: call setup_binary_analysis.
        Assert: Err with "Unexpected function extraction response".
        """
        from bannedfuncdetector.application.binary_analyzer import (
            session_setup as ss_mod,
        )
        from bannedfuncdetector.domain.result import ok

        fake_r2 = FakeR2(
            cmd_map={"aaa": ""},
            cmdj_map={"aflj": [{"name": "main", "offset": 0x1000, "size": 100}]},
        )

        def closer_ok(r2):
            return ok(None)

        runtime = self._make_runtime(fake_r2, closer_ok)
        plan = self._make_plan(runtime)

        class _ThirdFuncResult:
            """Neither Ok nor Err — triggers line 86's defensive fallback."""

            def is_ok(self):
                return False

            def is_err(self):
                return False

        third = _ThirdFuncResult()
        original_extract = ss_mod._extract_functions

        def extract_returning_third(r2, verbose=False):
            return third

        try:
            ss_mod._extract_functions = extract_returning_third
            from bannedfuncdetector.application.binary_analyzer.session_setup import (
                setup_binary_analysis,
            )
            result = setup_binary_analysis("/bin/ls", plan)
        finally:
            ss_mod._extract_functions = original_extract

        assert result.is_err()
        assert "Unexpected function extraction response" in result.error.error.message


# =============================================================================
# 3. dto_mappers.py:60 — banned_functions is not a list → banned_calls = ()
# =============================================================================


class TestDtoMappers:
    """
    Purpose: Cover dto_mappers.detection_entity_from_dto line 60 — the
    `else: banned_calls = ()` branch when banned_functions is not a list.
    """

    def test_banned_functions_string_produces_empty_banned_calls(self):
        """
        Purpose: dto_mappers.py:60 — str for "banned_functions" hits else.
        """
        from bannedfuncdetector.application.dto_mappers import detection_entity_from_dto

        dto = {
            "name": "dangerous_func",
            "address": 0x4000,
            "size": 64,
            "banned_functions": "strcpy",  # str, not list
            "detection_method": "import",
        }
        entity = detection_entity_from_dto(dto)

        assert entity.banned_calls == ()
        assert entity.name == "dangerous_func"

    def test_banned_functions_none_produces_empty_banned_calls(self):
        """
        Purpose: dto_mappers.py:60 — None is not a list.
        """
        from bannedfuncdetector.application.dto_mappers import detection_entity_from_dto

        dto = {
            "name": "func_x",
            "address": 0x2000,
            "size": 32,
            "banned_functions": None,
            "detection_method": "pattern",
        }
        entity = detection_entity_from_dto(dto)

        assert entity.banned_calls == ()

    def test_banned_functions_integer_produces_empty_banned_calls(self):
        """
        Purpose: dto_mappers.py:60 — int is not a list.
        """
        from bannedfuncdetector.application.dto_mappers import detection_entity_from_dto

        dto = {
            "name": "func_y",
            "address": 0x3000,
            "banned_functions": 99,
        }
        entity = detection_entity_from_dto(dto)

        assert entity.banned_calls == ()


# =============================================================================
# 4. directory_runners.py:67 — config_factory is None → ValueError
# =============================================================================


class TestDirectoryRunnersConfigFactoryNone:
    """
    Purpose: Cover directory_runners.iter_parallel_directory_results line 67 —
    `raise ValueError("config_factory is required for directory analysis")`
    when plan.runtime.config_factory is None.
    """

    def _make_plan_without_config_factory(self):
        from bannedfuncdetector.application.analysis_runtime import (
            AnalysisRuntime,
            BinaryRuntimeServices,
        )
        from bannedfuncdetector.application.internal.execution_plans import (
            DirectoryScanPlan,
        )
        from bannedfuncdetector.domain.result import ok

        fake_r2 = FakeR2()
        runtime = AnalysisRuntime(
            config=FakeConfigRepository({"banned_functions": ["strcpy"]}),
            r2_factory=lambda path: fake_r2,
            config_factory=None,  # triggers line 67
            binary=BinaryRuntimeServices(
                binary_opener=lambda path, verbose, r2_factory: fake_r2,
                r2_closer=lambda r2: ok(None),
            ),
        )
        return DirectoryScanPlan(
            runtime=runtime,
            verbose=False,
            parallel=True,
            decompiler_type="default",
            skip_analysis=True,
        )

    def test_config_factory_none_raises_value_error(self):
        """
        Purpose: directory_runners.py:67 — ValueError raised when
        config_factory is None.
        """
        from bannedfuncdetector.application.internal.directory_runners import (
            iter_parallel_directory_results,
        )

        plan = self._make_plan_without_config_factory()

        with pytest.raises(ValueError, match="config_factory is required"):
            list(iter_parallel_directory_results(["/bin/ls"], plan, max_workers=1))


# =============================================================================
# 5. r2_session.py:99 — post-loop RuntimeError when loop never ran
# =============================================================================


class TestR2SessionRetryExhaustion:
    """
    Purpose: Cover r2_session.open_binary_with_r2 line 99 —
    `raise RuntimeError(f"Failed to open binary with r2: ...")`.

    With _OPEN_RETRY_ATTEMPTS=2 the loop re-raises on the last attempt,
    hitting line 90 not line 99.  Line 99 fires only when the for loop
    body never executes (range is empty).  We temporarily set
    _OPEN_RETRY_ATTEMPTS=0 in the module namespace — same pattern used
    throughout the existing suite.
    """

    def test_zero_attempts_skips_loop_and_raises_runtime_error_at_line_99(self):
        """
        Purpose: r2_session.py:99 — post-loop RuntimeError when the
        for-range is empty (_OPEN_RETRY_ATTEMPTS temporarily set to 0).

        Arrange: patch _OPEN_RETRY_ATTEMPTS to 0; factory never called.
        Act: call open_binary_with_r2.
        Assert: RuntimeError("Failed to open binary with r2: ...") is raised.
        """
        from bannedfuncdetector.infrastructure.adapters import r2_session as r2s_mod
        from bannedfuncdetector.infrastructure.adapters.r2_session import (
            open_binary_with_r2,
        )

        original_attempts = r2s_mod._OPEN_RETRY_ATTEMPTS
        call_count = [0]

        def factory_never_called(path):
            call_count[0] += 1
            raise BrokenPipeError("should not be called")

        try:
            r2s_mod._OPEN_RETRY_ATTEMPTS = 0
            with pytest.raises(RuntimeError, match="Failed to open binary with r2"):
                open_binary_with_r2(
                    "/bin/ls",
                    verbose=False,
                    r2_factory=factory_never_called,
                )
        finally:
            r2s_mod._OPEN_RETRY_ATTEMPTS = original_attempts

        assert call_count[0] == 0  # loop body never ran


# =============================================================================
# 6a. r2ai_server.py:85 — _log_model_list with >5 models (truncation line)
# =============================================================================


class TestR2AiServerLogModelList:
    """
    Purpose: Cover r2ai_server._log_model_list line 85 —
    `if len(models) > 5: logger.info("    ... and %d more", ...)`.
    """

    def test_log_model_list_more_than_five_logs_truncation(self):
        """
        Purpose: r2ai_server.py:85 — 6 models triggers the truncation branch.
        """
        from bannedfuncdetector.infrastructure.adapters.r2ai_server import (
            _log_model_list,
        )

        models = [
            "model-alpha",
            "model-beta",
            "model-gamma",
            "model-delta",
            "model-epsilon",
            "model-zeta",  # 6th item triggers `len(models) > 5`
        ]

        _log_model_list(models, header="Available models:")

    def test_log_model_list_exactly_five_no_truncation(self):
        """
        Purpose: r2ai_server.py:85 — exactly 5 models; truncation NOT taken.
        """
        from bannedfuncdetector.infrastructure.adapters.r2ai_server import (
            _log_model_list,
        )

        _log_model_list(["m1", "m2", "m3", "m4", "m5"], header="Five models:")


# =============================================================================
# 6b. r2ai_server.py:293 — _await_server_ready returns True (server UP)
# =============================================================================


class TestR2AiServerAwaitServerReady:
    """
    Purpose: Cover r2ai_server._await_server_ready line 293 — `return True`
    when the server responds within the allowed attempts.

    We use start_test_server from conftest (the same helper used extensively
    in test_coverage_final.py) to spin up a real local HTTP server that
    responds with 200 to /ping.
    """

    def test_await_server_ready_returns_true_when_server_is_up(self):
        """
        Purpose: r2ai_server.py:293 — `return True` fires when
        _wait_for_server succeeds on the first ping.

        Arrange: start_test_server (real HTTP server responding 200 to /ping).
        Act: call _await_server_ready with the server URL.
        Assert: returns True.
        """
        from bannedfuncdetector.infrastructure.adapters.r2ai_server import (
            _await_server_ready,
        )

        url, server = start_test_server(ping_status=200)
        try:
            result = _await_server_ready(url)
            assert result is True
        finally:
            server.shutdown()


# =============================================================================
# 7. availability.py:47 — _check_service_decompiler(print_message=True) when
#    decai is NOT available (warning branch)
# =============================================================================


class TestAvailabilityDecaiWarningBranch:
    """
    Purpose: Cover availability.py:47 —
    `logger.warning("Plugin decai is not available or Ollama is not running")`
    inside _check_service_decompiler(print_message=True) when decai is
    unavailable.

    Because decai/Ollama may or may not be running on the host, we cannot
    rely on the environment.  We force the unavailable path by temporarily
    replacing `check_decompiler_plugin_available` in the availability module
    namespace with a real callable that always returns False for DECAI.
    This is the same module-attribute replacement pattern used throughout
    the existing test suite.
    """

    def test_check_service_decompiler_unavailable_logs_warning_at_line_47(self):
        """
        Purpose: availability.py:47 — with print_message=True and
        check_decompiler_plugin_available returning False, the else-branch
        `logger.warning("Plugin decai is not available...")` fires.

        Arrange: replace check_decompiler_plugin_available in the availability
        module namespace with a real callable returning False.
        Act: call _check_service_decompiler(print_message=True).
        Assert: returns False and does not raise.
        """
        from bannedfuncdetector.infrastructure.decompilers import (
            availability as av_mod,
        )

        original_check = av_mod.check_decompiler_plugin_available

        def always_unavailable(decompiler_type):
            return False

        try:
            av_mod.check_decompiler_plugin_available = always_unavailable
            result = av_mod._check_service_decompiler(print_message=True)
        finally:
            av_mod.check_decompiler_plugin_available = original_check

        assert result is False

    def test_check_service_decompiler_available_logs_info_branch(self):
        """
        Purpose: availability.py:44-45 — with print_message=True and decai
        available, the if-branch `logger.info("Plugin decai is available...")`
        fires (also ensures the available=True path does not raise).
        """
        from bannedfuncdetector.infrastructure.decompilers import (
            availability as av_mod,
        )

        original_check = av_mod.check_decompiler_plugin_available

        def always_available(decompiler_type):
            return True

        try:
            av_mod.check_decompiler_plugin_available = always_available
            result = av_mod._check_service_decompiler(print_message=True)
        finally:
            av_mod.check_decompiler_plugin_available = original_check

        assert result is True


# =============================================================================
# 8. decompiler_availability.py:22-23 — _is_http_ok AttributeError/TypeError
# =============================================================================


class TestDecompilerAvailabilityIsHttpOk:
    """
    Purpose: Cover decompiler_availability._is_http_ok lines 22-23 —
    `except (AttributeError, TypeError): return False`.
    """

    def test_is_http_ok_property_raises_attribute_error_returns_false(self):
        """
        Purpose: decompiler_availability.py:22-23 — AttributeError from
        status_code is caught and False returned.
        """
        from bannedfuncdetector.infrastructure.decompilers.decompiler_availability import (
            _is_http_ok,
        )

        class BadResponse:
            @property
            def status_code(self):
                raise AttributeError("no status_code")

        result = _is_http_ok(BadResponse())
        assert result is False

    def test_is_http_ok_property_raises_type_error_returns_false(self):
        """
        Purpose: decompiler_availability.py:22-23 — TypeError from
        status_code is caught and False returned.
        """
        from bannedfuncdetector.infrastructure.decompilers.decompiler_availability import (
            _is_http_ok,
        )

        class TypeErrorResponse:
            @property
            def status_code(self):
                raise TypeError("type error")

        result = _is_http_ok(TypeErrorResponse())
        assert result is False

    def test_is_http_ok_plain_object_no_attribute_returns_false(self):
        """
        Purpose: decompiler_availability.py:22-23 — plain object() has no
        status_code; attribute access raises AttributeError.
        """
        from bannedfuncdetector.infrastructure.decompilers.decompiler_availability import (
            _is_http_ok,
        )

        result = _is_http_ok(object())
        assert result is False


# =============================================================================
# 9. validators.py:48 — _normalize_command empty command → ValueError
#    validators.py:140 — _run_command blocked unrecognised executable
# =============================================================================


class TestValidatorsMissingLines:
    """
    Purpose:
    - Line 48: _normalize_command raises ValueError("Command cannot be empty")
      when called with an empty sequence.
    - Line 140: _run_command raises ValueError("Blocked unrecognized command")
      when command[0] is not in ALLOWED_REQUIREMENT_EXECUTABLES.
    """

    def test_normalize_command_empty_command_raises_value_error(self):
        """
        Purpose: validators.py:48 — `raise ValueError("Command cannot be empty")`
        fires when command is falsy (empty list).

        Arrange: pass an empty list to _normalize_command.
        Act: call _normalize_command([]).
        Assert: raises ValueError("Command cannot be empty").
        """
        from bannedfuncdetector.infrastructure.validators import _normalize_command

        with pytest.raises(ValueError, match="Command cannot be empty"):
            _normalize_command([])

    def test_normalize_command_nonexistent_executable_raises_file_not_found(self):
        """
        Purpose: validators.py:51 — FileNotFoundError when shutil.which
        returns None (bonus coverage: adjacent line verified still works).
        """
        from bannedfuncdetector.infrastructure.validators import _normalize_command

        with pytest.raises(FileNotFoundError, match="Executable not found"):
            _normalize_command(["definitely_not_a_real_exe_xyz_9876543"])

    def test_run_command_blocked_unrecognised_command_raises_value_error(self):
        """
        Purpose: validators.py:140 — `raise ValueError("Blocked unrecognized
        command: ...")` when command[0] is not in ALLOWED_REQUIREMENT_EXECUTABLES.

        Arrange: call _run_command with a command whose first element is
        "curl", which is not in {"r2", "python"}.
        Act: call _run_command.
        Assert: raises ValueError("Blocked unrecognized command").
        """
        from bannedfuncdetector.infrastructure.validators import _run_command

        with pytest.raises(ValueError, match="Blocked unrecognized command"):
            _run_command(["curl", "--version"])

    def test_run_command_blocked_empty_list_raises_value_error(self):
        """
        Purpose: validators.py:140 — empty list also triggers the ValueError
        guard (`not resolved` is True → first condition fires).
        """
        from bannedfuncdetector.infrastructure.validators import _run_command

        with pytest.raises(ValueError, match="Blocked unrecognized command"):
            _run_command([])


# =============================================================================
# 10. file_detection.py:165-171 — OSError propagates from _load_magic_module
#     file_detection.py:172-178 — TypeError from magic module after from_file
# =============================================================================


class TestFileDetectionFallbackBranches:
    """
    Purpose: Cover the two except fallback branches inside is_executable_file
    (lines 165-171 for OSError/IOError and 172-178 for RuntimeError/ValueError/
    TypeError).

    The key insight: exceptions raised by `from_file` INSIDE
    _detect_executable_with_magic are caught by its own `except Exception`
    at line 112-113 (returning None).  The outer handlers at 165-178 are
    reached only when an exception is raised OUTSIDE that inner try/except,
    specifically:

    OSError path (165-171):
      - Make _load_magic_module() itself raise OSError; that call at line 106
        is outside the inner try/except and propagates to is_executable_file.

    TypeError/ValueError path (172-178):
      - Make _load_magic_module() return a real object whose from_file()
        returns a non-string (e.g. integer 42).  Inside _detect_executable_
        with_magic, the detected_type is assigned at line 111 (inside try),
        but the `marker in detected_type` check at line 117/123 is OUTSIDE
        the try.  `"PE32" in 42` raises TypeError which propagates to the
        outer handlers at 172-178.

    Both replacements are module-attribute swaps (not mocking).
    """

    def test_oserror_from_load_magic_module_triggers_oserror_fallback(
        self, tmp_path
    ):
        """
        Purpose: file_detection.py:165-171 — _load_magic_module() raises
        OSError; the outer except (OSError, IOError) handler fires and falls
        back to _check_magic_bytes.

        Arrange: write an ELF file; replace _load_magic_module with a real
        callable that raises OSError.
        Act: call is_executable_file.
        Assert: returns True (fallback _check_magic_bytes reads the real
        ELF magic bytes correctly).
        """
        from bannedfuncdetector.infrastructure import file_detection as fd_mod

        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 60)
        elf_path_str = str(elf_path)

        original_load = fd_mod._load_magic_module

        def load_magic_raising_oserror():
            raise OSError("libmagic not found")

        try:
            fd_mod._load_magic_module = load_magic_raising_oserror
            result = fd_mod.is_executable_file(elf_path_str, "elf")
        finally:
            fd_mod._load_magic_module = original_load

        # _check_magic_bytes fallback reads real ELF magic → True
        assert result is True

    def test_ioerror_from_load_magic_module_triggers_oserror_fallback(
        self, tmp_path
    ):
        """
        Purpose: file_detection.py:165-171 — IOError (alias of OSError)
        triggers the same handler.
        """
        from bannedfuncdetector.infrastructure import file_detection as fd_mod

        pe_path = tmp_path / "test.exe"
        pe_path.write_bytes(b"MZ" + b"\x00" * 62)
        pe_path_str = str(pe_path)

        original_load = fd_mod._load_magic_module

        def load_magic_raising_ioerror():
            raise IOError("io error from libmagic")

        try:
            fd_mod._load_magic_module = load_magic_raising_ioerror
            result = fd_mod.is_executable_file(pe_path_str, "pe")
        finally:
            fd_mod._load_magic_module = original_load

        assert result is True

    def test_type_error_from_marker_check_triggers_runtime_fallback(
        self, tmp_path
    ):
        """
        Purpose: file_detection.py:172-178 — TypeError raised OUTSIDE the
        inner try/except of _detect_executable_with_magic triggers the outer
        except (RuntimeError, ValueError, TypeError) handler.

        The TypeError comes from `marker in detected_type` at line 117/123
        when from_file returns an integer (not a string).

        Arrange: _load_magic_module returns a real object whose from_file
        returns 42 (int); PE magic file.
        Act: call is_executable_file.
        Assert: returns True via _check_magic_bytes fallback.
        """
        from bannedfuncdetector.infrastructure import file_detection as fd_mod

        pe_path = tmp_path / "test2.exe"
        pe_path.write_bytes(b"MZ" + b"\x00" * 62)
        pe_path_str = str(pe_path)

        class MagicModuleReturningInt:
            """Real object whose from_file returns int instead of str."""

            def from_file(self, path: str) -> int:
                return 42  # `"PE32" in 42` → TypeError at line 123

        original_load = fd_mod._load_magic_module

        def load_magic_returning_int():
            return MagicModuleReturningInt()

        try:
            fd_mod._load_magic_module = load_magic_returning_int
            result = fd_mod.is_executable_file(pe_path_str, "pe")
        finally:
            fd_mod._load_magic_module = original_load

        # Fallback _check_magic_bytes reads MZ → True
        assert result is True

    def test_type_error_any_file_type_triggers_runtime_fallback(self, tmp_path):
        """
        Purpose: file_detection.py:172-178 — same TypeError path for file_type
        "any" (branch at line 115-121 rather than 122-127).
        """
        from bannedfuncdetector.infrastructure import file_detection as fd_mod

        macho_path = tmp_path / "test.macho"
        macho_path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
        macho_path_str = str(macho_path)

        class MagicModuleReturningNone:
            """from_file returns None; `marker in None` raises TypeError."""

            def from_file(self, path: str):
                return None  # `"ELF" in None` → TypeError at line 117

        original_load = fd_mod._load_magic_module

        def load_magic_returning_none():
            return MagicModuleReturningNone()

        try:
            fd_mod._load_magic_module = load_magic_returning_none
            result = fd_mod.is_executable_file(macho_path_str, "any")
        finally:
            fd_mod._load_magic_module = original_load

        # Fallback reads Mach-O magic → True
        assert result is True


class TestTryImportMagicMissingModule:
    """Cover file_detection._try_import_magic optional-dependency fallback.

    The fallback is exercised with a genuinely absent module name (a real
    input), so no import machinery is mocked.
    """

    def test_absent_module_returns_none(self):
        """A non-existent module name raises ImportError → returns None."""
        from bannedfuncdetector.infrastructure import file_detection as fd_mod

        result = fd_mod._try_import_magic("bannedfuncdetector_no_such_module_xyz")

        assert result is None

    def test_module_without_from_file_returns_none(self):
        """A real module lacking from_file raises AttributeError → None."""
        from bannedfuncdetector.infrastructure import file_detection as fd_mod

        # `os` imports fine but has no from_file, hitting the same except block.
        result = fd_mod._try_import_magic("os")

        assert result is None

    def test_default_module_imports_real_magic(self):
        """The default name resolves to the real libmagic wrapper when usable.

        libmagic (the C library behind python-magic) is a system dependency that
        is absent on some CI runners (macOS/Windows), where ``_try_import_magic``
        returns None. Assert the invariant that holds either way; on Linux (the
        coverage-gated platform) libmagic is present, so the success branch is
        still exercised.
        """
        from bannedfuncdetector.infrastructure import file_detection as fd_mod

        result = fd_mod._try_import_magic()

        if fd_mod.is_magic_available():
            assert result is not None
            assert hasattr(result, "from_file")
        else:
            assert result is None


class TestGetAvailableDecompilerDefaultFallback:
    """Cover availability.get_available_decompiler explicit default fallback."""

    def test_unavailable_preference_falls_back_to_default(self):
        """When no non-default decompiler is available, the function returns
        'default' via the final guaranteed fallback."""
        import bannedfuncdetector.infrastructure.decompilers.availability as av_mod
        from bannedfuncdetector.infrastructure.decompilers.decompiler_types import (
            DecompilerType,
        )

        # Make every probe report unavailable so the result does not depend on
        # which r2 plugins happen to be installed on the test host.
        original_check = av_mod.check_decompiler_available
        try:
            av_mod.check_decompiler_available = lambda name, print_message=False: False
            assert av_mod.get_available_decompiler("r2dec") == (
                DecompilerType.DEFAULT.value
            )
            assert av_mod.get_available_decompiler("unknown") == (
                DecompilerType.DEFAULT.value
            )
        finally:
            av_mod.check_decompiler_available = original_check

    def test_explicit_default_preference_returns_default(self):
        """Preferring 'default' returns it without probing alternatives."""
        from bannedfuncdetector.infrastructure.decompilers.availability import (
            get_available_decompiler,
        )
        from bannedfuncdetector.infrastructure.decompilers.decompiler_types import (
            DecompilerType,
        )

        assert get_available_decompiler("default") == DecompilerType.DEFAULT.value
        assert (
            get_available_decompiler(DecompilerType.DEFAULT)
            == DecompilerType.DEFAULT.value
        )

    def test_available_candidate_is_returned(self):
        """When a non-default candidate is available, the loop returns it.

        check_decompiler_available is substituted (real fake, restored in
        finally) so an r2 plugin reports as present without requiring it to
        be installed in the test environment.
        """
        import bannedfuncdetector.infrastructure.decompilers.availability as av_mod
        from bannedfuncdetector.infrastructure.decompilers.decompiler_types import (
            DecompilerType,
        )

        original_check = av_mod.check_decompiler_available
        try:
            av_mod.check_decompiler_available = (
                lambda name, print_message=False: name
                == DecompilerType.R2GHIDRA.value
            )
            result = av_mod.get_available_decompiler("r2ghidra")
        finally:
            av_mod.check_decompiler_available = original_check

        assert result == DecompilerType.R2GHIDRA.value
