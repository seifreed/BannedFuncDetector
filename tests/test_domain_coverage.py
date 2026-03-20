#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""
Coverage tests for:
  - bannedfuncdetector.domain.entities
  - bannedfuncdetector.domain.types
  - bannedfuncdetector.application.dto_mappers

All tests call real production code with real inputs.  No mocks, no stubs.
"""

from bannedfuncdetector.domain.entities import (
    CATEGORY_RISK_WEIGHTS,
    CRITICAL_CATEGORIES,
    DETECTION_METHOD_WEIGHTS,
    AnalysisResult,
    BannedFunction,
    DirectoryAnalysisSummary,
    FunctionDescriptor,
)
from bannedfuncdetector.domain.error_types import ErrorCategory
from bannedfuncdetector.domain.types import (
    classify_error,
    create_detection_result,
    safe_parse_address,
    search_banned_call_in_text,
)
from bannedfuncdetector.application.dto_mappers import (
    detection_entity_from_dto,
    detection_entity_to_dto,
    function_descriptor_from_dto,
    function_descriptor_to_dto,
)

# ---------------------------------------------------------------------------
# Helpers – build real domain objects used across multiple tests
# ---------------------------------------------------------------------------


def _make_banned_function(
    name: str = "strcpy",
    address: int = 0x401000,
    size: int = 32,
    banned_calls: tuple[str, ...] = ("strcpy",),
    detection_method: str = "import",
    category: str | None = "string_copy",
) -> BannedFunction:
    return BannedFunction(
        name=name,
        address=address,
        size=size,
        banned_calls=banned_calls,
        detection_method=detection_method,
        category=category,
    )


def _make_analysis_result(
    file_name: str = "test.exe",
    file_path: str = "/tmp/test.exe",
    total_functions: int = 10,
    detected_functions: tuple[BannedFunction, ...] = (),
    analysis_date: str = "2026-03-15",
) -> AnalysisResult:
    return AnalysisResult(
        file_name=file_name,
        file_path=file_path,
        total_functions=total_functions,
        detected_functions=detected_functions,
        analysis_date=analysis_date,
    )


# ===========================================================================
# domain/entities.py – BannedFunction
# ===========================================================================


class TestBannedFunctionIsCritical:
    """BannedFunction.is_critical covers category-None and category-in/out-of-critical-set."""

    def test_is_critical_true_for_string_copy_category(self):
        func = _make_banned_function(category="string_copy")
        assert func.is_critical is True

    def test_is_critical_true_for_string_concat_category(self):
        func = _make_banned_function(category="string_concat")
        assert func.is_critical is True

    def test_is_critical_true_for_string_format_category(self):
        func = _make_banned_function(category="string_format")
        assert func.is_critical is True

    def test_is_critical_true_for_string_input_category(self):
        func = _make_banned_function(category="string_input")
        assert func.is_critical is True

    def test_is_critical_true_for_memory_category(self):
        func = _make_banned_function(category="memory")
        assert func.is_critical is True

    def test_is_critical_true_for_process_category(self):
        func = _make_banned_function(category="process")
        assert func.is_critical is True

    def test_is_critical_false_for_non_critical_category(self):
        # 'path_manipulation' is not in CRITICAL_CATEGORIES
        func = _make_banned_function(category="path_manipulation")
        assert func.is_critical is False

    def test_is_critical_false_when_category_is_none(self):
        func = _make_banned_function(category=None)
        assert func.is_critical is False

    def test_all_critical_categories_constant_members_yield_true(self):
        for cat in CRITICAL_CATEGORIES:
            func = _make_banned_function(category=cat)
            assert (
                func.is_critical is True
            ), f"Expected is_critical=True for category {cat!r}"


class TestBannedFunctionRiskScore:
    """BannedFunction.risk_score exercises category weight and detection method weight paths."""

    def test_risk_score_is_integer(self):
        func = _make_banned_function(category="string_copy", detection_method="import")
        score = func.risk_score
        assert isinstance(score, int)

    def test_risk_score_is_within_bounds(self):
        func = _make_banned_function(category="string_copy", detection_method="import")
        assert 0 <= func.risk_score <= 100

    def test_risk_score_uses_category_weight(self):
        # string_input has weight 10, decompilation method weight 10
        # score = min(100, 10*7 + 10*3) = min(100, 100) = 100
        func = _make_banned_function(
            category="string_input", detection_method="decompilation"
        )
        assert func.risk_score == 100

    def test_risk_score_caps_at_100(self):
        func = _make_banned_function(
            category="string_input", detection_method="decompilation"
        )
        assert func.risk_score <= 100

    def test_risk_score_with_none_category_uses_default_weight_5(self):
        # category=None → category_weight=5, method "name" → method_weight=6
        # score = min(100, 5*7 + 6*3) = min(100, 35+18) = 53
        func = _make_banned_function(category=None, detection_method="name")
        assert func.risk_score == 53

    def test_risk_score_with_unknown_detection_method_uses_default_5(self):
        # category "time" weight=2, unknown method → weight=5
        # score = min(100, 2*7 + 5*3) = min(100, 14+15) = 29
        func = _make_banned_function(category="time", detection_method="unknown_method")
        assert func.risk_score == 29

    def test_risk_score_for_all_known_categories_stays_in_range(self):
        for cat in CATEGORY_RISK_WEIGHTS:
            func = _make_banned_function(category=cat, detection_method="import")
            assert (
                0 <= func.risk_score <= 100
            ), f"Score out of range for category {cat!r}"

    def test_risk_score_for_all_known_detection_methods_stays_in_range(self):
        for method in DETECTION_METHOD_WEIGHTS:
            func = _make_banned_function(
                category="string_copy", detection_method=method
            )
            assert (
                0 <= func.risk_score <= 100
            ), f"Score out of range for method {method!r}"

    def test_risk_score_formula_correctness(self):
        # string_copy weight=8, "string" method weight=4
        # score = min(100, 8*7 + 4*3) = min(100, 56+12) = 68
        func = _make_banned_function(category="string_copy", detection_method="string")
        assert func.risk_score == 68


# ===========================================================================
# domain/entities.py – AnalysisResult
# ===========================================================================


class TestAnalysisResultProperties:
    """AnalysisResult critical_count and has_critical_issues properties."""

    def test_critical_count_zero_when_no_detections(self):
        result = _make_analysis_result(detected_functions=())
        assert result.critical_count == 0

    def test_critical_count_counts_only_critical_functions(self):
        critical = _make_banned_function(category="string_copy")
        non_critical = _make_banned_function(
            name="mktemp", category="path_manipulation"
        )
        result = _make_analysis_result(detected_functions=(critical, non_critical))
        assert result.critical_count == 1

    def test_critical_count_all_critical(self):
        f1 = _make_banned_function(name="strcpy", category="string_copy")
        f2 = _make_banned_function(name="gets", category="string_input")
        result = _make_analysis_result(detected_functions=(f1, f2))
        assert result.critical_count == 2

    def test_has_critical_issues_false_when_empty(self):
        result = _make_analysis_result(detected_functions=())
        assert result.has_critical_issues is False

    def test_has_critical_issues_false_when_only_non_critical(self):
        non_critical = _make_banned_function(category="path_manipulation")
        result = _make_analysis_result(detected_functions=(non_critical,))
        assert result.has_critical_issues is False

    def test_has_critical_issues_true_when_at_least_one_critical(self):
        critical = _make_banned_function(category="memory")
        result = _make_analysis_result(detected_functions=(critical,))
        assert result.has_critical_issues is True

    def test_has_issues_true_when_detections_present(self):
        # Exercises entities.py line 114: the True branch of has_issues
        func = _make_banned_function(category="string_copy")
        result = _make_analysis_result(detected_functions=(func,))
        assert result.has_issues is True

    def test_has_issues_false_when_no_detections(self):
        result = _make_analysis_result(detected_functions=())
        assert result.has_issues is False


# ===========================================================================
# domain/entities.py – DirectoryAnalysisSummary
# ===========================================================================


class TestDirectoryAnalysisSummaryProperties:
    """DirectoryAnalysisSummary.analyzed_files and total_findings properties."""

    def test_analyzed_files_returns_count_of_results(self):
        r1 = _make_analysis_result(file_name="a.exe")
        r2 = _make_analysis_result(file_name="b.exe")
        summary = DirectoryAnalysisSummary(
            directory="/tmp",
            analyzed_results=(r1, r2),
            total_files=5,
        )
        assert summary.analyzed_files == 2

    def test_analyzed_files_zero_when_no_results(self):
        summary = DirectoryAnalysisSummary(
            directory="/tmp",
            analyzed_results=(),
            total_files=0,
        )
        assert summary.analyzed_files == 0

    def test_total_findings_sums_insecure_counts(self):
        f1 = _make_banned_function(name="strcpy", category="string_copy")
        f2 = _make_banned_function(name="gets", category="string_input")
        r1 = _make_analysis_result(detected_functions=(f1,))
        r2 = _make_analysis_result(detected_functions=(f1, f2))
        summary = DirectoryAnalysisSummary(
            directory="/tmp",
            analyzed_results=(r1, r2),
            total_files=3,
        )
        assert summary.total_findings == 3

    def test_total_findings_zero_when_no_detections(self):
        r1 = _make_analysis_result(detected_functions=())
        summary = DirectoryAnalysisSummary(
            directory="/tmp",
            analyzed_results=(r1,),
            total_files=1,
        )
        assert summary.total_findings == 0

    def test_total_findings_zero_when_no_results(self):
        summary = DirectoryAnalysisSummary(
            directory="/tmp",
            analyzed_results=(),
            total_files=0,
        )
        assert summary.total_findings == 0


# ===========================================================================
# domain/types.py – classify_error
# ===========================================================================


class TestClassifyError:
    """classify_error exercises every branch: OSError/IOError, RuntimeError/ValueError,
    KeyError/AttributeError/TypeError, and the default fallback."""

    def test_oserror_returns_io_category(self):
        result = classify_error(OSError("disk error"))
        assert result == ErrorCategory.IO

    def test_ioerror_returns_io_category(self):
        # IOError is an alias for OSError in Python 3
        result = classify_error(IOError("pipe broken"))
        assert result == ErrorCategory.IO

    def test_runtime_error_returns_runtime_category(self):
        result = classify_error(RuntimeError("unexpected state"))
        assert result == ErrorCategory.RUNTIME

    def test_value_error_returns_runtime_category(self):
        result = classify_error(ValueError("bad value"))
        assert result == ErrorCategory.RUNTIME

    def test_key_error_returns_data_category(self):
        result = classify_error(KeyError("missing key"))
        assert result == ErrorCategory.DATA

    def test_attribute_error_returns_data_category(self):
        result = classify_error(AttributeError("no attribute"))
        assert result == ErrorCategory.DATA

    def test_type_error_returns_data_category(self):
        result = classify_error(TypeError("wrong type"))
        assert result == ErrorCategory.DATA

    def test_generic_exception_returns_error_category(self):
        result = classify_error(Exception("something went wrong"))
        assert result == ErrorCategory.ERROR

    def test_unexpected_exception_subclass_returns_error_category(self):
        class CustomException(Exception):
            pass

        result = classify_error(CustomException("custom"))
        assert result == ErrorCategory.ERROR


# ===========================================================================
# domain/types.py – safe_parse_address
# ===========================================================================


class TestSafeParseAddress:
    """safe_parse_address covers None, int, hex string, empty string, non-hex string,
    and non-string/non-int types."""

    def test_none_returns_zero(self):
        assert safe_parse_address(None) == 0

    def test_integer_passthrough(self):
        assert safe_parse_address(0x401000) == 0x401000

    def test_zero_integer(self):
        assert safe_parse_address(0) == 0

    def test_hex_string_with_prefix(self):
        assert safe_parse_address("0x401000") == 0x401000

    def test_hex_string_without_prefix(self):
        # bare hex digits are valid hex literals
        assert safe_parse_address("4010a0") == 0x4010A0

    def test_empty_string_returns_zero(self):
        assert safe_parse_address("") == 0

    def test_whitespace_only_string_returns_zero(self):
        assert safe_parse_address("   ") == 0

    def test_non_hex_string_returns_zero(self):
        assert safe_parse_address("main") == 0

    def test_sym_dotted_name_returns_zero(self):
        assert safe_parse_address("sym.main") == 0

    def test_float_type_returns_zero(self):
        # float is neither int nor str → final fallback branch
        assert safe_parse_address(3.14) == 0

    def test_list_type_returns_zero(self):
        assert safe_parse_address([0x1000]) == 0

    def test_hex_string_with_leading_whitespace(self):
        assert safe_parse_address("  0x100  ") == 0x100


# ===========================================================================
# domain/types.py – search_banned_call_in_text
# ===========================================================================


class TestSearchBannedCallInText:
    """search_banned_call_in_text checks pattern matching against decompiled text."""

    def test_finds_canonical_banned_function_in_text(self):
        # "strcpy" is in BANNED_FUNCTIONS; use a clear call-site pattern
        code = "int foo() { strcpy(dst, src); return 0; }"
        assert search_banned_call_in_text(code, "strcpy") is True

    def test_does_not_find_absent_function(self):
        code = "int foo() { memcpy(dst, src, 16); return 0; }"
        assert search_banned_call_in_text(code, "strcpy") is False

    def test_case_insensitive_match(self):
        # The compiled pattern uses re.IGNORECASE
        code = "STRCPY(dst, src);"
        assert search_banned_call_in_text(code, "strcpy") is True

    def test_custom_non_canonical_function_name(self):
        # A name not in BANNED_FUNCTIONS falls back to on-demand compilation
        code = "int main() { my_unsafe_func(x); }"
        assert search_banned_call_in_text(code, "my_unsafe_func") is True

    def test_custom_function_name_absent_in_text(self):
        code = "int main() { safe_func(x); }"
        assert search_banned_call_in_text(code, "my_unsafe_func") is False

    def test_partial_word_does_not_match(self):
        # "strcpyA" should not match a pattern for "strcpy" followed by "(" directly
        # because "\b" word boundary is used; but "strcpyA(" would not match "strcpy("
        code = "strcpyA(dst, src);"
        # The pattern is r"\bstrcpy\s*\(" — "strcpyA(" has 'A' between name and '('
        assert search_banned_call_in_text(code, "strcpy") is False

    def test_empty_text_returns_false(self):
        assert search_banned_call_in_text("", "strcpy") is False

    def test_gets_canonical_function(self):
        code = "char *ptr = gets(buf);"
        assert search_banned_call_in_text(code, "gets") is True

    def test_whitespace_between_name_and_paren(self):
        # The pattern allows \s* between name and '('
        code = "sprintf  (buf, fmt);"
        assert search_banned_call_in_text(code, "sprintf") is True

    def test_special_regex_characters_in_custom_name_are_escaped(self):
        # re.escape ensures that special chars like '.' do not cause re.error;
        # this exercises the on-demand compilation path with a name containing
        # characters that would otherwise be invalid in a bare regex.
        # The pattern will compile successfully (re.error branch unreachable)
        # and the search will correctly find no match.
        code = "int foo() { safe(); }"
        assert search_banned_call_in_text(code, "func.name") is False

    def test_custom_name_with_brackets_does_not_raise(self):
        # Brackets are escaped by re.escape; verifies no exception is thrown
        # and the function returns a boolean result.
        code = "int foo() { call(); }"
        result = search_banned_call_in_text(code, "func[0]")
        assert isinstance(result, bool)


# ===========================================================================
# domain/types.py – create_detection_result
# ===========================================================================


class TestCreateDetectionResult:
    """create_detection_result builds a BannedFunction via safe_parse_address
    and get_highest_risk_category."""

    def test_returns_banned_function_instance(self):
        result = create_detection_result(
            func_name="foo",
            func_addr=0x401000,
            banned_functions=["strcpy"],
            detection_method="import",
        )
        assert isinstance(result, BannedFunction)

    def test_name_is_preserved(self):
        result = create_detection_result("vuln_func", 0x100, ["gets"], "name")
        assert result.name == "vuln_func"

    def test_address_parsed_from_hex_string(self):
        result = create_detection_result("f", "0x401000", ["strcpy"], "import")
        assert result.address == 0x401000

    def test_address_parsed_from_int(self):
        result = create_detection_result("f", 0x200, ["sprintf"], "import")
        assert result.address == 0x200

    def test_address_defaults_to_zero_for_none(self):
        result = create_detection_result("f", None, ["strcpy"], "import")
        assert result.address == 0

    def test_banned_calls_tuple_is_preserved(self):
        result = create_detection_result("f", 0x100, ["strcpy", "gets"], "import")
        assert result.banned_calls == ("strcpy", "gets")

    def test_detection_method_is_preserved(self):
        result = create_detection_result("f", 0x100, ["strcpy"], "decompilation")
        assert result.detection_method == "decompilation"

    def test_size_is_zero(self):
        result = create_detection_result("f", 0x100, ["strcpy"], "import")
        assert result.size == 0

    def test_category_is_none_when_banned_functions_empty(self):
        result = create_detection_result("f", 0x100, [], "import")
        assert result.category is None

    def test_category_assigned_from_banned_functions(self):
        # strcpy belongs to "string_copy" — must have a category assigned
        result = create_detection_result("f", 0x100, ["strcpy"], "import")
        assert result.category is not None

    def test_banned_calls_is_tuple_not_list(self):
        result = create_detection_result("f", 0x100, ["strcpy", "strcat"], "import")
        assert isinstance(result.banned_calls, tuple)


# ===========================================================================
# application/dto_mappers.py – function_descriptor_to_dto
# ===========================================================================


class TestFunctionDescriptorToDto:
    """function_descriptor_to_dto converts a FunctionDescriptor entity to a dict."""

    def test_returns_dict_with_expected_keys(self):
        entity = FunctionDescriptor(name="main", address=0x1000, size=64)
        dto = function_descriptor_to_dto(entity)
        assert set(dto.keys()) == {"name", "offset", "size"}

    def test_name_is_preserved(self):
        entity = FunctionDescriptor(name="helper", address=0x2000, size=32)
        dto = function_descriptor_to_dto(entity)
        assert dto["name"] == "helper"

    def test_address_mapped_to_offset_key(self):
        entity = FunctionDescriptor(name="f", address=0x401000, size=0)
        dto = function_descriptor_to_dto(entity)
        assert dto["offset"] == 0x401000

    def test_size_is_preserved(self):
        entity = FunctionDescriptor(name="f", address=0, size=128)
        dto = function_descriptor_to_dto(entity)
        assert dto["size"] == 128

    def test_roundtrip_descriptor_through_dto(self):
        entity = FunctionDescriptor(name="roundtrip", address=0xFF00, size=50)
        dto = function_descriptor_to_dto(entity)
        recovered = function_descriptor_from_dto(
            {"name": dto["name"], "offset": dto["offset"], "size": dto["size"]}
        )
        assert recovered.name == entity.name
        assert recovered.address == entity.address
        assert recovered.size == entity.size


# ===========================================================================
# application/dto_mappers.py – detection_entity_from_dto
# ===========================================================================


class TestDetectionEntityFromDto:
    """detection_entity_from_dto converts a raw dict or BannedFunction into a domain entity."""

    def test_passthrough_when_already_banned_function(self):
        entity = _make_banned_function()
        result = detection_entity_from_dto(entity)
        assert result is entity

    def test_converts_dict_to_banned_function(self):
        raw = {
            "name": "strcpy",
            "address": 0x401000,
            "size": 32,
            "banned_functions": ["strcpy"],
            "type": "string_copy",
            "detection_method": "import",
        }
        result = detection_entity_from_dto(raw)
        assert isinstance(result, BannedFunction)

    def test_name_extracted_from_dict(self):
        raw = {
            "name": "vuln_func",
            "address": 0x100,
            "banned_functions": [],
            "detection_method": "name",
        }
        result = detection_entity_from_dto(raw)
        assert result.name == "vuln_func"

    def test_missing_name_defaults_to_unknown(self):
        raw = {"address": 0x100, "banned_functions": [], "detection_method": "name"}
        result = detection_entity_from_dto(raw)
        assert result.name == "unknown"

    def test_address_parsed_from_hex_string(self):
        raw = {
            "name": "f",
            "address": "0x401000",
            "banned_functions": [],
            "detection_method": "import",
        }
        result = detection_entity_from_dto(raw)
        assert result.address == 0x401000

    def test_address_defaults_to_zero_when_absent(self):
        raw = {"name": "f", "banned_functions": [], "detection_method": "import"}
        result = detection_entity_from_dto(raw)
        assert result.address == 0

    def test_banned_calls_populated_from_banned_functions_key(self):
        raw = {
            "name": "f",
            "address": 0,
            "banned_functions": ["strcpy", "gets"],
            "detection_method": "import",
        }
        result = detection_entity_from_dto(raw)
        assert result.banned_calls == ("strcpy", "gets")

    def test_banned_calls_empty_when_key_absent(self):
        raw = {"name": "f", "address": 0, "detection_method": "import"}
        result = detection_entity_from_dto(raw)
        assert result.banned_calls == ()

    def test_category_taken_from_type_key(self):
        raw = {
            "name": "f",
            "address": 0,
            "banned_functions": [],
            "type": "memory",
            "detection_method": "import",
        }
        result = detection_entity_from_dto(raw)
        assert result.category == "memory"

    def test_category_is_none_when_type_is_not_string(self):
        raw = {
            "name": "f",
            "address": 0,
            "banned_functions": [],
            "type": 42,
            "detection_method": "import",
        }
        result = detection_entity_from_dto(raw)
        assert result.category is None

    def test_category_is_none_when_type_absent(self):
        raw = {
            "name": "f",
            "address": 0,
            "banned_functions": [],
            "detection_method": "import",
        }
        result = detection_entity_from_dto(raw)
        assert result.category is None

    def test_detection_method_from_detection_method_key(self):
        raw = {
            "name": "f",
            "address": 0,
            "banned_functions": [],
            "detection_method": "decompilation",
        }
        result = detection_entity_from_dto(raw)
        assert result.detection_method == "decompilation"

    def test_detection_method_falls_back_to_match_type_key(self):
        raw = {
            "name": "f",
            "address": 0,
            "banned_functions": [],
            "match_type": "string",
        }
        result = detection_entity_from_dto(raw)
        assert result.detection_method == "string"

    def test_detection_method_defaults_to_unknown_when_absent(self):
        raw = {"name": "f", "address": 0, "banned_functions": []}
        result = detection_entity_from_dto(raw)
        assert result.detection_method == "unknown"

    def test_non_string_items_in_banned_functions_are_filtered(self):
        # The mapper filters with isinstance(call, str)
        raw = {
            "name": "f",
            "address": 0,
            "banned_functions": ["strcpy", 42, None, "gets"],
            "detection_method": "import",
        }
        result = detection_entity_from_dto(raw)
        assert result.banned_calls == ("strcpy", "gets")

    def test_size_extracted_from_dict(self):
        raw = {
            "name": "f",
            "address": 0,
            "size": 256,
            "banned_functions": [],
            "detection_method": "import",
        }
        result = detection_entity_from_dto(raw)
        assert result.size == 256

    def test_size_defaults_to_zero_when_absent(self):
        raw = {
            "name": "f",
            "address": 0,
            "banned_functions": [],
            "detection_method": "import",
        }
        result = detection_entity_from_dto(raw)
        assert result.size == 0


# ===========================================================================
# application/dto_mappers.py – detection_entity_to_dto
# ===========================================================================


class TestDetectionEntityToDto:
    """detection_entity_to_dto serialises a BannedFunction into a dict."""

    def test_returns_dict(self):
        entity = _make_banned_function()
        dto = detection_entity_to_dto(entity)
        assert isinstance(dto, dict)

    def test_expected_keys_present(self):
        entity = _make_banned_function()
        dto = detection_entity_to_dto(entity)
        assert set(dto.keys()) == {"name", "address", "banned_functions", "match_type"}

    def test_name_preserved(self):
        entity = _make_banned_function(name="gets")
        dto = detection_entity_to_dto(entity)
        assert dto["name"] == "gets"

    def test_address_preserved(self):
        entity = _make_banned_function(address=0xDEAD)
        dto = detection_entity_to_dto(entity)
        assert dto["address"] == 0xDEAD

    def test_banned_functions_is_list(self):
        entity = _make_banned_function(banned_calls=("strcpy", "strcat"))
        dto = detection_entity_to_dto(entity)
        assert dto["banned_functions"] == ["strcpy", "strcat"]

    def test_match_type_is_detection_method(self):
        entity = _make_banned_function(detection_method="decompilation")
        dto = detection_entity_to_dto(entity)
        assert dto["match_type"] == "decompilation"

    def test_empty_banned_calls_produces_empty_list(self):
        entity = _make_banned_function(banned_calls=())
        dto = detection_entity_to_dto(entity)
        assert dto["banned_functions"] == []

    def test_roundtrip_via_from_dto(self):
        original = _make_banned_function(
            name="sprintf",
            address=0x5000,
            banned_calls=("sprintf",),
            detection_method="import",
            category="string_format",
        )
        dto = detection_entity_to_dto(original)
        # Re-inject type so round-trip restores category
        dto["type"] = original.category
        recovered = detection_entity_from_dto(dto)
        assert recovered.name == original.name
        assert recovered.address == original.address
        assert recovered.detection_method == original.detection_method
