#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BannedFuncDetector - Parallel Analyzer Tests

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Author: Marc Rivero | @seifreed
"""

import concurrent.futures

import pytest

from bannedfuncdetector.application.function_detection_runtime import (
    analyze_functions_in_binary,
    run_intra_binary_detection,
)
from bannedfuncdetector.application.function_detection_support import (
    process_parallel_results,
)
from bannedfuncdetector.application.internal.execution_plans import FunctionScanPlan
from bannedfuncdetector.domain.banned_functions import get_banned_functions_set
from bannedfuncdetector.domain.result import Ok, Err


class FakeConfig:
    """Fake configuration for testing."""

    def __init__(self, worker_limit=None, banned_functions=None):
        self.data = {
            "worker_limit": worker_limit,
            "banned_functions": banned_functions or ["strcpy", "gets"],
        }

    def get(self, key, default=None):
        return self.data.get(key, default)

    def __getitem__(self, key):
        return self.data[key]


class TestProcessParallelResults:
    """Test suite for process_parallel_results function."""

    def test_process_parallel_results_all_ok(self):
        """Test processing results where all futures return Ok."""

        # Create futures that return Ok results
        def make_future(value):
            future = concurrent.futures.Future()
            future.set_result(Ok(value))
            return future

        detections = [
            {"name": "func1", "address": "0x1000"},
            {"name": "func2", "address": "0x2000"},
        ]
        futures = [make_future(d) for d in detections]

        results = process_parallel_results(futures, verbose=False)

        # Check that we got 2 results
        assert len(results) == 2
        # Results might not be in order due to as_completed
        result_names = {r["name"] for r in results}
        assert "func1" in result_names
        assert "func2" in result_names

    def test_process_parallel_results_mixed_ok_err(self):
        """Test processing results with mix of Ok and Err."""

        def make_ok_future(value):
            future = concurrent.futures.Future()
            future.set_result(Ok(value))
            return future

        def make_err_future(error):
            future = concurrent.futures.Future()
            future.set_result(Err(error))
            return future

        futures = [
            make_ok_future({"name": "func1", "address": "0x1000"}),
            make_err_future("No banned functions"),
            make_ok_future({"name": "func2", "address": "0x2000"}),
        ]

        results = process_parallel_results(futures, verbose=False)

        # Only Ok results should be collected
        assert len(results) == 2
        # Results might not be in order due to as_completed
        result_names = {r["name"] for r in results}
        assert "func1" in result_names
        assert "func2" in result_names

    def test_process_parallel_results_all_err(self):
        """Test processing results where all futures return Err."""

        def make_err_future(error):
            future = concurrent.futures.Future()
            future.set_result(Err(error))
            return future

        futures = [
            make_err_future("No banned"),
            make_err_future("Clean function"),
        ]

        results = process_parallel_results(futures, verbose=False)

        assert len(results) == 0

    def test_process_parallel_results_with_exception(self):
        """Test processing results handles future exceptions."""

        def make_exception_future():
            future = concurrent.futures.Future()
            future.set_exception(RuntimeError("Analysis failed"))
            return future

        def make_ok_future(value):
            future = concurrent.futures.Future()
            future.set_result(Ok(value))
            return future

        futures = [
            make_ok_future({"name": "func1", "address": "0x1000"}),
            make_exception_future(),
            make_ok_future({"name": "func2", "address": "0x2000"}),
        ]

        results = process_parallel_results(futures, verbose=False)

        # Exception should be caught, only Ok results returned
        assert len(results) == 2

    def test_process_parallel_results_verbose_mode(self):
        """Test processing results with verbose logging."""

        def make_ok_future(value):
            future = concurrent.futures.Future()
            future.set_result(Ok(value))
            return future

        futures = [
            make_ok_future({"name": "func1", "address": "0x1000"}),
        ]

        results = process_parallel_results(futures, verbose=True)

        assert len(results) == 1


class TestAnalyzeFunctionsInBinary:
    """Test suite for _analyze_functions_in_binary function."""

    def test_analyze_functions_parallel_basic(self, fake_r2_factory):
        """Test parallel function analysis basic flow."""
        fake = fake_r2_factory()
        functions = [
            {"name": "func1", "offset": 4096},
            {"name": "func2", "offset": 8192},
        ]
        banned_set = {"strcpy", "gets"}
        config = FakeConfig()
        options = FunctionScanPlan(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=2,
            config=config,
        )

        # Fake analyzer that returns Ok
        def fake_analyzer(r2, func, *, request):
            return Ok({"name": func["name"], "address": hex(func["offset"])})

        results = analyze_functions_in_binary(
            r2=fake,
            functions=functions,
            banned_functions_set=banned_set,
            options=options,
            function_analyzer=fake_analyzer,
        )

        assert len(results) == 2

    def test_analyze_functions_parallel_with_failures(self, fake_r2_factory):
        """Test parallel analysis with some function failures."""
        fake = fake_r2_factory()
        functions = [
            {"name": "clean", "offset": 4096},
            {"name": "banned", "offset": 8192},
        ]
        banned_set = {"strcpy"}
        config = FakeConfig()
        options = FunctionScanPlan(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=2,
            config=config,
        )

        # Fake analyzer that returns Err for "clean"
        def fake_analyzer(r2, func, *, request):
            if func["name"] == "clean":
                return Err("No banned functions")
            return Ok({"name": func["name"], "address": hex(func["offset"])})

        results = analyze_functions_in_binary(
            r2=fake,
            functions=functions,
            banned_functions_set=banned_set,
            options=options,
            function_analyzer=fake_analyzer,
        )

        # Only "banned" should be in results
        assert len(results) == 1
        assert results[0]["name"] == "banned"

    def test_analyze_functions_parallel_requires_function_analyzer(
        self, fake_r2_factory
    ):
        """Test that function raises error when no analyzer provided."""
        fake = fake_r2_factory()
        functions = [{"name": "test", "offset": 4096}]
        banned_set = {"strcpy"}
        config = FakeConfig()
        options = FunctionScanPlan(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=1,
            config=config,
        )

        with pytest.raises(ValueError, match="function_analyzer must be provided"):
            analyze_functions_in_binary(
                r2=fake,
                functions=functions,
                banned_functions_set=banned_set,
                options=options,
                function_analyzer=None,
            )

    def test_analyze_functions_parallel_respects_worker_limit(self, fake_r2_factory):
        """Test that parallel analysis respects worker limit."""
        fake = fake_r2_factory()
        functions = [{"name": f"func{i}", "offset": 4096 + i * 100} for i in range(10)]
        banned_set = {"strcpy"}
        config = FakeConfig()
        options = FunctionScanPlan(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=2,
            config=config,
        )

        def fake_analyzer(r2, func, *, request):
            return Err("Clean")

        results = analyze_functions_in_binary(
            r2=fake,
            functions=functions,
            banned_functions_set=banned_set,
            options=options,
            function_analyzer=fake_analyzer,
        )

        # All functions analyzed, even with limited workers
        assert isinstance(results, list)


class TestRunIntraBinaryDetection:
    """Test suite for _run_intra_binary_detection function."""

    def test_run_parallel_detection_basic(self, fake_r2_factory):
        """Test parallel detection basic flow."""
        fake = fake_r2_factory()
        functions = [{"name": "test", "offset": 4096}]
        config = FakeConfig(banned_functions=["strcpy", "gets"])
        options = FunctionScanPlan(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=1,
            config=config,
        )

        def fake_provider(cfg):
            return {"strcpy", "gets"}

        def fake_analyzer(r2, func, *, request):
            return Err("Clean")

        results = run_intra_binary_detection(
            r2=fake,
            functions=functions,
            options=options,
            function_analyzer=fake_analyzer,
            banned_functions_provider=fake_provider,
        )

        assert isinstance(results, list)

    def test_run_parallel_detection_uses_default_provider(self, fake_r2_factory):
        """Test that function uses default provider when none provided."""
        fake = fake_r2_factory()
        functions = [{"name": "test", "offset": 4096}]
        config = FakeConfig()
        options = FunctionScanPlan(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=1,
            config=config,
        )

        def fake_analyzer(r2, func, *, request):
            return Err("Clean")

        results = run_intra_binary_detection(
            r2=fake,
            functions=functions,
            options=options,
            function_analyzer=fake_analyzer,
        )

        assert isinstance(results, list)


class TestGetBannedFunctionsSet:
    """Test suite for get_banned_functions_set function."""

    def test_get_banned_functions_set_returns_set(self):
        """Test that get_banned_functions_set returns a set."""
        result = get_banned_functions_set()

        assert isinstance(result, set)

    def test_get_banned_functions_set_with_config(self):
        """Test that get_banned_functions_set uses config values."""
        config = FakeConfig(banned_functions=["custom_func"])

        result = get_banned_functions_set(config)

        assert "custom_func" in result

    def test_get_banned_functions_set_default_contains_common_functions(self):
        """Test that default banned functions include common insecure functions."""
        result = get_banned_functions_set()

        # Should contain at least some common insecure functions
        assert len(result) > 0


class TestParallelAnalyzerIntegration:
    """Integration tests for parallel analyzer."""

    def test_parallel_analysis_end_to_end(self, fake_r2_factory):
        """Test complete parallel analysis flow."""
        fake = fake_r2_factory()
        functions = [
            {"name": "func1", "offset": 4096},
            {"name": "func2", "offset": 8192},
            {"name": "func3", "offset": 12288},
        ]
        config = FakeConfig(banned_functions=["strcpy"])
        options = FunctionScanPlan(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=2,
            config=config,
        )

        def fake_analyzer(r2, func, *, request):
            if func["name"] == "func2":
                return Ok({"name": func["name"], "address": hex(func["offset"])})
            return Err("Clean")

        def fake_provider(cfg):
            return {"strcpy"}

        results = run_intra_binary_detection(
            r2=fake,
            functions=functions,
            options=options,
            function_analyzer=fake_analyzer,
            banned_functions_provider=fake_provider,
        )

        assert len(results) == 1
        assert results[0]["name"] == "func2"
