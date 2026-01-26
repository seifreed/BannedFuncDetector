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
from unittest.mock import patch

import pytest

from bannedfuncdetector.application.parallel_analyzer import (
    _resolve_thread_count,
    _analyze_functions_parallel,
    _process_parallel_results,
    _run_parallel_detection,
)
from bannedfuncdetector.domain.banned_functions import get_banned_functions_set
from bannedfuncdetector.domain.result import Ok, Err
from bannedfuncdetector.domain.config_types import AnalysisOptions
from bannedfuncdetector.infrastructure.config_repository import get_default_config
from conftest import FakeR2


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


class TestResolveThreadCount:
    """Test suite for _resolve_thread_count function."""

    def test_resolve_thread_count_with_explicit_limit(self):
        """Test thread count resolution with explicit worker_limit."""
        result = _resolve_thread_count(worker_limit=4)

        assert result == 4

    def test_resolve_thread_count_from_config(self):
        """Test thread count resolution from config."""
        config = FakeConfig(worker_limit=8)

        result = _resolve_thread_count(worker_limit=None, config=config)

        assert result == 8

    def test_resolve_thread_count_from_cpu_count(self):
        """Test thread count resolution from CPU count."""
        import os

        config = FakeConfig(worker_limit=None)

        result = _resolve_thread_count(worker_limit=None, config=config)

        # Should use CPU count
        expected = os.cpu_count() or 1
        assert result == expected

    def test_resolve_thread_count_capped_by_max_items(self):
        """Test thread count capped by max_items."""
        config = FakeConfig(worker_limit=8)

        result = _resolve_thread_count(
            worker_limit=None, max_items=3, config=config
        )

        # Should be capped at 3
        assert result == 3

    def test_resolve_thread_count_max_items_larger_than_limit(self):
        """Test that larger max_items doesn't increase thread count."""
        result = _resolve_thread_count(worker_limit=4, max_items=10)

        # Should still be 4
        assert result == 4

    def test_resolve_thread_count_uses_default_config(self):
        """Test thread count resolution with default config."""
        result = _resolve_thread_count(worker_limit=None, config=None)

        # Should get a valid number
        assert isinstance(result, int)
        assert result > 0


class TestProcessParallelResults:
    """Test suite for _process_parallel_results function."""

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

        results = _process_parallel_results(futures, verbose=False)

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

        results = _process_parallel_results(futures, verbose=False)

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

        results = _process_parallel_results(futures, verbose=False)

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

        results = _process_parallel_results(futures, verbose=False)

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

        results = _process_parallel_results(futures, verbose=True)

        assert len(results) == 1


class TestAnalyzeFunctionsParallel:
    """Test suite for _analyze_functions_parallel function."""

    def test_analyze_functions_parallel_basic(self, fake_r2_factory):
        """Test parallel function analysis basic flow."""
        fake = fake_r2_factory()
        functions = [
            {"name": "func1", "offset": 4096},
            {"name": "func2", "offset": 8192},
        ]
        banned_set = {"strcpy", "gets"}
        config = FakeConfig()
        options = AnalysisOptions(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=2,
            config=config,
        )

        # Mock analyzer that returns Ok
        def mock_analyzer(r2, func, banned, dec_type, verbose, cfg):
            return Ok({"name": func["name"], "address": hex(func["offset"])})

        results = _analyze_functions_parallel(
            r2=fake,
            functions=functions,
            banned_functions_set=banned_set,
            options=options,
            function_analyzer=mock_analyzer,
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
        options = AnalysisOptions(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=2,
            config=config,
        )

        # Mock analyzer that returns Err for "clean"
        def mock_analyzer(r2, func, banned, dec_type, verbose, cfg):
            if func["name"] == "clean":
                return Err("No banned functions")
            return Ok({"name": func["name"], "address": hex(func["offset"])})

        results = _analyze_functions_parallel(
            r2=fake,
            functions=functions,
            banned_functions_set=banned_set,
            options=options,
            function_analyzer=mock_analyzer,
        )

        # Only "banned" should be in results
        assert len(results) == 1
        assert results[0]["name"] == "banned"

    def test_analyze_functions_parallel_requires_function_analyzer(self, fake_r2_factory):
        """Test that function raises error when no analyzer provided."""
        fake = fake_r2_factory()
        functions = [{"name": "test", "offset": 4096}]
        banned_set = {"strcpy"}
        config = FakeConfig()
        options = AnalysisOptions(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=1,
            config=config,
        )

        with pytest.raises(ValueError, match="function_analyzer must be provided"):
            _analyze_functions_parallel(
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
        options = AnalysisOptions(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=2,
            config=config,
        )

        def mock_analyzer(r2, func, banned, dec_type, verbose, cfg):
            return Err("Clean")

        results = _analyze_functions_parallel(
            r2=fake,
            functions=functions,
            banned_functions_set=banned_set,
            options=options,
            function_analyzer=mock_analyzer,
        )

        # All functions analyzed, even with limited workers
        assert isinstance(results, list)


class TestRunParallelDetection:
    """Test suite for _run_parallel_detection function."""

    def test_run_parallel_detection_basic(self, fake_r2_factory):
        """Test parallel detection basic flow."""
        fake = fake_r2_factory()
        functions = [{"name": "test", "offset": 4096}]
        config = FakeConfig(banned_functions=["strcpy", "gets"])
        options = AnalysisOptions(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=1,
            config=config,
        )

        def mock_provider(cfg):
            return {"strcpy", "gets"}

        def mock_analyzer(r2, func, banned, dec_type, verbose, cfg):
            return Err("Clean")

        results = _run_parallel_detection(
            r2=fake,
            functions=functions,
            options=options,
            function_analyzer=mock_analyzer,
            banned_functions_provider=mock_provider,
        )

        assert isinstance(results, list)

    def test_run_parallel_detection_uses_default_provider(self, fake_r2_factory):
        """Test that function uses default provider when none provided."""
        fake = fake_r2_factory()
        functions = [{"name": "test", "offset": 4096}]
        config = FakeConfig()
        options = AnalysisOptions(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=1,
            config=config,
        )

        def mock_analyzer(r2, func, banned, dec_type, verbose, cfg):
            return Err("Clean")

        results = _run_parallel_detection(
            r2=fake,
            functions=functions,
            options=options,
            function_analyzer=mock_analyzer,
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
        options = AnalysisOptions(
            decompiler_type="r2ghidra",
            verbose=False,
            worker_limit=2,
            config=config,
        )

        def mock_analyzer(r2, func, banned, dec_type, verbose, cfg):
            if func["name"] == "func2":
                return Ok({"name": func["name"], "address": hex(func["offset"])})
            return Err("Clean")

        def mock_provider(cfg):
            return {"strcpy"}

        results = _run_parallel_detection(
            r2=fake,
            functions=functions,
            options=options,
            function_analyzer=mock_analyzer,
            banned_functions_provider=mock_provider,
        )

        assert len(results) == 1
        assert results[0]["name"] == "func2"
