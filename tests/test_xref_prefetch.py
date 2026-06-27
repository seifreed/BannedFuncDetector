"""Tests for batched ``axffj`` prefetch and its transparent r2 wrapper."""

import json

from bannedfuncdetector.application.binary_analyzer.xref_prefetch import (
    CachedAxffjClient,
    prefetch_axffj,
)
from bannedfuncdetector.application.function_detection_runtime import (
    _with_prefetched_xrefs,
)
from bannedfuncdetector.application.dto_mappers import function_descriptor_from_dto
from bannedfuncdetector.application.internal import FunctionScanPlan
from bannedfuncdetector.application.binary_analyzer.xref_prefetch import _SEP


class _BatchR2:
    """Fake r2 that emulates ``axffj``/``?e`` from a per-address ref map.

    ``refs`` maps the stringified address to its ``axffj`` payload. A value of
    ``None`` emits no output for that address (the genuinely-empty case).
    """

    def __init__(self, refs):
        self._refs = refs
        self.cmd_calls = 0
        self.cmdj_calls = []

    def cmd(self, command):
        self.cmd_calls += 1
        out = []
        for line in command.split("\n"):
            line = line.strip()
            if line.startswith("axffj @"):
                addr = line.split("@", 1)[1].strip()
                payload = self._refs.get(addr)
                if payload is not None:
                    out.append(json.dumps(payload))
            elif line.startswith("?e "):
                out.append(line[3:])
        return "\n".join(out) + "\n"

    def cmdj(self, command):
        self.cmdj_calls.append(command)
        if command.startswith("axffj @"):
            return self._refs.get(command.split("@", 1)[1].strip(), [])
        return None

    def quit(self):
        self.quit_called = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.exit_called = True
        return False


def test_prefetch_empty_addresses_returns_empty():
    assert prefetch_axffj(_BatchR2({}), []) == {}


def test_prefetch_round_trips_each_address():
    refs = {"4096": [{"name": "sym.imp.strcpy"}], "8192": []}
    r2 = _BatchR2(refs)
    cache = prefetch_axffj(r2, [4096, 8192])
    assert cache == {
        "axffj @ 4096": [{"name": "sym.imp.strcpy"}],
        "axffj @ 8192": [],
    }
    # Every address was served by a single batched cmd, not per-address cmdj.
    assert r2.cmd_calls == 1
    assert r2.cmdj_calls == []


def test_prefetch_treats_empty_segment_as_no_refs():
    r2 = _BatchR2({"4096": None})
    cache = prefetch_axffj(r2, [4096])
    assert cache == {"axffj @ 4096": []}


def test_prefetch_bails_when_sentinel_absent():
    class NoSep:
        def cmd(self, command):
            return "no separator here"

    assert prefetch_axffj(NoSep(), [1, 2]) == {}


def test_prefetch_bails_on_truncated_output():
    class OneSep:
        def cmd(self, command):
            return f"[]\n{_SEP}\n"  # one separator for a two-command batch

    assert prefetch_axffj(OneSep(), [1, 2]) == {}


def test_prefetch_degrades_when_cmd_raises_io_error():
    class Boom:
        def cmd(self, command):
            raise OSError("r2 pipe broke")

    assert prefetch_axffj(Boom(), [1, 2]) == {}


def test_prefetch_bails_on_bad_json():
    class BadJson:
        def cmd(self, command):
            return f"not-json\n{_SEP}\n"

    assert prefetch_axffj(BadJson(), [1]) == {}


def test_prefetch_spans_multiple_batches():
    addrs = list(range(10_000_000, 10_000_400))  # long enough to exceed one batch
    refs = {str(a): [] for a in addrs}
    r2 = _BatchR2(refs)
    cache = prefetch_axffj(r2, addrs)
    assert len(cache) == len(addrs)
    assert r2.cmd_calls > 1  # proves the batch boundary was crossed


def test_cached_client_serves_hits_and_delegates_misses():
    inner = _BatchR2({"4096": [{"name": "x"}]})
    client = CachedAxffjClient(inner, {"axffj @ 4096": [{"name": "cached"}]})
    assert client.cmdj("axffj @ 4096") == [{"name": "cached"}]  # hit, no delegation
    assert inner.cmdj_calls == []
    assert client.cmdj("aflj") is None  # miss -> delegated
    assert inner.cmdj_calls == ["aflj"]


def test_cached_client_delegates_cmd_quit_and_context():
    inner = _BatchR2({})
    client = CachedAxffjClient(inner, {})
    client.cmd("aaa")
    assert inner.cmd_calls == 1
    client.quit()
    assert inner.quit_called is True
    with client as ctx:
        assert ctx is client
    assert inner.exit_called is True


def _plan(skip_analysis=False):
    return FunctionScanPlan(
        verbose=False,
        worker_limit=1,
        decompiler_type="default",
        config=object(),
        skip_banned=False,
        skip_analysis=skip_analysis,
    )


def test_with_prefetched_xrefs_skips_when_analysis_disabled():
    r2 = _BatchR2({})
    funcs = [function_descriptor_from_dto({"name": "f", "offset": 4096})]
    assert _with_prefetched_xrefs(r2, funcs, _plan(skip_analysis=True)) is r2


def test_with_prefetched_xrefs_skips_empty_function_list():
    r2 = _BatchR2({})
    assert _with_prefetched_xrefs(r2, [], _plan()) is r2


def test_with_prefetched_xrefs_skips_non_descriptor_functions():
    r2 = _BatchR2({})
    assert _with_prefetched_xrefs(r2, [{"name": "f"}], _plan()) is r2


def test_with_prefetched_xrefs_skips_when_cache_empty():
    class NoSep:
        def cmd(self, command):
            return ""

    r2 = NoSep()
    funcs = [function_descriptor_from_dto({"name": "f", "offset": 4096})]
    assert _with_prefetched_xrefs(r2, funcs, _plan()) is r2


def test_with_prefetched_xrefs_wraps_when_cache_built():
    r2 = _BatchR2({"4096": [{"name": "sym.imp.strcpy"}]})
    funcs = [function_descriptor_from_dto({"name": "f", "offset": 4096})]
    wrapped = _with_prefetched_xrefs(r2, funcs, _plan())
    assert isinstance(wrapped, CachedAxffjClient)
    assert wrapped.cmdj("axffj @ 4096") == [{"name": "sym.imp.strcpy"}]
