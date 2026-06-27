"""Batched prefetch of per-function ``axffj`` cross-references.

The xref detection path queries ``axffj @ addr`` once per function. Each query
is a separate r2pipe round-trip, so on a binary with tens of thousands of
functions the inter-process I/O dominates analysis time.

radare2 runs several commands from a single newline-joined string in one
round-trip. This module batches the per-function queries and splits the
concatenated output on a sentinel line emitted (``?e``) between each result.
The data is identical to issuing the queries one at a time -- same command,
same order -- just with ~100x fewer round-trips.

Results are exposed through :class:`CachedAxffjClient`, a transparent
``IR2Client`` wrapper that serves the prefetched ``axffj`` results and
delegates every other command unchanged. Prefetch falls back to an empty map
on any unexpected output, so callers revert to per-function queries with no
behavioural difference.
"""

import json
import logging
from collections.abc import Iterator, Sequence
from typing import Any

from bannedfuncdetector.domain.protocols import IR2Client

logger = logging.getLogger(__name__)

_SEP = "__BFD_AXFFJ_SEP__"
_SEP_CMD = f"?e {_SEP}"
# r2pipe truncates a single command string beyond ~4KB; keep batches well under.
_MAX_BATCH_BYTES = 3000


def _axffj_cmd(addr: Any) -> str:
    """The exact ``axffj`` command the per-function path issues for ``addr``."""
    return f"axffj @ {addr}"


def _batches(addrs: Sequence[Any], max_bytes: int) -> Iterator[list[Any]]:
    """Group addresses so each joined command string stays under ``max_bytes``."""
    chunk: list[Any] = []
    size = 0
    for addr in addrs:
        piece_len = len(f"{_axffj_cmd(addr)}\n{_SEP_CMD}\n")
        if chunk and size + piece_len > max_bytes:
            yield chunk
            chunk, size = [], 0
        chunk.append(addr)
        size += piece_len
    if chunk:
        yield chunk


def prefetch_axffj(r2: IR2Client, addrs: Sequence[Any]) -> dict[str, Any]:
    """Return ``{axffj-command: refs}`` for every address, fetched in batches.

    Returns an empty map (so callers fall back to per-function queries) when
    there are no addresses or the batched output cannot be parsed -- e.g. a
    client that does not understand the sentinel batch.
    """
    if not addrs:
        return {}
    cache: dict[str, Any] = {}
    try:
        for chunk in _batches(addrs, _MAX_BATCH_BYTES):
            joined = "\n".join(f"{_axffj_cmd(a)}\n{_SEP_CMD}" for a in chunk)
            out = r2.cmd(joined)
            if not out or _SEP not in out:
                return {}
            # A complete batch emits one sentinel per command, so splitting
            # yields len(chunk)+1 segments (a trailing piece after the last
            # sentinel). Fewer means the output was truncated mid-batch.
            segments = out.split(_SEP)
            if len(segments) <= len(chunk):
                return {}
            for addr, segment in zip(chunk, segments):
                text = segment.strip()
                cache[_axffj_cmd(addr)] = json.loads(text) if text else []
    except (ValueError, TypeError, AttributeError, OSError, IOError) as exc:
        logger.debug("axffj prefetch failed, falling back to per-function: %s", exc)
        return {}
    return cache


class CachedAxffjClient:
    """``IR2Client`` wrapper serving prefetched ``axffj`` results from a cache.

    Every command other than the cached ``axffj`` queries delegates to the
    wrapped client unchanged.
    """

    def __init__(self, inner: IR2Client, cache: dict[str, Any]) -> None:
        self._inner = inner
        self._cache = cache

    def cmd(self, command: str) -> str:
        return self._inner.cmd(command)

    def cmdj(self, command: str) -> Any:
        if command in self._cache:
            return self._cache[command]
        return self._inner.cmdj(command)

    def quit(self) -> None:
        self._inner.quit()

    def __enter__(self) -> "CachedAxffjClient":
        return self

    def __exit__(
        self, exc_type: type | None, exc_val: BaseException | None, exc_tb: Any | None
    ) -> None:
        self._inner.__exit__(exc_type, exc_val, exc_tb)


__all__ = ["prefetch_axffj", "CachedAxffjClient"]
