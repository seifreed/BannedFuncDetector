"""Detection helpers for banned-function analysis."""

import logging
from typing import Any

from bannedfuncdetector.domain import BannedFunction, FunctionDescriptor
from bannedfuncdetector.domain.protocols import IR2Client
from bannedfuncdetector.domain.result import Result, ok, err
from bannedfuncdetector.domain.banned_functions import BANNED_FUNCTIONS
from bannedfuncdetector.domain.types import (
    create_detection_result as _create_detection_result,
    find_banned_calls_in_text,
    find_banned_names_in_text,
)

logger = logging.getLogger(__name__)


def _find_banned_in_name(text: str, banned_functions: set[str]) -> list[str]:
    """Return banned functions matching ``text`` by bare name (word-boundary)."""
    return find_banned_names_in_text(text, banned_functions)


def _find_banned_in_code(text: str, banned_functions: set[str]) -> list[str]:
    """Return banned functions found in decompiled code by call site."""
    return find_banned_calls_in_text(text, banned_functions)


def _validate_analysis_inputs(
    func: FunctionDescriptor | None, banned_functions: set[str] | None
) -> Result[set[str], str]:
    """Validate and normalize inputs for function analysis."""
    if func is None:
        return err("Function descriptor cannot be None")

    normalized = banned_functions or BANNED_FUNCTIONS
    # Return the set directly; callers treat it as read-only.
    return ok(normalized if isinstance(normalized, set) else set(normalized))


def _check_function_name_banned(
    func_name: str, func_addr: Any, banned_functions: set[str], verbose: bool = False
) -> Result[BannedFunction, str]:
    """Check whether the function name itself matches a banned symbol."""
    detected_banned = _find_banned_in_name(func_name, banned_functions)

    if detected_banned:
        if verbose:
            logger.info(f"Insecure function detected by name: {func_name}")
        return ok(
            _create_detection_result(func_name, func_addr, detected_banned, "name")
        )
    return err(f"No banned functions found in name: {func_name}")


_R2_SYMBOL_PREFIXES = ("sym.imp.", "sym.", "imp.", "reloc.", "flirt.", "loc.", "fcn.")


def _strip_r2_symbol_prefix(name: str) -> str:
    """Reduce an r2 flag name (``sym.imp.strcpy``) to its bare symbol (``strcpy``)."""
    for prefix in _R2_SYMBOL_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


def _xref_callee_names(r2: IR2Client, func_addr: Any) -> list[str]:
    """Bare names of every symbol the function at ``func_addr`` references."""
    if r2 is None:
        return []
    refs = r2.cmdj(f"axffj @ {func_addr}")
    if not isinstance(refs, list):
        return []
    names: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        name = ref.get("name")
        if isinstance(name, str) and name:
            names.append(_strip_r2_symbol_prefix(name))
    return names


def _find_banned_calls_via_xref(
    r2: IR2Client,
    func_name: str,
    func_addr: Any,
    banned_functions: set[str],
    verbose: bool = False,
) -> Result[BannedFunction, str]:
    """Detect banned calls from a function's cross-references (``axffj``).

    Works on stripped/Go binaries where decompilation is unreliable: r2 resolves
    call targets to symbol names directly, so we match those against the banned
    set instead of regexing recovered C.
    """
    callees = _xref_callee_names(r2, func_addr)
    if not callees:
        return err(f"No cross-references found for {func_name}")

    # Reuse the call-site matcher by synthesizing one call per callee; keeps
    # detection semantics identical to the old decompiled-text path.
    # ponytail: misses fortified wrappers (__strcpy_chk vs strcpy), same gap the
    # text path had; add wrapper-stripping if those need flagging.
    synthetic_calls = "\n".join(f"{name}(" for name in callees)
    detected_banned = _find_banned_in_code(synthetic_calls, banned_functions)

    if detected_banned:
        if verbose:
            logger.info(f"Insecure function detected via xrefs: {func_name}")
        return ok(
            _create_detection_result(func_name, func_addr, detected_banned, "xref")
        )
    return err(f"No banned functions found in xrefs: {func_name}")


__all__: list[str] = []  # internal module; use explicit imports
