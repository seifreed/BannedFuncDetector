#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DTOs used at integration and adapter boundaries."""

from typing import TypedDict


class DetectionResultDTO(TypedDict, total=False):
    """Serialized detection payload crossing adapter boundaries."""

    name: str
    address: int | str
    banned_functions: list[str]
    detection_method: str
    match_type: str
    decompiler: str
    size: int
    type: str
    string: str


class FunctionInfoDTO(TypedDict, total=False):
    """Serialized function metadata returned by binary analysis adapters."""

    name: str
    offset: int
    size: int


__all__ = [
    "DetectionResultDTO",
    "FunctionInfoDTO",
]
