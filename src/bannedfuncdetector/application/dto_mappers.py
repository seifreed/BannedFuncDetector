"""DTO-to-domain and domain-to-DTO mapping helpers."""

from __future__ import annotations

from typing import Any

from bannedfuncdetector.domain import BannedFunction, FunctionDescriptor
from bannedfuncdetector.domain.types import safe_parse_address


def function_dto_name(func: dict[str, Any]) -> str:
    """Return a normalized function name from a raw payload."""
    return str(func.get("name") or "unknown")


def function_dto_offset(func: dict[str, Any]) -> int:
    """Return a normalized integer offset from a raw payload."""
    offset = func.get("offset", func.get("addr", 0))
    return safe_parse_address(offset)


def function_dto_size(func: dict[str, Any]) -> int:
    """Return a normalized function size from a raw payload."""
    return int(func.get("size", 0))


def function_descriptor_from_dto(raw: dict[str, Any]) -> FunctionDescriptor:
    """Convert a raw adapter payload into a domain function descriptor."""
    return FunctionDescriptor(
        name=function_dto_name(raw),
        address=function_dto_offset(raw),
        size=function_dto_size(raw),
    )


def function_descriptor_to_dto(entity: FunctionDescriptor) -> dict[str, object]:
    """Convert a domain function descriptor into the adapter shape."""
    return {
        "name": entity.name,
        "offset": entity.address,
        "size": entity.size,
    }


def detection_entity_from_dto(detection: BannedFunction | dict[str, object]) -> BannedFunction:
    """Convert a raw detection payload into a domain detection entity."""
    if isinstance(detection, BannedFunction):
        return detection

    address = detection.get("address", 0)
    parsed_address = safe_parse_address(address)
    banned_calls_raw = detection.get("banned_functions", [])
    if isinstance(banned_calls_raw, list):
        banned_calls = tuple(str(call) for call in banned_calls_raw if isinstance(call, str))
    else:
        banned_calls = ()
    category = detection.get("type")
    detection_method = detection.get("detection_method", detection.get("match_type", "unknown"))
    return BannedFunction(
        name=str(detection.get("name", "unknown")),
        address=parsed_address,
        size=safe_parse_address(detection.get("size", 0)),
        banned_calls=banned_calls,
        detection_method=str(detection_method),
        category=str(category) if isinstance(category, str) else None,
    )


def detection_entity_to_dto(entity: BannedFunction) -> dict[str, object]:
    """Convert a domain detection entity into the adapter shape."""
    return {
        "name": entity.name,
        "address": entity.address,
        "banned_functions": list(entity.banned_calls),
        "match_type": entity.detection_method,
    }


__all__ = [
    "detection_entity_from_dto",
    "detection_entity_to_dto",
    "function_descriptor_from_dto",
    "function_descriptor_to_dto",
    "function_dto_name",
    "function_dto_offset",
    "function_dto_size",
]
