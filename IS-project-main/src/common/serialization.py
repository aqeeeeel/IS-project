from __future__ import annotations

import base64
import json
from dataclasses import fields, is_dataclass
from enum import Enum
from typing import Any, TypeVar, get_args, get_origin

T = TypeVar("T")


def to_primitive(value: Any) -> Any:
    if is_dataclass(value):
        return {field.name: to_primitive(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): to_primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_primitive(item) for item in value]
    return value


def to_json(value: Any, *, indent: int = 2) -> str:
    return json.dumps(to_primitive(value), indent=indent, sort_keys=True)


def _deserialize_value(expected_type: Any, value: Any) -> Any:
    origin = get_origin(expected_type)

    if value is None:
        return None

    if origin is None:
        if isinstance(expected_type, type) and issubclass(expected_type, Enum):
            return expected_type(value)
        if isinstance(expected_type, type) and is_dataclass(expected_type):
            return from_dict(value, expected_type)
        return value

    if origin in (list, tuple, set):
        (inner_type,) = get_args(expected_type) if get_args(expected_type) else (Any,)
        items = [_deserialize_value(inner_type, item) for item in value]
        if origin is tuple:
            return tuple(items)
        if origin is set:
            return set(items)
        return items

    if origin is dict:
        args = get_args(expected_type)
        value_type = args[1] if len(args) == 2 else Any
        return {str(k): _deserialize_value(value_type, v) for k, v in value.items()}

    if origin is type(None):
        return None

    if origin is Any:
        return value

    # Handle Optional[T] and Union types by trying each variant.
    if origin.__name__ == "Union" or str(origin) == "types.UnionType":
        for variant in get_args(expected_type):
            if variant is type(None) and value is None:
                return None
            try:
                return _deserialize_value(variant, value)
            except (TypeError, ValueError):
                continue
        return value

    return value


def from_dict(data: dict[str, Any], cls: type[T]) -> T:
    kwargs: dict[str, Any] = {}
    for field in fields(cls):
        if field.name not in data:
            continue
        kwargs[field.name] = _deserialize_value(field.type, data[field.name])
    return cls(**kwargs)


def from_json(payload: str, cls: type[T]) -> T:
    raw = json.loads(payload)
    if not isinstance(raw, dict):
        raise TypeError("JSON payload must decode to a dictionary for dataclass conversion")
    return from_dict(raw, cls)


def bytes_to_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64_to_bytes(encoded: str) -> bytes:
    return base64.b64decode(encoded.encode("ascii"))
