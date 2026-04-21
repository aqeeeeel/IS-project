from __future__ import annotations

import hashlib
import hmac
from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]


def _to_bytes(value: bytes | str | BytesLike) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError("Value must be bytes-like or str")


def sha256_hex(value: bytes | str | BytesLike) -> str:
    return hashlib.sha256(_to_bytes(value)).hexdigest()


def blake2b_hex(value: bytes | str | BytesLike, *, digest_size: int = 32) -> str:
    return hashlib.blake2b(_to_bytes(value), digest_size=digest_size).hexdigest()


def hmac_sha256_hex(key: bytes | str | BytesLike, message: bytes | str | BytesLike) -> str:
    return hmac.new(_to_bytes(key), _to_bytes(message), digestmod=hashlib.sha256).hexdigest()


def compare_digest(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
