from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from .hashing import compare_digest, hmac_sha256_hex


def generate_nonce(size_bytes: int = 16) -> str:
    if size_bytes <= 0:
        raise ValueError("size_bytes must be positive")
    raw = secrets.token_bytes(size_bytes)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _canonical_auth_material(nonce: str, timestamp: int, payload_b64: str) -> bytes:
    return f"{nonce}|{timestamp}|{payload_b64}".encode("utf-8")


def _payload_to_b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _b64_to_payload(payload_b64: str) -> bytes:
    return base64.b64decode(payload_b64.encode("ascii"))


@dataclass(slots=True)
class NonceTracker:
    ttl_seconds: int = 300
    _seen: dict[str, int] = field(init=False, repr=False, default_factory=dict)

    def __post_init__(self) -> None:
        if self.ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

    def _purge_expired(self, now: int) -> None:
        cutoff = now - self.ttl_seconds
        expired = [nonce for nonce, ts in self._seen.items() if ts < cutoff]
        for nonce in expired:
            del self._seen[nonce]

    def mark_if_fresh(self, nonce: str, *, now: int | None = None) -> bool:
        timestamp = int(now if now is not None else time.time())
        self._purge_expired(timestamp)
        if nonce in self._seen:
            return False
        self._seen[nonce] = timestamp
        return True


def build_authenticated_message(
    payload: bytes,
    key: bytes,
    *,
    nonce: str | None = None,
    timestamp: int | None = None,
) -> dict[str, Any]:
    used_nonce = nonce if nonce is not None else generate_nonce()
    used_timestamp = int(timestamp if timestamp is not None else time.time())
    payload_b64 = _payload_to_b64(payload)
    material = _canonical_auth_material(used_nonce, used_timestamp, payload_b64)
    tag = hmac_sha256_hex(key, material)
    return {
        "nonce": used_nonce,
        "timestamp": used_timestamp,
        "payload_b64": payload_b64,
        "tag": tag,
    }


def verify_authenticated_message(
    message: Mapping[str, Any],
    key: bytes,
    *,
    max_age_seconds: int | None = None,
    nonce_tracker: NonceTracker | None = None,
    now: int | None = None,
) -> tuple[bool, bytes | None]:
    try:
        nonce = str(message["nonce"])
        timestamp = int(message["timestamp"])
        payload_b64 = str(message["payload_b64"])
        received_tag = str(message["tag"])
    except (KeyError, TypeError, ValueError):
        return False, None

    material = _canonical_auth_material(nonce, timestamp, payload_b64)
    expected_tag = hmac_sha256_hex(key, material)
    if not compare_digest(received_tag, expected_tag):
        return False, None

    reference_time = int(now if now is not None else time.time())
    if max_age_seconds is not None:
        if max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be positive")
        if (reference_time - timestamp) > max_age_seconds:
            return False, None

    if nonce_tracker is not None and not nonce_tracker.mark_if_fresh(nonce, now=reference_time):
        return False, None

    try:
        payload = _b64_to_payload(payload_b64)
    except (ValueError, TypeError):
        return False, None

    return True, payload


def derive_session_key(*materials: bytes, key_size: int = 32) -> bytes:
    if key_size <= 0:
        raise ValueError("key_size must be positive")
    if not materials:
        raise ValueError("at least one key material input is required")
    digest = hashlib.sha256(b"|".join(materials)).digest()
    if key_size <= len(digest):
        return digest[:key_size]

    stream = bytearray(digest)
    counter = 1
    while len(stream) < key_size:
        stream.extend(hashlib.sha256(digest + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(stream[:key_size])


def aesgcm_encrypt_optional(plaintext: bytes, key: bytes, *, aad: bytes | None = None) -> dict[str, str]:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError("AES-GCM support requires the 'cryptography' package") from exc

    nonce = secrets.token_bytes(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext, aad)
    return {
        "mode": "aes-gcm",
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "aad_b64": base64.b64encode(aad).decode("ascii") if aad is not None else "",
    }


def aesgcm_decrypt_optional(payload: Mapping[str, str], key: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError("AES-GCM support requires the 'cryptography' package") from exc

    nonce = base64.b64decode(payload["nonce_b64"].encode("ascii"))
    ciphertext = base64.b64decode(payload["ciphertext_b64"].encode("ascii"))
    aad_raw = payload.get("aad_b64", "")
    aad = base64.b64decode(aad_raw.encode("ascii")) if aad_raw else None
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, ciphertext, aad)


def safe_json_dumps(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
