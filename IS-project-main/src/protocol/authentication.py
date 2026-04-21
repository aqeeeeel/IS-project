from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from time import time
from typing import Any

from common.crypto_utils import (
    NonceTracker,
    build_authenticated_message,
    derive_session_key,
    generate_nonce,
    verify_authenticated_message,
)
from common.fuzzy import repetition_decode, repetition_encode
from common.types import MatrixMetadata
from encryption.matrix_cipher import EncryptedPayload, MatrixCatalog, MatrixCipher, generate_invertible_binary_matrix, invert_binary_matrix


@dataclass(frozen=True, slots=True)
class AuthenticationChallenge:
    session_id: str
    device_id: str
    model_id: str
    challenge_id: str
    challenge_vector: list[int]
    server_nonce: str
    issued_at: int
    timeout_seconds: int
    response_bit_length: int
    server_message: dict[str, Any]
    ecc_repetition: int = 1


@dataclass(frozen=True, slots=True)
class AuthenticationReply:
    session_id: str
    device_id: str
    server_nonce: str
    device_nonce: str
    matrix_id: str
    padding_bits: int
    encrypted_response_b64: str
    device_message: dict[str, Any]


@dataclass(frozen=True, slots=True)
class AuthenticationResult:
    success: bool
    session_id: str
    device_id: str
    reason: str | None = None
    hamming_distance: int | None = None
    hamming_ratio: float | None = None
    authenticated_at: int | None = None
    session_key_b64: str | None = None


@dataclass(slots=True)
class AuthenticationSession:
    session_id: str
    device_id: str
    model_id: str
    challenge_id: str
    challenge_vector: list[int]
    server_nonce: str
    created_at: int
    expires_at: int
    response_bit_length: int
    ecc_repetition: int = 1
    state: str = "issued"
    failure_reason: str | None = None
    session_key_b64: str | None = None
    used_device_nonces: set[str] = field(default_factory=set)

    def is_expired(self, now: int | None = None) -> bool:
        reference = int(now if now is not None else time())
        return reference > self.expires_at


@dataclass(slots=True)
class AuthenticationState:
    tracker: NonceTracker = field(default_factory=lambda: NonceTracker(ttl_seconds=300))
    sessions: dict[str, AuthenticationSession] = field(default_factory=dict)


def matrix_catalog_from_metadata(
    matrix_set: list[MatrixMetadata],
    *,
    block_size_bits: int = 8,
) -> MatrixCatalog:
    from encryption.matrix_cipher import MatrixKey
    import hashlib
    import random

    if not matrix_set:
        raise ValueError("matrix_set must not be empty")

    keys: list[MatrixKey] = []
    for idx, metadata in enumerate(matrix_set):
        seed_material = (
            f"{metadata.checksum or 'none'}:{metadata.rows}:{metadata.cols}:{metadata.dtype}:{idx}"
        )
        seed = int(hashlib.sha256(seed_material.encode("utf-8")).hexdigest()[:16], 16)
        rng = random.Random(seed)
        matrix = generate_invertible_binary_matrix(block_size_bits, rng)
        inverse = invert_binary_matrix(matrix)
        matrix_id = metadata.checksum or f"matrix-{idx:03d}"
        keys.append(MatrixKey(matrix_id=matrix_id, matrix=matrix, inverse=inverse))

    return MatrixCatalog(keys)


def build_server_challenge(
    *,
    session_id: str,
    device_id: str,
    model_id: str,
    challenge_id: str,
    challenge_vector: list[int],
    timeout_seconds: int,
    shared_key: bytes,
    response_bit_length: int = 256,
    ecc_repetition: int = 1,
    issued_at: int | None = None,
    server_nonce: str | None = None,
) -> AuthenticationChallenge:
    now = int(issued_at if issued_at is not None else time())
    nonce = server_nonce if server_nonce is not None else generate_nonce()

    payload = {
        "session_id": session_id,
        "device_id": device_id,
        "model_id": model_id,
        "challenge_id": challenge_id,
        "challenge_vector": challenge_vector,
        "server_nonce": nonce,
        "issued_at": now,
        "timeout_seconds": timeout_seconds,
        "response_bit_length": response_bit_length,
        "ecc_repetition": ecc_repetition,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    server_message = build_authenticated_message(encoded, shared_key, nonce=nonce, timestamp=now)

    return AuthenticationChallenge(
        session_id=session_id,
        device_id=device_id,
        model_id=model_id,
        challenge_id=challenge_id,
        challenge_vector=challenge_vector,
        server_nonce=nonce,
        issued_at=now,
        timeout_seconds=timeout_seconds,
        response_bit_length=response_bit_length,
        ecc_repetition=ecc_repetition,
        server_message=server_message,
    )


def verify_server_challenge(
    challenge: AuthenticationChallenge,
    shared_key: bytes,
    *,
    nonce_tracker: NonceTracker,
    now: int | None = None,
) -> bool:
    valid, decoded = verify_authenticated_message(
        challenge.server_message,
        shared_key,
        max_age_seconds=challenge.timeout_seconds,
        nonce_tracker=nonce_tracker,
        now=now,
    )
    if not valid or decoded is None:
        return False

    try:
        parsed = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False

    expected = {
        "session_id": challenge.session_id,
        "device_id": challenge.device_id,
        "model_id": challenge.model_id,
        "challenge_id": challenge.challenge_id,
        "challenge_vector": challenge.challenge_vector,
        "server_nonce": challenge.server_nonce,
        "issued_at": challenge.issued_at,
        "timeout_seconds": challenge.timeout_seconds,
        "response_bit_length": challenge.response_bit_length,
        "ecc_repetition": challenge.ecc_repetition,
    }
    return parsed == expected


def build_device_reply(
    *,
    challenge: AuthenticationChallenge,
    device_id: str,
    response_bits: str,
    shared_key: bytes,
    matrix_set: list[MatrixMetadata],
    timestamp: int | None = None,
    device_nonce: str | None = None,
) -> AuthenticationReply:
    cipher = MatrixCipher(matrix_catalog_from_metadata(matrix_set), block_size_bits=8)

    response_bytes = bits_to_bytes(response_bits)
    if challenge.ecc_repetition > 1:
        response_bytes = bits_to_bytes(repetition_encode(response_bits, challenge.ecc_repetition))
    encrypted = cipher.encrypt(response_bytes, selector=challenge.server_nonce.encode("utf-8"))

    used_timestamp = int(timestamp if timestamp is not None else time())
    used_device_nonce = device_nonce if device_nonce is not None else generate_nonce()
    encoded_payload = {
        "session_id": challenge.session_id,
        "device_id": device_id,
        "server_nonce": challenge.server_nonce,
        "device_nonce": used_device_nonce,
        "matrix_id": encrypted.matrix_id,
        "padding_bits": encrypted.padding_bits,
        "encrypted_response_b64": base64.b64encode(encrypted.ciphertext).decode("ascii"),
    }

    encoded_bytes = json.dumps(encoded_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    device_message = build_authenticated_message(
        encoded_bytes,
        shared_key,
        nonce=used_device_nonce,
        timestamp=used_timestamp,
    )

    return AuthenticationReply(
        session_id=challenge.session_id,
        device_id=device_id,
        server_nonce=challenge.server_nonce,
        device_nonce=used_device_nonce,
        matrix_id=encrypted.matrix_id,
        padding_bits=encrypted.padding_bits,
        encrypted_response_b64=encoded_payload["encrypted_response_b64"],
        device_message=device_message,
    )


def decode_reply_response_bits(
    reply: AuthenticationReply,
    *,
    matrix_set: list[MatrixMetadata],
    expected_bit_length: int,
    ecc_repetition: int = 1,
) -> str:
    cipher = MatrixCipher(matrix_catalog_from_metadata(matrix_set), block_size_bits=8)
    encrypted = EncryptedPayload(
        matrix_id=reply.matrix_id,
        block_size_bits=8,
        padding_bits=reply.padding_bits,
        ciphertext=base64.b64decode(reply.encrypted_response_b64.encode("ascii")),
    )
    response_bytes = cipher.decrypt(encrypted)
    raw_bits = bytes_to_bits(response_bytes)
    if ecc_repetition > 1:
        decoded = repetition_decode(raw_bits, ecc_repetition)
        return decoded[:expected_bit_length]
    return bytes_to_bits(response_bytes, expected_bit_length)


def verify_device_reply_message(
    reply: AuthenticationReply,
    shared_key: bytes,
    *,
    timeout_seconds: int,
    nonce_tracker: NonceTracker,
    now: int | None = None,
) -> bool:
    valid, decoded = verify_authenticated_message(
        reply.device_message,
        shared_key,
        max_age_seconds=timeout_seconds,
        nonce_tracker=nonce_tracker,
        now=now,
    )
    if not valid or decoded is None:
        return False

    try:
        parsed = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False

    expected = {
        "session_id": reply.session_id,
        "device_id": reply.device_id,
        "server_nonce": reply.server_nonce,
        "device_nonce": reply.device_nonce,
        "matrix_id": reply.matrix_id,
        "padding_bits": reply.padding_bits,
        "encrypted_response_b64": reply.encrypted_response_b64,
    }
    return parsed == expected


def bits_to_bytes(bits: str) -> bytes:
    if any(char not in {"0", "1"} for char in bits):
        raise ValueError("bits must contain only 0 and 1 characters")
    if len(bits) % 8 != 0:
        raise ValueError("bit-string length must be divisible by 8")

    out = bytearray()
    for idx in range(0, len(bits), 8):
        out.append(int(bits[idx : idx + 8], 2))
    return bytes(out)


def bytes_to_bits(data: bytes, expected_length: int | None = None) -> str:
    bits = "".join(f"{byte:08b}" for byte in data)
    if expected_length is None:
        return bits
    if expected_length < 0:
        raise ValueError("expected_length must be >= 0")
    if expected_length > len(bits):
        raise ValueError("expected_length exceeds decoded bit-string length")
    return bits[:expected_length]


def derive_authentication_session_key(
    response_bits: str,
    *,
    session_id: str,
    server_nonce: str,
    device_nonce: str,
) -> bytes:
    if not response_bits:
        raise ValueError("response_bits must not be empty")
    if any(char not in {"0", "1"} for char in response_bits):
        raise ValueError("response_bits must contain only 0 and 1")
    return derive_session_key(
        response_bits.encode("utf-8"),
        session_id.encode("utf-8"),
        server_nonce.encode("utf-8"),
        device_nonce.encode("utf-8"),
    )
