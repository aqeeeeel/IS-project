from __future__ import annotations

from common.crypto_utils import aesgcm_decrypt_optional, aesgcm_encrypt_optional

from .matrix_cipher import EncryptedPayload, MatrixCatalog, MatrixCipher


_DEFAULT_CATALOG = MatrixCatalog.generate(count=8, block_size_bits=8, seed=2026)
_DEFAULT_CIPHER = MatrixCipher(_DEFAULT_CATALOG, block_size_bits=8)

def _selector(secret: bytes) -> bytes:
    if not secret:
        raise ValueError("Secret key material must not be empty")
    return secret


def encrypt_bytes(data: bytes, secret: bytes) -> bytes:
    encrypted = _DEFAULT_CIPHER.encrypt(data, selector=_selector(secret))
    header = f"{encrypted.matrix_id}:{encrypted.padding_bits}:".encode("ascii")
    return header + encrypted.ciphertext


def decrypt_bytes(ciphertext: bytes, secret: bytes) -> bytes:
    try:
        matrix_id_raw, padding_raw, body = ciphertext.split(b":", 2)
    except ValueError as exc:
        raise ValueError("Ciphertext header format is invalid") from exc

    expected_key = _DEFAULT_CATALOG.select(selector=_selector(secret))
    matrix_id = matrix_id_raw.decode("ascii")
    if matrix_id != expected_key.matrix_id:
        raise ValueError("Ciphertext matrix selector does not match provided secret")

    padding_bits = int(padding_raw.decode("ascii"))
    encrypted_payload = EncryptedPayload(
        matrix_id=matrix_id,
        block_size_bits=8,
        padding_bits=padding_bits,
        ciphertext=body,
    )
    return _DEFAULT_CIPHER.decrypt(encrypted_payload)


def hybrid_encrypt_payload(payload: bytes, session_key: bytes, *, aad: bytes | None = None) -> dict[str, str]:
    return aesgcm_encrypt_optional(payload, session_key, aad=aad)


def hybrid_decrypt_payload(payload: dict[str, str], session_key: bytes) -> bytes:
    return aesgcm_decrypt_optional(payload, session_key)
