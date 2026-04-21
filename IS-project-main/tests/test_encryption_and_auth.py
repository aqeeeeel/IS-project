from __future__ import annotations

from common.crypto_utils import NonceTracker, build_authenticated_message, generate_nonce, verify_authenticated_message
from encryption.matrix_cipher import MatrixCatalog, MatrixCipher, invert_binary_matrix


def test_matrix_encryption_decryption_round_trip() -> None:
    catalog = MatrixCatalog.generate(count=5, block_size_bits=8, seed=77)
    cipher = MatrixCipher(catalog, block_size_bits=8)

    payload = b"PUF matrix encryption payload \x00\x01\x7f"
    encrypted = cipher.encrypt(payload, selector=b"device-1|session-xyz")
    decrypted = cipher.decrypt(encrypted)

    assert decrypted == payload


def test_generated_catalog_matrices_are_invertible() -> None:
    catalog = MatrixCatalog.generate(count=4, block_size_bits=8, seed=11)
    for matrix_id in catalog.ids():
        entry = catalog.get(matrix_id)
        recalculated_inverse = invert_binary_matrix(entry.matrix)
        assert recalculated_inverse == entry.inverse


def test_authenticated_message_integrity() -> None:
    key = b"integrity-secret"
    message = build_authenticated_message(b"secure payload", key, nonce="nonce-1", timestamp=1_700_000_000)

    ok, payload = verify_authenticated_message(message, key, max_age_seconds=600, now=1_700_000_100)
    assert ok
    assert payload == b"secure payload"

    tampered = dict(message)
    tampered["payload_b64"] = "QUJD"
    ok_tampered, payload_tampered = verify_authenticated_message(
        tampered,
        key,
        max_age_seconds=600,
        now=1_700_000_100,
    )
    assert not ok_tampered
    assert payload_tampered is None


def test_nonce_freshness_and_replay_protection() -> None:
    generated = {generate_nonce() for _ in range(32)}
    assert len(generated) == 32

    key = b"nonce-secret"
    tracker = NonceTracker(ttl_seconds=60)
    message = build_authenticated_message(b"once", key, nonce="replay-me", timestamp=2_000)

    first_ok, _ = verify_authenticated_message(
        message,
        key,
        max_age_seconds=60,
        nonce_tracker=tracker,
        now=2_010,
    )
    second_ok, _ = verify_authenticated_message(
        message,
        key,
        max_age_seconds=60,
        nonce_tracker=tracker,
        now=2_011,
    )

    assert first_ok
    assert not second_ok
