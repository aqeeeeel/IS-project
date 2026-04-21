"""Encryption adapters for model payload protection."""

from .crypto import decrypt_bytes, encrypt_bytes, hybrid_decrypt_payload, hybrid_encrypt_payload
from .matrix_cipher import (
	EncryptedPayload,
	MatrixCatalog,
	MatrixCipher,
	MatrixKey,
	generate_invertible_binary_matrix,
	invert_binary_matrix,
	reshape_blocks_to_bytes,
	reshape_bytes_to_blocks,
)

__all__ = [
	"EncryptedPayload",
	"MatrixCatalog",
	"MatrixCipher",
	"MatrixKey",
	"decrypt_bytes",
	"encrypt_bytes",
	"hybrid_decrypt_payload",
	"hybrid_encrypt_payload",
	"generate_invertible_binary_matrix",
	"invert_binary_matrix",
	"reshape_blocks_to_bytes",
	"reshape_bytes_to_blocks",
]
