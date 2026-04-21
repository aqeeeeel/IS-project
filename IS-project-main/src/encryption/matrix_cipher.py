from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import Sequence


def _identity(size: int) -> list[list[int]]:
    return [[1 if row == col else 0 for col in range(size)] for row in range(size)]


def _copy_matrix(matrix: Sequence[Sequence[int]]) -> list[list[int]]:
    return [list(row) for row in matrix]


def _matrix_vector_mul_mod2(matrix: Sequence[Sequence[int]], vector: Sequence[int]) -> list[int]:
    out: list[int] = []
    for row in matrix:
        bit = 0
        for left, right in zip(row, vector):
            bit ^= (left & right)
        out.append(bit)
    return out


def invert_binary_matrix(matrix: Sequence[Sequence[int]]) -> list[list[int]]:
    size = len(matrix)
    if size == 0 or any(len(row) != size for row in matrix):
        raise ValueError("Matrix must be non-empty and square")

    working = _copy_matrix(matrix)
    inverse = _identity(size)

    for col in range(size):
        pivot = None
        for row in range(col, size):
            if working[row][col] == 1:
                pivot = row
                break
        if pivot is None:
            raise ValueError("Matrix is not invertible over GF(2)")

        if pivot != col:
            working[col], working[pivot] = working[pivot], working[col]
            inverse[col], inverse[pivot] = inverse[pivot], inverse[col]

        for row in range(size):
            if row == col:
                continue
            if working[row][col] == 1:
                for idx in range(size):
                    working[row][idx] ^= working[col][idx]
                    inverse[row][idx] ^= inverse[col][idx]

    return inverse


def generate_invertible_binary_matrix(size: int, rng: random.Random) -> list[list[int]]:
    if size <= 0:
        raise ValueError("size must be positive")

    for _ in range(1024):
        candidate = [[rng.randint(0, 1) for _ in range(size)] for _ in range(size)]
        try:
            invert_binary_matrix(candidate)
            return candidate
        except ValueError:
            continue

    raise RuntimeError("Unable to generate invertible matrix")


def reshape_bytes_to_blocks(payload: bytes, block_size_bits: int) -> tuple[list[list[int]], int]:
    if block_size_bits <= 0:
        raise ValueError("block_size_bits must be positive")

    bits: list[int] = []
    for byte in payload:
        bits.extend([(byte >> shift) & 1 for shift in range(7, -1, -1)])

    padding_bits = (block_size_bits - (len(bits) % block_size_bits)) % block_size_bits
    bits.extend([0] * padding_bits)

    blocks = [
        bits[idx : idx + block_size_bits]
        for idx in range(0, len(bits), block_size_bits)
    ]
    return blocks, padding_bits


def reshape_blocks_to_bytes(blocks: Sequence[Sequence[int]], padding_bits: int) -> bytes:
    if padding_bits < 0:
        raise ValueError("padding_bits must be >= 0")

    bits = [bit for block in blocks for bit in block]
    if padding_bits > len(bits):
        raise ValueError("padding_bits exceeds total bit count")
    if padding_bits:
        bits = bits[:-padding_bits]

    if len(bits) % 8 != 0:
        raise ValueError("Bitstream length must be divisible by 8")

    output = bytearray()
    for idx in range(0, len(bits), 8):
        value = 0
        for bit in bits[idx : idx + 8]:
            value = (value << 1) | bit
        output.append(value)
    return bytes(output)


@dataclass(frozen=True, slots=True)
class MatrixKey:
    matrix_id: str
    matrix: list[list[int]]
    inverse: list[list[int]]


@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    matrix_id: str
    block_size_bits: int
    padding_bits: int
    ciphertext: bytes


class MatrixCatalog:
    def __init__(self, keys: list[MatrixKey]) -> None:
        if not keys:
            raise ValueError("keys must not be empty")
        self._keys = {item.matrix_id: item for item in keys}

    @classmethod
    def generate(
        cls,
        *,
        count: int,
        block_size_bits: int = 8,
        seed: int | None = None,
    ) -> "MatrixCatalog":
        if count <= 0:
            raise ValueError("count must be positive")

        rng = random.Random(seed)
        keys: list[MatrixKey] = []
        for idx in range(count):
            matrix = generate_invertible_binary_matrix(block_size_bits, rng)
            inverse = invert_binary_matrix(matrix)
            keys.append(
                MatrixKey(
                    matrix_id=f"matrix-{idx:03d}",
                    matrix=matrix,
                    inverse=inverse,
                )
            )
        return cls(keys)

    def ids(self) -> list[str]:
        return sorted(self._keys.keys())

    def get(self, matrix_id: str) -> MatrixKey:
        try:
            return self._keys[matrix_id]
        except KeyError as exc:
            raise KeyError(f"Unknown matrix_id '{matrix_id}'") from exc

    def select(self, *, matrix_id: str | None = None, selector: bytes | None = None) -> MatrixKey:
        if matrix_id is not None:
            return self.get(matrix_id)
        if selector is None:
            return self.get(self.ids()[0])

        digest = hashlib.sha256(selector).digest()
        index = int.from_bytes(digest[:4], "big") % len(self._keys)
        return self.get(self.ids()[index])


class MatrixCipher:
    def __init__(self, catalog: MatrixCatalog, *, block_size_bits: int = 8) -> None:
        self.catalog = catalog
        self.block_size_bits = block_size_bits

    def encrypt(
        self,
        payload: bytes,
        *,
        matrix_id: str | None = None,
        selector: bytes | None = None,
    ) -> EncryptedPayload:
        key = self.catalog.select(matrix_id=matrix_id, selector=selector)
        blocks, padding_bits = reshape_bytes_to_blocks(payload, self.block_size_bits)
        encrypted_blocks = [_matrix_vector_mul_mod2(key.matrix, block) for block in blocks]
        ciphertext = reshape_blocks_to_bytes(encrypted_blocks, 0)
        return EncryptedPayload(
            matrix_id=key.matrix_id,
            block_size_bits=self.block_size_bits,
            padding_bits=padding_bits,
            ciphertext=ciphertext,
        )

    def decrypt(self, encrypted: EncryptedPayload) -> bytes:
        if encrypted.block_size_bits != self.block_size_bits:
            raise ValueError("Encrypted payload block size does not match cipher block size")

        key = self.catalog.get(encrypted.matrix_id)
        blocks, _ = reshape_bytes_to_blocks(encrypted.ciphertext, self.block_size_bits)
        plain_blocks = [_matrix_vector_mul_mod2(key.inverse, block) for block in blocks]
        return reshape_blocks_to_bytes(plain_blocks, encrypted.padding_bits)
