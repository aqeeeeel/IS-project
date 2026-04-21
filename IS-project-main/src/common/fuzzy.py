from __future__ import annotations

from dataclasses import dataclass


def _validate_bits(bits: str) -> None:
    if any(char not in {"0", "1"} for char in bits):
        raise ValueError("bit-string must contain only 0 and 1")


def repetition_encode(bits: str, repetition: int) -> str:
    _validate_bits(bits)
    if repetition <= 0:
        raise ValueError("repetition must be positive")
    return "".join(bit * repetition for bit in bits)


def repetition_decode(encoded_bits: str, repetition: int) -> str:
    _validate_bits(encoded_bits)
    if repetition <= 0:
        raise ValueError("repetition must be positive")
    if len(encoded_bits) % repetition != 0:
        raise ValueError("encoded_bits length must be divisible by repetition")

    output: list[str] = []
    for idx in range(0, len(encoded_bits), repetition):
        chunk = encoded_bits[idx : idx + repetition]
        ones = chunk.count("1")
        zeros = len(chunk) - ones
        output.append("1" if ones >= zeros else "0")
    return "".join(output)


@dataclass(frozen=True, slots=True)
class FuzzyHelper:
    reference_bits: str
    max_hamming_distance: int


@dataclass(frozen=True, slots=True)
class NoisyRecoveryProfile:
    helper: FuzzyHelper | None = None
    ecc_repetition: int = 1


def hamming_distance(left: str, right: str) -> int:
    if len(left) != len(right):
        raise ValueError("equal lengths required")
    _validate_bits(left)
    _validate_bits(right)
    return sum(1 for l_bit, r_bit in zip(left, right) if l_bit != r_bit)


def fuzzy_enroll(reference_bits: str, *, max_hamming_distance: int) -> FuzzyHelper:
    _validate_bits(reference_bits)
    if max_hamming_distance < 0:
        raise ValueError("max_hamming_distance must be >= 0")
    return FuzzyHelper(reference_bits=reference_bits, max_hamming_distance=max_hamming_distance)


def fuzzy_recover(noisy_bits: str, helper: FuzzyHelper) -> str | None:
    _validate_bits(noisy_bits)
    if len(noisy_bits) != len(helper.reference_bits):
        return None
    distance = hamming_distance(noisy_bits, helper.reference_bits)
    if distance > helper.max_hamming_distance:
        return None
    return helper.reference_bits


def build_recovery_profile(
    reference_bits: str,
    *,
    max_hamming_distance: int = 0,
    ecc_repetition: int = 1,
) -> NoisyRecoveryProfile:
    _validate_bits(reference_bits)
    if max_hamming_distance < 0:
        raise ValueError("max_hamming_distance must be >= 0")
    if ecc_repetition <= 0:
        raise ValueError("ecc_repetition must be positive")

    helper = None
    if max_hamming_distance > 0:
        helper = fuzzy_enroll(reference_bits, max_hamming_distance=max_hamming_distance)
    return NoisyRecoveryProfile(helper=helper, ecc_repetition=ecc_repetition)


def recover_noisy_bits(noisy_bits: str, profile: NoisyRecoveryProfile) -> str | None:
    _validate_bits(noisy_bits)

    recovered_bits = noisy_bits
    if profile.ecc_repetition > 1:
        try:
            recovered_bits = repetition_decode(noisy_bits, profile.ecc_repetition)
        except ValueError:
            return None

    if profile.helper is None:
        return recovered_bits
    return fuzzy_recover(recovered_bits, profile.helper)
