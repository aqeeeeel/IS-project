from __future__ import annotations

import pickle
import random
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterator

from puf.interface import PUFSimulator


class ChallengeSelectionStrategy(str, Enum):
    ENUMERATION = "enumeration"
    TRAVERSAL = "traversal"


@dataclass(frozen=True, slots=True)
class EncodedParameterPacket:
    challenge_size: int
    bit_length: int
    strategy: ChallengeSelectionStrategy
    stability_repetitions: int
    challenges: list[list[int]]


def serialize_parameters(parameters: Any) -> bytes:
    """Prototype serializer for exact round-trip parameter recovery."""
    return pickle.dumps(parameters, protocol=4)


def bytes_to_bits(payload: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in payload)


def _int_to_challenge(value: int, challenge_size: int) -> list[int]:
    mask = (1 << challenge_size) - 1
    value &= mask
    return [
        (value >> shift) & 1
        for shift in range(challenge_size - 1, -1, -1)
    ]


def _enumeration_generator(challenge_size: int) -> Iterator[list[int]]:
    value = 0
    while True:
        yield _int_to_challenge(value, challenge_size)
        value += 1


def _traversal_generator(challenge_size: int, *, seed: int | None = None) -> Iterator[list[int]]:
    rng = random.Random(seed)
    current = [rng.randint(0, 1) for _ in range(challenge_size)]
    while True:
        yield list(current)
        flips = rng.randint(1, max(1, challenge_size // 4))
        for _ in range(flips):
            index = rng.randrange(challenge_size)
            current[index] = 1 - current[index]


def _challenge_stream(
    challenge_size: int,
    strategy: ChallengeSelectionStrategy,
    *,
    seed: int | None = None,
) -> Iterator[list[int]]:
    if strategy == ChallengeSelectionStrategy.ENUMERATION:
        return _enumeration_generator(challenge_size)
    if strategy == ChallengeSelectionStrategy.TRAVERSAL:
        return _traversal_generator(challenge_size, seed=seed)
    raise ValueError(f"Unsupported challenge selection strategy '{strategy}'")


def evaluate_consistent_response(
    simulator: PUFSimulator,
    challenge: list[int],
    *,
    repetitions: int,
    noisy: bool,
) -> int | None:
    samples = simulator.evaluate_repeated(challenge, repetitions=repetitions, noisy=noisy)
    return samples[0] if len(set(samples)) == 1 else None


def encode_parameters_to_challenges(
    parameters: Any,
    *,
    simulator: PUFSimulator,
    strategy: ChallengeSelectionStrategy = ChallengeSelectionStrategy.ENUMERATION,
    stability_repetitions: int = 5,
    noisy: bool = True,
    selection_seed: int | None = None,
    max_attempts_per_bit: int = 20_000,
) -> EncodedParameterPacket:
    if stability_repetitions <= 0:
        raise ValueError("stability_repetitions must be positive")
    if max_attempts_per_bit <= 0:
        raise ValueError("max_attempts_per_bit must be positive")

    payload = serialize_parameters(parameters)
    bits = bytes_to_bits(payload)
    stream = _challenge_stream(
        simulator.challenge_size,
        strategy,
        seed=selection_seed,
    )

    selected: list[list[int]] = []
    for bit_char in bits:
        target = int(bit_char)
        matched = False

        for _ in range(max_attempts_per_bit):
            challenge = next(stream)
            consistent = evaluate_consistent_response(
                simulator,
                challenge,
                repetitions=stability_repetitions,
                noisy=noisy,
            )
            if consistent is None:
                continue
            if consistent == target:
                selected.append(challenge)
                matched = True
                break

        if not matched:
            raise RuntimeError("Unable to find a stable challenge that matches parameter bit")

    return EncodedParameterPacket(
        challenge_size=simulator.challenge_size,
        bit_length=len(bits),
        strategy=strategy,
        stability_repetitions=stability_repetitions,
        challenges=selected,
    )
