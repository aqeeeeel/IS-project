from __future__ import annotations

import random
from abc import ABC, abstractmethod
from typing import Sequence


class BasePUFSimulator(ABC):
    def __init__(
        self,
        challenge_size: int,
        *,
        noise_probability: float = 0.0,
        stability: float = 1.0,
        seed: int | None = None,
    ) -> None:
        if challenge_size <= 0:
            raise ValueError("challenge_size must be positive")
        if not 0.0 <= noise_probability <= 1.0:
            raise ValueError("noise_probability must be between 0 and 1")
        if not 0.0 <= stability <= 1.0:
            raise ValueError("stability must be between 0 and 1")

        self.challenge_size = challenge_size
        self.noise_probability = noise_probability
        self.stability = stability
        self._rng = random.Random(seed)

    @abstractmethod
    def _ideal_response(self, challenge: Sequence[int]) -> int:
        """Compute noiseless response bit."""

    def _validate_challenge(self, challenge: Sequence[int]) -> None:
        if len(challenge) != self.challenge_size:
            raise ValueError(
                f"Challenge length {len(challenge)} does not match expected size {self.challenge_size}"
            )
        if any(bit not in (0, 1) for bit in challenge):
            raise ValueError("Challenge vector must contain only binary values 0/1")

    def _apply_noise(self, bit: int) -> int:
        # Stability models intrinsic reliability while noise_probability captures channel effects.
        flip_probability = min(1.0, max(0.0, (1.0 - self.stability) + self.noise_probability))
        if flip_probability == 0.0:
            return bit
        if self._rng.random() < flip_probability:
            return 1 - bit
        return bit

    def evaluate(self, challenge: Sequence[int], *, noisy: bool = False) -> int:
        self._validate_challenge(challenge)
        result = self._ideal_response(challenge)
        return self._apply_noise(result) if noisy else result

    def evaluate_repeated(
        self,
        challenge: Sequence[int],
        repetitions: int,
        *,
        noisy: bool = True,
    ) -> list[int]:
        if repetitions <= 0:
            raise ValueError("repetitions must be positive")
        return [self.evaluate(challenge, noisy=noisy) for _ in range(repetitions)]

    def evaluate_stable(
        self,
        challenge: Sequence[int],
        repetitions: int = 7,
    ) -> int:
        samples = self.evaluate_repeated(challenge, repetitions=repetitions, noisy=True)
        ones = sum(samples)
        zeros = len(samples) - ones
        return 1 if ones >= zeros else 0

    @staticmethod
    def hamming_distance(left: Sequence[int] | str, right: Sequence[int] | str) -> int:
        if len(left) != len(right):
            raise ValueError("Hamming distance requires equal-length inputs")
        return sum(1 for l_bit, r_bit in zip(left, right) if l_bit != r_bit)

    @staticmethod
    def hamming_ratio(left: Sequence[int] | str, right: Sequence[int] | str) -> float:
        if len(left) == 0:
            raise ValueError("Hamming ratio requires non-empty inputs")
        distance = BasePUFSimulator.hamming_distance(left, right)
        return distance / float(len(left))
