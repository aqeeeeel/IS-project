from __future__ import annotations

import random
from typing import Sequence

from .simulator_base import BasePUFSimulator


class ArbiterPUFSimulator(BasePUFSimulator):
    """Additive-delay Arbiter PUF simulator."""

    def __init__(
        self,
        challenge_size: int,
        *,
        noise_probability: float = 0.0,
        stability: float = 1.0,
        seed: int | None = None,
    ) -> None:
        super().__init__(
            challenge_size=challenge_size,
            noise_probability=noise_probability,
            stability=stability,
            seed=seed,
        )
        weight_rng = random.Random(seed)
        self._weights = [weight_rng.uniform(-1.0, 1.0) for _ in range(challenge_size + 1)]

    def _transform(self, challenge: Sequence[int]) -> list[int]:
        phi: list[int] = []
        product = 1
        for bit in reversed(challenge):
            product *= 1 if bit == 1 else -1
            phi.append(product)
        phi.reverse()
        phi.append(1)
        return phi

    def _ideal_response(self, challenge: Sequence[int]) -> int:
        phi = self._transform(challenge)
        score = sum(weight * value for weight, value in zip(self._weights, phi))
        return 1 if score >= 0.0 else 0
