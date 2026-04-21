from __future__ import annotations

from typing import Sequence

from .arbiter import ArbiterPUFSimulator
from .simulator_base import BasePUFSimulator


class XORArbiterPUFSimulator(BasePUFSimulator):
    """XOR-APUF built from multiple Arbiter PUF instances."""

    def __init__(
        self,
        challenge_size: int,
        *,
        num_xors: int = 4,
        noise_probability: float = 0.0,
        stability: float = 1.0,
        seed: int | None = None,
    ) -> None:
        if num_xors <= 0:
            raise ValueError("num_xors must be positive")

        super().__init__(
            challenge_size=challenge_size,
            noise_probability=noise_probability,
            stability=stability,
            seed=seed,
        )
        base_seed = seed if seed is not None else 0
        self._components = [
            ArbiterPUFSimulator(
                challenge_size=challenge_size,
                noise_probability=0.0,
                stability=1.0,
                seed=base_seed + idx + 1,
            )
            for idx in range(num_xors)
        ]

    def _ideal_response(self, challenge: Sequence[int]) -> int:
        xor_bit = 0
        for component in self._components:
            xor_bit ^= component.evaluate(challenge, noisy=False)
        return xor_bit
