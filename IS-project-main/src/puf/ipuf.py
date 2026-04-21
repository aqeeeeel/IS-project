from __future__ import annotations

from typing import Sequence

from .arbiter import ArbiterPUFSimulator
from .simulator_base import BasePUFSimulator


class InterposePUFSimulator(BasePUFSimulator):
    """Interpose PUF (iPUF) simulator using two cascaded Arbiter PUFs."""

    def __init__(
        self,
        challenge_size: int,
        *,
        interpose_index: int | None = None,
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
        if challenge_size < 2:
            raise ValueError("iPUF requires challenge_size >= 2")

        self.interpose_index = interpose_index if interpose_index is not None else challenge_size // 2
        if not 0 <= self.interpose_index <= challenge_size:
            raise ValueError("interpose_index must be in [0, challenge_size]")

        base_seed = seed if seed is not None else 0
        self._upper = ArbiterPUFSimulator(challenge_size=challenge_size, seed=base_seed + 11)
        self._lower = ArbiterPUFSimulator(challenge_size=challenge_size + 1, seed=base_seed + 29)

    def _ideal_response(self, challenge: Sequence[int]) -> int:
        upper_bit = self._upper.evaluate(challenge, noisy=False)
        lower_challenge = (
            list(challenge[: self.interpose_index])
            + [upper_bit]
            + list(challenge[self.interpose_index :])
        )
        return self._lower.evaluate(lower_challenge, noisy=False)
