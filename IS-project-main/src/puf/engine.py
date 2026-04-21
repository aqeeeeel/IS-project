from __future__ import annotations

import secrets
from typing import Sequence

from common.types import Challenge, Response

from .arbiter import ArbiterPUFSimulator
from .factory import PUFBackend, PUFBuildOptions, create_puf_simulator
from .interface import PUFSimulator
from .simulator_base import BasePUFSimulator


class PUFEngine:
    """Facade around the simulator interface used by server/device flows."""

    def __init__(
        self,
        model_id: str,
        challenge_bits: int = 256,
        *,
        backend: PUFBackend = PUFBackend.ARBITER,
    ) -> None:
        self.model_id = model_id
        self.challenge_bits = challenge_bits
        self.backend = backend

    def generate_challenge(self, challenge_id: str, device_id: str) -> Challenge:
        vector = [secrets.randbits(1) for _ in range(self.challenge_bits)]
        return Challenge(
            challenge_id=challenge_id,
            device_id=device_id,
            model_id=self.model_id,
            vector=vector,
        )

    def _seed_from_identity(self, identity_seed: str) -> int:
        return sum((idx + 1) * ord(ch) for idx, ch in enumerate(identity_seed))

    def _build_simulator(self, identity_seed: str) -> PUFSimulator:
        options = PUFBuildOptions(
            challenge_size=self.challenge_bits,
            seed=self._seed_from_identity(identity_seed),
            noise_probability=0.0,
            stability=1.0,
        )
        return create_puf_simulator(self.backend, options)

    def _challenge_variant(self, challenge_vector: Sequence[int], round_index: int) -> list[int]:
        # Expand one challenge into a reproducible sequence to derive a response bitstring.
        if not challenge_vector:
            raise ValueError("challenge_vector must not be empty")

        width = len(challenge_vector)
        rotation = round_index % width
        rotated = list(challenge_vector[rotation:]) + list(challenge_vector[:rotation])
        if ((round_index // width) % 2) == 1:
            return [1 - bit for bit in rotated]
        return rotated

    def derive_response_bits(self, challenge: Challenge, identity_seed: str) -> str:
        simulator = self._build_simulator(identity_seed)
        response_bits = [
            str(simulator.evaluate(self._challenge_variant(challenge.vector, idx), noisy=False))
            for idx in range(256)
        ]
        return "".join(response_bits)

    def compare_responses(self, expected_bits: str, actual_bits: str) -> float:
        return BasePUFSimulator.hamming_ratio(expected_bits, actual_bits)

    def verify_response(
        self,
        challenge: Challenge,
        response: Response,
        identity_seed: str,
        tolerance: float = 0.98,
    ) -> bool:
        expected = self.derive_response_bits(challenge, identity_seed)
        actual = response.response_bits
        if len(expected) != len(actual):
            return False

        distance_ratio = self.compare_responses(expected, actual)
        score = 1.0 - distance_ratio
        return score >= tolerance
