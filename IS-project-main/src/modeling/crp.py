from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Sequence

from puf.interface import PUFSimulator


@dataclass(slots=True)
class CRPDataset:
    challenges: list[list[int]]
    responses: list[int]

    def __post_init__(self) -> None:
        if len(self.challenges) != len(self.responses):
            raise ValueError("challenges and responses must have equal length")
        if self.challenges and any(len(c) != len(self.challenges[0]) for c in self.challenges):
            raise ValueError("all challenges must have the same width")

    @property
    def size(self) -> int:
        return len(self.responses)

    @property
    def challenge_size(self) -> int:
        if not self.challenges:
            return 0
        return len(self.challenges[0])


def generate_random_challenges(
    num_samples: int,
    challenge_size: int,
    *,
    seed: int | None = None,
) -> list[list[int]]:
    if num_samples <= 0:
        raise ValueError("num_samples must be positive")
    if challenge_size <= 0:
        raise ValueError("challenge_size must be positive")

    rng = random.Random(seed)
    return [[rng.randint(0, 1) for _ in range(challenge_size)] for _ in range(num_samples)]


def query_simulator(
    simulator: PUFSimulator,
    challenge: Sequence[int],
    *,
    noisy: bool = False,
    repetitions: int = 1,
) -> int:
    if repetitions <= 0:
        raise ValueError("repetitions must be positive")
    if repetitions == 1:
        return simulator.evaluate(challenge, noisy=noisy)
    if noisy:
        return simulator.evaluate_stable(challenge, repetitions=repetitions)

    values = simulator.evaluate_repeated(challenge, repetitions=repetitions, noisy=False)
    ones = sum(values)
    zeros = len(values) - ones
    return 1 if ones >= zeros else 0


def collect_crps(
    simulator: PUFSimulator,
    *,
    num_samples: int,
    seed: int | None = None,
    noisy: bool = False,
    repetitions: int = 1,
) -> CRPDataset:
    challenges = generate_random_challenges(
        num_samples=num_samples,
        challenge_size=simulator.challenge_size,
        seed=seed,
    )
    responses = [
        query_simulator(simulator, challenge, noisy=noisy, repetitions=repetitions)
        for challenge in challenges
    ]
    return CRPDataset(challenges=challenges, responses=responses)
