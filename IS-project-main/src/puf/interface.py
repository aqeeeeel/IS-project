from __future__ import annotations

from typing import Protocol, Sequence


class PUFSimulator(Protocol):
    """Common simulator contract that can be replaced by a hardware driver later."""

    challenge_size: int

    def evaluate(self, challenge: Sequence[int], *, noisy: bool = False) -> int:
        """Return a single binary response bit for a challenge vector."""

    def evaluate_repeated(
        self,
        challenge: Sequence[int],
        repetitions: int,
        *,
        noisy: bool = True,
    ) -> list[int]:
        """Return repeated binary responses under optional noise."""

    def evaluate_stable(
        self,
        challenge: Sequence[int],
        repetitions: int = 7,
    ) -> int:
        """Return majority-voted response from repeated noisy evaluations."""

    @staticmethod
    def hamming_distance(left: Sequence[int] | str, right: Sequence[int] | str) -> int:
        """Return Hamming distance for two equal-length bit sequences."""

    @staticmethod
    def hamming_ratio(left: Sequence[int] | str, right: Sequence[int] | str) -> float:
        """Return normalized Hamming distance in [0, 1]."""
