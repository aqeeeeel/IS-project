from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .arbiter import ArbiterPUFSimulator
from .interface import PUFSimulator
from .ipuf import InterposePUFSimulator
from .xor_apuf import XORArbiterPUFSimulator


class PUFBackend(str, Enum):
    ARBITER = "arbiter"
    XOR_APUF = "xor_apuf"
    IPUF = "ipuf"
    FPGA = "fpga"


@dataclass(slots=True)
class PUFBuildOptions:
    challenge_size: int
    noise_probability: float = 0.0
    stability: float = 1.0
    seed: int | None = None
    xor_count: int = 4
    interpose_index: int | None = None


def create_puf_simulator(backend: PUFBackend, options: PUFBuildOptions) -> PUFSimulator:
    if backend == PUFBackend.ARBITER:
        return ArbiterPUFSimulator(
            challenge_size=options.challenge_size,
            noise_probability=options.noise_probability,
            stability=options.stability,
            seed=options.seed,
        )
    if backend == PUFBackend.XOR_APUF:
        return XORArbiterPUFSimulator(
            challenge_size=options.challenge_size,
            num_xors=options.xor_count,
            noise_probability=options.noise_probability,
            stability=options.stability,
            seed=options.seed,
        )
    if backend == PUFBackend.IPUF:
        return InterposePUFSimulator(
            challenge_size=options.challenge_size,
            interpose_index=options.interpose_index,
            noise_probability=options.noise_probability,
            stability=options.stability,
            seed=options.seed,
        )

    raise NotImplementedError(
        "FPGA backend is not wired yet. Implement a class with the PUFSimulator interface and return it here."
    )
