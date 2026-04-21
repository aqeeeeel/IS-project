from __future__ import annotations

import pickle
from typing import Any

from puf.interface import PUFSimulator

from .parameter_encoder import EncodedParameterPacket, evaluate_consistent_response


def bits_to_bytes(bits: str) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("bit-stream length must be divisible by 8")
    if any(char not in {"0", "1"} for char in bits):
        raise ValueError("bits must contain only 0 and 1")

    out = bytearray()
    for idx in range(0, len(bits), 8):
        out.append(int(bits[idx : idx + 8], 2))
    return bytes(out)


def deserialize_parameters(payload: bytes) -> Any:
    return pickle.loads(payload)


def decode_parameters_from_challenges(
    packet: EncodedParameterPacket,
    *,
    simulator: PUFSimulator,
    noisy: bool = True,
    stability_attempts: int = 3,
) -> Any:
    if simulator.challenge_size != packet.challenge_size:
        raise ValueError("Simulator challenge size does not match encoded packet")
    if stability_attempts <= 0:
        raise ValueError("stability_attempts must be positive")

    recovered_bits: list[str] = []
    for challenge in packet.challenges:
        accepted: int | None = None
        for _ in range(stability_attempts):
            accepted = evaluate_consistent_response(
                simulator,
                challenge,
                repetitions=packet.stability_repetitions,
                noisy=noisy,
            )
            if accepted is not None:
                break

        if accepted is None:
            raise RuntimeError("Failed stability check while decoding parameter challenge")
        recovered_bits.append(str(accepted))

    bit_stream = "".join(recovered_bits)
    if len(bit_stream) != packet.bit_length:
        raise RuntimeError("Recovered bit-stream length mismatch")

    payload = bits_to_bytes(bit_stream)
    return deserialize_parameters(payload)
